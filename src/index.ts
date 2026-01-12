export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Manual Sync Trigger
    if (url.pathname === "/sync") {
      try {
        await this.scheduled(null, env);
        return new Response("Sync completed successfully! Check your D1 database.");
      } catch (err) {
        return new Response("Sync Failed: " + err.message, { status: 500 });
      }
    }

    // Search functionality
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");

    if (make && model) {
      const result = await env.DB.prepare(`
        SELECT MAX(cvss_score) as maxScore 
        FROM cves 
        JOIN cve_cpe_mapping ON cves.cve_id = cve_cpe_mapping.cve_id 
        WHERE make = ? AND model LIKE ?
      `).bind(make.toLowerCase(), `%${model.toLowerCase()}%`).first();

      return new Response(JSON.stringify({
        query: { make, model },
        max_cvss: result?.maxScore || 0
      }), { headers: { "Content-Type": "application/json" } });
    }

    return new Response("Worker is live. Visit /sync to load data.");
  },

  async scheduled(event, env) {
    // 1. Check current progress
    const countResult = await env.DB.prepare("SELECT COUNT(*) as total FROM cves").first();
    const currentRows = countResult.total || 0;

    // 2. Fetch the NEXT 2,000 rows using startIndex
    // NVD allows max 2000 per request. This tells NVD: "Start after the rows I already have"
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex=${currentRows}`;
    
    const response = await fetch(nvdUrl, {
      headers: { 
        "apiKey": env.NVD_API_KEY,
        "User-Agent": "Cloudflare-Worker-ICS-PoC" 
      }
    });

    if (!response.ok) throw new Error("NVD API Error: " + response.status);
    
    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];

    // 3. Save the new batch
    // Using a batch here makes it much faster
    const statements = [];
    
    for (const item of vulnerabilities) {
      const cve = item.cve;
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 0;

      statements.push(
        env.DB.prepare(`INSERT OR REPLACE INTO cves (cve_id, cvss_score, description) VALUES (?, ?, ?)`)
           .bind(cve.id, score, cve.descriptions[0].value)
      );

      if (cve.configurations) {
        for (const config of cve.configurations) {
          for (const node of (config.nodes || [])) {
            for (const match of (node.cpeMatch || [])) {
              const p = match.criteria.split(':');
              if (p.length > 5) {
                statements.push(
                  env.DB.prepare(`INSERT INTO cve_cpe_mapping (cve_id, part, make, model, firmware, cpe_full) VALUES (?, ?, ?, ?, ?, ?)`)
                    .bind(cve.id, p[2], p[3], p[4], p[5], match.criteria)
                );
              }
            }
          }
        }
      }
    }
    
    // Execute all inserts at once
    await env.DB.batch(statements);
    console.log(`Successfully added rows up to index: ${currentRows + vulnerabilities.length}`);
  }
};
