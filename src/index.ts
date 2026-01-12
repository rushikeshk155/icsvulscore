export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // This part lets you force a data download by visiting your-worker.dev/sync
    if (url.pathname === "/sync") {
      await this.scheduled(null, env);
      return new Response("Sync Started! Please check your D1 database in 1 minute.");
    }

    // This part lets you search your data
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
        max_cvss_found: result?.maxScore || "No data yet. Did you run /sync?"
      }), { headers: { "Content-Type": "application/json" } });
    }

    return new Response("NVD ICS Tracker is active. Visit /sync to load data or use ?make=vendor&model=product to search.");
  },

  // This is the engine that talks to NVD
  async scheduled(event, env) {
    const last24h = new Date(Date.now() - 86400000).toISOString();
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=${last24h}`;

    const response = await fetch(nvdUrl, {
      headers: { "apiKey": env.NVD_API_KEY, "User-Agent": "Cloudflare-Worker" }
    });
    const data = await response.json();

    for (const item of data.vulnerabilities) {
      const cve = item.cve;
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 0;

      // Save main CVE
      await env.DB.prepare(`INSERT OR REPLACE INTO cves (cve_id, cvss_score, description) VALUES (?, ?, ?)`)
        .bind(cve.id, score, cve.descriptions[0].value).run();

      // Save Make/Model/Firmware mappings
      if (cve.configurations) {
        for (const config of cve.configurations) {
          for (const node of (config.nodes || [])) {
            for (const match of (node.cpeMatch || [])) {
              const p = match.criteria.split(':');
              if (p.length > 5) {
                await env.DB.prepare(`INSERT INTO cve_cpe_mapping (cve_id, part, make, model, firmware, cpe_full) VALUES (?, ?, ?, ?, ?, ?)`)
                  .bind(cve.id, p[2], p[3], p[4], p[5], match.criteria).run();
              }
            }
          }
        }
      }
    }
  }
};
