export async function updateNVDIncremental(env: any) {
  const now = new Date();
  // We look back 25 hours to provide a 1-hour overlap. 
  // This ensures no records are missed due to NIST processing delays.
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  // Format: YYYY-MM-DDTHH:MM:SS (NVD does not want milliseconds or 'Z')
  const start = yesterday.toISOString().split('.')[0]; 
  const end = now.toISOString().split('.')[0];

  // 'includeMatchStringChange=true' is critical: it catches CVEs where 
  // only product names/mappings were modified.
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}&includeMatchStringChange=true`;
  
  try {
    const res = await fetch(url, { headers: { "apiKey": env.NVD_API_KEY } });
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || null;

      // 1. Update/Insert the CVE details
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(cve.id, score, cve.descriptions[0]?.value || "", cve.lastModified));

      // 2. Clear old mappings to prevent stale data
      statements.push(env.DB.prepare(`DELETE FROM cve_cpe_mapping WHERE cve_id = ?`).bind(cve.id));

      // 3. Process new Configurations (CPE Mappings)
      if (cve.configurations) {
        cve.configurations.forEach((config: any) => {
          config.nodes?.forEach((node: any) => {
            node.cpeMatch?.forEach((match: any) => {
              const parts = match.criteria.split(':');
              if (parts.length >= 5) {
                const make = parts[3].toLowerCase();
                const model = parts[4].toLowerCase();
                statements.push(env.DB.prepare(`
                  INSERT INTO cve_cpe_mapping (cve_id, make, model) VALUES (?, ?, ?)
                `).bind(cve.id, make, model));
              }
            });
          });
        });
      }
    }

    if (statements.length > 0) {
      await env.DB.batch(statements); // Atomic transaction
      console.log(`Incremental sync complete: ${vulnerabilities.length} CVEs processed.`);
    }
  } catch (err) {
    console.error("Incremental Sync Failed:", err);
  }
}
