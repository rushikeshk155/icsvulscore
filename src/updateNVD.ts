export async function updateNVDIncremental(env: any) {
  const now = new Date();
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  const start = yesterday.toISOString().split('.')[0]; 
  const end = now.toISOString().split('.')[0];

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

      // 1. Update CVE details + last_modified field
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(cve.id, score, cve.descriptions[0]?.value || "", cve.lastModified));

      // 2. Clear and rebuild mappings
      statements.push(env.DB.prepare(`DELETE FROM cve_cpe_mapping WHERE cve_id = ?`).bind(cve.id));

      if (cve.configurations) {
        cve.configurations.forEach((config: any) => {
          config.nodes?.forEach((node: any) => {
            node.cpeMatch?.forEach((match: any) => {
              const parts = match.criteria.split(':');
              if (parts.length >= 5) {
                statements.push(env.DB.prepare(`
                  INSERT INTO cve_cpe_mapping (cve_id, make, model) VALUES (?, ?, ?)
                `).bind(cve.id, parts[3].toLowerCase(), parts[4].toLowerCase()));
              }
            });
          });
        });
      }
    }

    if (statements.length > 0) await env.DB.batch(statements);
    console.log(`Synced ${vulnerabilities.length} updates.`);
  } catch (err) {
    console.error("Incremental Sync Failed:", err);
  }
}
