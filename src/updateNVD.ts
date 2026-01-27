export async function updateNVDIncremental(env: any) {
  const now = new Date();
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  const start = yesterday.toISOString().split('.')[0]; 
  const end = now.toISOString().split('.')[0];

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}&includeMatchStringChange=true`;
  
  try {
    const res = await fetch(url, { 
      headers: { "apiKey": env.NVD_API_KEY || "" } 
    });
    
    if (!res.ok) throw new Error(`NVD API error: ${res.status}`);
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      
      // 1. Safe CVSS Score extraction (Normalized to null if missing)
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? 
                    cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null;

      // 2. Safe Description extraction
      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? "";

      // 3. Main CVE Upsert (Ensuring no 'undefined' reaches .bind())
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(
        cve.id ?? null, 
        score, 
        desc, 
        cve.lastModified ?? null
      ));

      // 4. Clear existing mappings to maintain atomicity
      statements.push(env.DB.prepare(`DELETE FROM cve_cpe_mapping WHERE cve_id = ?`).bind(cve.id));

      // 5. Build new CPE Mappings
      if (cve.configurations) {
        for (const config of cve.configurations) {
          for (const node of config.nodes || []) {
            for (const match of node.cpeMatch || []) {
              const parts = match.criteria.split(':');
              if (parts.length >= 5) {
                statements.push(env.DB.prepare(`
                  INSERT INTO cve_cpe_mapping (cve_id, make, model) VALUES (?, ?, ?)
                `).bind(
                  cve.id, 
                  parts[3].toLowerCase(), 
                  parts[4].toLowerCase()
                ));
              }
            }
          }
        }
      }
    }

    // 6. Execute as atomic batch
    if (statements.length > 0) {
      await env.DB.batch(statements);
      console.log(`Incremental update successful: ${vulnerabilities.length} CVEs.`);
    }
  } catch (err) {
    console.error("Sync Error:", err);
  }
}
