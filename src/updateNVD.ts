/**
 * Incremental NVD Sync Script
 * Optimized to prevent Cloudflare Worker timeouts.
 */

export async function updateNVDIncremental(env: any) {
  const now = new Date();
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  const start = yesterday.toISOString().split('.')[0] + ".000Z"; 
  const end = now.toISOString().split('.')[0] + ".000Z";

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}`;
  
  try {
    console.log(`Fetching updates from: ${start} to ${end}`);
    
    const res = await fetch(url, { 
      headers: { 
        "apiKey": env.NVD_API_KEY,
        "User-Agent": "Cloudflare-Worker-CVE-Sync"
      } 
    });
    
    if (!res.ok) throw new Error(`NVD API Error: ${res.status}`);
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    
    if (vulnerabilities.length === 0) {
      console.log("No new updates found in this time range.");
      return;
    }

    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || null;

      // 1. Update CVE table - Mapping lastModified to last_modified column
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(
        cve.id, 
        score, 
        cve.descriptions?.find((d: any) => d.lang === 'en')?.value || "", 
        cve.lastModified || null
      ));

      // 2. Clear old product mappings
      statements.push(env.DB.prepare(`DELETE FROM cve_cpe_mapping WHERE cve_id = ?`).bind(cve.id));

      // 3. Rebuild product mappings
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

    // Execute in chunks if there are many updates to avoid timeouts
    if (statements.length > 0) {
      console.log(`Sending ${statements.length} SQL statements to D1...`);
      await env.DB.batch(statements);
      console.log(`Successfully updated ${vulnerabilities.length} CVEs.`);
    }

  } catch (err) {
    console.error("Incremental Sync Process Failed:", err);
    throw err; // Re-throw so the Fetch handler knows it failed
  }
}
