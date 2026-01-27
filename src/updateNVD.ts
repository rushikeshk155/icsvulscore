/**
 * Incremental NVD Sync Script
 * This function fetches CVEs modified in the last 25 hours.
 * It populates the 'last_modified' column and refreshes 'cve_cpe_mapping'.
 */

export async function updateNVDIncremental(env: any) {
  const now = new Date();
  // Look back 25 hours to ensure a small overlap so no records are missed
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  // Format dates to ISO-8601 without milliseconds for the NVD API
  const start = yesterday.toISOString().split('.')[0]; 
  const end = now.toISOString().split('.')[0];

  // includeMatchStringChange=true ensures we catch updates to software product names
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}&includeMatchStringChange=true`;
  
  try {
    console.log(`Starting Incremental Sync from ${start} to ${end}`);
    
    const res = await fetch(url, { 
      headers: { "apiKey": env.NVD_API_KEY } // Using your stored secret key
    });
    
    if (!res.ok) {
      throw new Error(`NVD API responded with status: ${res.status}`);
    }
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      
      // Extract CVSS score from the most recent metric version available
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || null;

      // 1. Update the main CVE table including the last_modified field
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(
        cve.id, 
        score, 
        cve.descriptions.find((d: any) => d.lang === 'en')?.value || "", 
        cve.lastModified // This fills the NULL field in your database
      ));

      // 2. Clear old product mappings for this specific CVE to prevent stale entries
      statements.push(env.DB.prepare(`DELETE FROM cve_cpe_mapping WHERE cve_id = ?`).bind(cve.id));

      // 3. Process the updated Configurations (CPE Mappings)
      if (cve.configurations) {
        cve.configurations.forEach((config: any) => {
          config.nodes?.forEach((node: any) => {
            node.cpeMatch?.forEach((match: any) => {
              const parts = match.criteria.split(':');
              // Extract make (vendor) and model (product) from the CPE string
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

    // Execute all changes as a single atomic batch transaction
    if (statements.length > 0) {
      await env.DB.batch(statements);
      console.log(`Successfully processed ${vulnerabilities.length} CVE updates.`);
    } else {
      console.log("No updates found for this period.");
    }
  } catch (err) {
    console.error("Incremental Sync failed:", err);
  }
}
