/**
 * Incremental NVD Sync Script
 * This version uses the strict ISO-8601 format required by NIST 
 * to prevent 404 errors.
 */

export async function updateNVDIncremental(env: any) {
  const now = new Date();
  // NIST API range cannot exceed 120 days. We use 25 hours for daily overlap.
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  /**
   * NIST REQUIREMENT: Extended ISO-8601 format
   * Format: [YYYY]-[MM]-[DD]T[HH]:[MM]:[SS].000Z
   * We use .toISOString() and split/replace to ensure no hidden 
   * milliseconds or incorrect characters cause a 404.
   */
  const start = yesterday.toISOString().split('.')[0] + ".000Z"; 
  const end = now.toISOString().split('.')[0] + ".000Z";

  // Both start and end parameters are REQUIRED when filtering by date.
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}`;
  
  try {
    console.log(`Fetching updates from: ${start} to ${end}`);
    
    const res = await fetch(url, { 
      headers: { 
        "apiKey": env.NVD_API_KEY,
        "User-Agent": "Cloudflare-Worker-CVE-Sync" // Good practice to identify your bot
      } 
    });
    
    if (!res.ok) {
      // Log the specific status to help debug (e.g., 403 for key issues, 404 for date issues)
      throw new Error(`NVD API Error: ${res.status} - ${res.statusText}`);
    }
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      
      // Extraction logic for CVSS scores
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || null;

      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || "";

      // 1. Update CVE table and populate the last_modified column
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(
        cve.id, 
        score, 
        desc, 
        cve.lastModified // NIST returns lastModified in the response
      ));

      // 2. Clear and rebuild product mappings
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

    if (statements.length > 0) {
      // Execute as a batch to stay within D1 execution limits
      await env.DB.batch(statements);
      console.log(`Successfully updated ${vulnerabilities.length} CVEs.`);
    } else {
      console.log("No new updates found for this time range.");
    }

  } catch (err) {
    console.error("Incremental Sync Process Failed:", err);
  }
}
