/**
 * Optimized NVD Sync Script
 * Focus: Updating 'cves' table details and 'last_modified' column only.
 * Strategy: Sequential chunking to prevent D1 CPU timeouts.
 */

export async function updateNVDIncremental(env: any) {
  const now = new Date();
  // Look back 25 hours for a daily update with a small safety overlap
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  // NIST strict ISO-8601 format: YYYY-MM-DDTHH:MM:SS.000Z
  const start = yesterday.toISOString().split('.')[0] + ".000Z"; 
  const end = now.toISOString().split('.')[0] + ".000Z";

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}`;
  
  try {
    console.log(`Fetching updates from: ${start} to ${end}`);
    
    const res = await fetch(url, { 
      headers: { 
        "apiKey": env.NVD_API_KEY || "",
        "User-Agent": "Cloudflare-Worker-CVE-Sync"
      } 
    });
    
    if (!res.ok) throw new Error(`NVD API responded with status: ${res.status}`);
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    
    if (vulnerabilities.length === 0) {
      console.log("No new updates found in this time range.");
      return;
    }

    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      
      // Extract CVSS score from the most recent metric version available
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? 
                    cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null;

      // Extract English description
      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? "";

      // Prepare update for the 'cves' table only
      // This maps 'cve.lastModified' from the API to your 'last_modified' column
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(
        cve.id, 
        score, 
        desc, 
        cve.lastModified // This populates the NULL column
      ));
    }

    // Process in chunks of 50 to stay safely under D1 CPU limits
    const CHUNK_SIZE = 50;
    console.log(`Updating ${vulnerabilities.length} CVE records in chunks...`);

    for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
      const chunk = statements.slice(i, i + CHUNK_SIZE);
      await env.DB.batch(chunk); // Awaiting each small batch prevents CPU timeout
    }

    console.log("Incremental update of 'last_modified' column completed successfully.");

  } catch (err) {
    console.error("Update failed:", err);
    throw err;
  }
}
