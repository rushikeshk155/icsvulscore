/**
 * Optimized NVD Sync Script
 * Goal: Update 'last_modified' column in the 'cves' table.
 * Fix: Uses CHUNK_SIZE to prevent D1 CPU Time Limit errors.
 */

export async function updateNVDIncremental(env: any) {
  const now = new Date();
  const yesterday = new Date(now.getTime() - (25 * 60 * 60 * 1000));
  
  // Format: [YYYY]-[MM]-[DD]T[HH]:[MM]:[SS].000Z
  const start = yesterday.toISOString().split('.')[0] + ".000Z"; 
  const end = now.toISOString().split('.')[0] + ".000Z";

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${start}&lastModEndDate=${end}`;
  
  try {
    console.log(`Fetching from NVD: ${start} to ${end}`);
    
    const res = await fetch(url, { 
      headers: { "apiKey": env.NVD_API_KEY || "" } 
    });
    
    if (!res.ok) throw new Error(`NVD API status: ${res.status}`);
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    
    if (vulnerabilities.length === 0) {
      console.log("No new updates found.");
      return;
    }

    const statements: any[] = [];

    for (const v of vulnerabilities) {
      const cve = v.cve;
      
      // Extract CVSS score
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? 
                    cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null;

      const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? "";

      // UPDATE ONLY THE CVES TABLE
      // This specifically targets the last_modified column
      statements.push(env.DB.prepare(`
        INSERT OR REPLACE INTO cves (cve_id, cvss_score, description, last_modified) 
        VALUES (?, ?, ?, ?)
      `).bind(
        cve.id, 
        score, 
        desc, 
        cve.lastModified // NIST provided value
      ));
    }

    /**
     * WORKAROUND: SEQUENTIAL CHUNKING
     * A massive update affecting many rows must be run in chunks.
     * Processing 50 rows at a time prevents CPU timeouts.
     */
    const CHUNK_SIZE = 50;
    console.log(`Processing ${statements.length} updates in chunks of ${CHUNK_SIZE}...`);

    for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
      const chunk = statements.slice(i, i + CHUNK_SIZE);
      // await each batch sequentially so they are not processed all at once
      await env.DB.batch(chunk); 
      console.log(`Successfully synced chunk ${Math.floor(i / CHUNK_SIZE) + 1}`);
    }

    console.log("Database update of 'last_modified' completed successfully.");

  } catch (err) {
    console.error("D1 Update Error:", err);
    throw err;
  }
}
