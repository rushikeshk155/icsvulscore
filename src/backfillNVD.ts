/**
 * Comprehensive NVD Backfill Script
 * Target: Safely populate historical 'last_modified' timestamps.
 * Measures: 2s sleep (API safety) + Chunking (DB safety).
 */

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export async function backfillNVD(env: any) {
  // NIST API allows max 120 days per request.
  // We'll move backward in 30-day windows to keep data sizes manageable.
  const TOTAL_DAYS_TO_BACKFILL = 365; // Set this to your desired range (e.g., 365 or 3650)
  const WINDOW_SIZE = 30;

  console.log(`Starting Safety-First Backfill for ${TOTAL_DAYS_TO_BACKFILL} days...`);

  for (let offset = 0; offset < TOTAL_DAYS_TO_BACKFILL; offset += WINDOW_SIZE) {
    const end = new Date(Date.now() - (offset * 24 * 60 * 60 * 1000));
    const start = new Date(end.getTime() - (WINDOW_SIZE * 24 * 60 * 60 * 1000));

    const startISO = start.toISOString().split('.')[0] + ".000Z";
    const endISO = end.toISOString().split('.')[0] + ".000Z";

    console.log(`>>> Window: ${startISO} to ${endISO}`);

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${startISO}&lastModEndDate=${endISO}`;
    
    try {
      // 1. NIST Rate Limit Precaution: Wait 2 seconds before every fetch
      await sleep(2000);

      const res = await fetch(url, { 
        headers: { "apiKey": env.NVD_API_KEY || "" } 
      });

      if (!res.ok) {
        console.error(`Skipping window due to API error ${res.status}`);
        continue;
      }

      const data: any = await res.json();
      const vulnerabilities = data.vulnerabilities || [];
      if (vulnerabilities.length === 0) continue;

      const statements: any[] = [];
      for (const v of vulnerabilities) {
        const cve = v.cve;
        const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 
                      cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? null;

        // Use UPDATE instead of INSERT OR REPLACE to be even safer
        statements.push(env.DB.prepare(`
          UPDATE cves 
          SET cvss_score = ?, description = ?, last_modified = ? 
          WHERE cve_id = ?
        `).bind(
          score, 
          cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? "", 
          cve.lastModified,
          cve.id
        ));
      }

      // 2. D1 CPU Precaution: Process in very small chunks
      const CHUNK_SIZE = 40; 
      for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
        const chunk = statements.slice(i, i + CHUNK_SIZE);
        await env.DB.batch(chunk); // Sequential batching prevents reset
      }
      
      console.log(`Window success: Updated ${vulnerabilities.length} records.`);

    } catch (err) {
      console.error(`Fatal error in window ${startISO}:`, err);
    }
  }
  console.log("Full backfill process finished.");
}
