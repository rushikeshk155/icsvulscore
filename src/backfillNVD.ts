/**
 * Yearly Backfill Script
 * Designed to heal the NULL gaps year-by-year without hitting CPU limits.
 */

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export async function backfillNVD(env: any) {
  // CONFIGURATION: Change the year here to target specific gaps from your screenshot
  const TARGET_YEAR = 2025; 
  const WINDOW_SIZE_DAYS = 30; // 30-day windows are safer for D1

  console.log(`Starting Backfill for Year: ${TARGET_YEAR}`);

  // We loop through the year in 30-day chunks
  for (let month = 0; month < 12; month++) {
    const start = new Date(TARGET_YEAR, month, 1);
    const end = new Date(TARGET_YEAR, month + 1, 0);

    const startISO = start.toISOString().split('.')[0] + ".000Z";
    const endISO = end.toISOString().split('.')[0] + ".000Z";

    console.log(`>>> Healing Window: ${startISO} to ${endISO}`);

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${startISO}&lastModEndDate=${endISO}`;
    
    try {
      // PRECAUTION 1: NIST Rate Limit
      await sleep(2000); 

      const res = await fetch(url, { 
        headers: { "apiKey": env.NVD_API_KEY || "" } 
      });

      if (!res.ok) {
        console.error(`NVD API error for ${startISO}: ${res.status}`);
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

        // PRECAUTION 2: SQL Update only (Safe for large DBs)
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

      // PRECAUTION 3: Small DB chunks
      const CHUNK_SIZE = 40; 
      for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
        const chunk = statements.slice(i, i + CHUNK_SIZE);
        await env.DB.batch(chunk);
      }
      
      console.log(`Window success: Healed ${vulnerabilities.length} records.`);

    } catch (err) {
      console.error(`Backfill failed for window ${startISO}:`, err);
    }
  }
  console.log(`Backfill for ${TARGET_YEAR} completed.`);
}
