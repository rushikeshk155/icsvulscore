export async function syncKevData(env: any) {
  const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  
  try {
    console.log("Fetching CISA KEV data...");
    const res = await fetch(KEV_URL);
    if (!res.ok) throw new Error(`CISA Feed down: ${res.status}`);
    
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];

    const statements = vulnerabilities.map((v: any) => {
      return env.DB.prepare(`
        INSERT OR REPLACE INTO cisa_kev (
          cve_id, vendor_project, product, vulnerability_name, 
          date_added, short_description, required_action, 
          due_date, known_ransomware_campaign_use
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        v.cveID, 
        v.vendorProject, 
        v.product, 
        v.vulnerabilityName, 
        v.dateAdded, 
        v.shortDescription, 
        v.requiredAction, 
        v.dueDate, 
        v.knownRansomwareCampaignUse
      );
    });

    // --- IMPROVEMENT: CHUNKING ---
    // D1 works best when large batches are split
    const CHUNK_SIZE = 50;
    for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
      const chunk = statements.slice(i, i + CHUNK_SIZE);
      await env.DB.batch(chunk);
      if (i % 250 === 0) console.log(`Synced ${i} KEV records...`);
    }

    console.log(`KEV Sync complete. Total records: ${vulnerabilities.length}`);
  } catch (err) {
    console.error("KEV Sync Error:", err);
    throw err; // Re-throw so the index.ts handler can catch it and show the error message
  }
}
