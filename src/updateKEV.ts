export async function syncKevData(env: any) {
  const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  
  try {
    const res = await fetch(KEV_URL);
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];

    // Map all ~1,500 records
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

    // Execute in one batch
    await env.DB.batch(statements);
    console.log(`Successfully synced ${vulnerabilities.length} KEV records.`);
    
  } catch (err) {
    console.error("KEV Sync Error:", err);
  }
}
