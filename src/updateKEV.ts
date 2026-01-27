export async function syncKevData(env: any) {
  const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  
  try {
    const res = await fetch(KEV_URL);
    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];

    const statements = vulnerabilities.map((v: any) => {
      return env.DB.prepare(`
        INSERT OR REPLACE INTO cisa_kev (
          cve_id, vendor_project, product, vulnerability_name, 
          date_added, short_description, required_action, 
          due_date, known_ransomware_campaign_use
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(v.cveID, v.vendorProject, v.product, v.vulnerabilityName, v.dateAdded, v.shortDescription, v.requiredAction, v.dueDate, v.knownRansomwareCampaignUse);
    });

    await env.DB.batch(statements);
    console.log("KEV Sync complete.");
  } catch (err) {
    console.error("KEV Sync Error:", err);
  }
}
