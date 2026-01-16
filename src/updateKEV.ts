// src/updateKEV.ts
export async function syncKevData(env: any) {
  console.log("Starting KEV sync...");
  try {
    const response = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    const data: any = await response.json();
    const vulnerabilities = data.vulnerabilities || [];

    const statements = vulnerabilities.map((v: any) => {
      return env.DB.prepare(`
        INSERT OR REPLACE INTO cisa_kev (
          cve_id, vendor_project, product, vulnerability_name, 
          date_added, short_description, required_action, due_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        v.cveID, v.vendorProject, v.product, v.vulnerabilityName, 
        v.dateAdded, v.shortDescription, v.requiredAction, v.dueDate
      );
    });

    // Execute 1,500+ records in a single D1 batch transaction
    await env.DB.batch(statements);
    console.log(`KEV sync complete: ${vulnerabilities.length} records processed.`);
  } catch (e) {
    console.error("KEV Sync Error:", e);
  }
}
