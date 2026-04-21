export async function backfillAttackMappings(env: any) {
  console.log("Starting 300k CVE-to-ATT&CK mapping...");

  // 1. Get a batch of CVEs that are not yet mapped
  const { results } = await env.DB.prepare(`
    SELECT cve_id FROM cves 
    WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM cve_attack_mapping)
    LIMIT 2000
  `).all();

  if (results.length === 0) return "Mapping Complete.";

  const statements: any[] = [];
  for (const row of results) {
    // Logic: If the CVE matches a CWE in our 'reference' bridge, create the link
    statements.push(env.DB.prepare(`
      INSERT OR IGNORE INTO cve_attack_mapping (cve_id, technique_id)
      SELECT ?, technique_id 
      FROM attack_to_cwe_reference 
      WHERE cwe_id IN (
          -- This subquery extracts the CWE ID we saved during the NVD backfill
          SELECT cwe_id FROM cve_weakness_data WHERE cve_id = ?
      )
    `).bind(row.cve_id, row.cve_id));
  }

  // Batch execute
  for (let i = 0; i < statements.length; i += 50) {
    await env.DB.batch(statements.slice(i, i + 50));
  }

  return `Mapped ${results.length} rows. Run again for next batch.`;
}
