export async function backfillAttackMappings(env: any) {
  // Increase limit to 5000 for faster processing
  const { results } = await env.DB.prepare(`
    SELECT wd.cve_id 
    FROM cve_weakness_data wd
    WHERE wd.cve_id NOT IN (SELECT cve_id FROM cve_attack_mapping)
    LIMIT 5000
  `).all();

  if (!results || results.length === 0) return "Backfill complete. No more unmapped weaknesses found.";

  // Clean data on the fly during the join
  const { meta } = await env.DB.prepare(`
    INSERT OR IGNORE INTO cve_attack_mapping (cve_id, technique_id)
    SELECT wd.cve_id, r.technique_id
    FROM cve_weakness_data wd
    JOIN attack_to_cwe_reference r ON 
      REPLACE(wd.cwe_id, ' ', '') = REPLACE(r.cwe_id, ' ', '')
    WHERE wd.cve_id IN (SELECT value FROM json_each(?))
  `).bind(JSON.stringify(results.map(r => r.cve_id))).run();

  return `Batch complete. Successfully linked ${meta.changes} new mappings. Refresh to continue.`;
}
