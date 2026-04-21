export async function backfillAttackMappings(env: any) {
  // 1. Grab CVEs that have a weakness but aren't mapped to a technique yet
  const { results } = await env.DB.prepare(`
    SELECT wd.cve_id 
    FROM cve_weakness_data wd
    WHERE wd.cve_id NOT IN (SELECT cve_id FROM cve_attack_mapping)
    LIMIT 2000
  `).all();

  if (!results || results.length === 0) {
    return "No new CVEs found to map. All current weaknesses are processed.";
  }

  // 2. Map them using a TRIMmed and fuzzy join to ignore spaces/formatting
  const { meta } = await env.DB.prepare(`
    INSERT OR IGNORE INTO cve_attack_mapping (cve_id, technique_id)
    SELECT wd.cve_id, r.technique_id
    FROM cve_weakness_data wd
    JOIN attack_to_cwe_reference r ON 
      REPLACE(wd.cwe_id, ' ', '') = REPLACE(r.cwe_id, ' ', '')
    WHERE wd.cve_id IN (SELECT value FROM json_each(?))
  `).bind(JSON.stringify(results.map(r => r.cve_id))).run();

  return `Processed ${results.length} CVEs. Successfully linked ${meta.changes} new mappings.`;
}
