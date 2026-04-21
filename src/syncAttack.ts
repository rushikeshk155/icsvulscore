// Add the ICS URL to your script
const ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const ICS_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json";

export async function syncAttackTechniques(env: any) {
  const urls = [ENTERPRISE_URL, ICS_URL];
  let totalAdded = 0;

  for (const url of urls) {
    console.log(`Fetching from: ${url}`);
    const res = await fetch(url);
    const stixBundle: any = await res.json();
    const objects = stixBundle.objects || [];
    const statements: any[] = [];

    for (const obj of objects) {
      if (obj.type === 'attack-pattern' && !obj.revoked) {
        const techniqueId = obj.external_references?.find(r => r.source_name.startsWith('mitre-attack'))?.external_id;
        if (techniqueId) {
          const tactic = obj.kill_chain_phases?.[0]?.phase_name ?? "Unknown";
          statements.push(env.DB.prepare(`
            INSERT OR REPLACE INTO attack_techniques (technique_id, tactic, name, description)
            VALUES (?, ?, ?, ?)
          `).bind(techniqueId, tactic.replace(/-/g, ' '), obj.name, obj.description?.split('\n')[0] || ""));
        }
      }
    }

    // Chunked Batch Insert
    for (let i = 0; i < statements.length; i += 50) {
      await env.DB.batch(statements.slice(i, i + 50));
    }
    totalAdded += statements.length;
  }
  console.log(`Hydration complete. Total Techniques in Library: ${totalAdded}`);
}
