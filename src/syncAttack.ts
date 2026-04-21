/**
 * MITRE ATT&CK Synchronization
 * Target: 'attack_techniques' table
 * Purpose: Populates the encyclopedia of adversary behaviors.
 */

const ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

export async function syncAttackTechniques(env: any) {
  console.log("Fetching MITRE ATT&CK STIX data...");
  
  const res = await fetch(ATTACK_STIX_URL);
  if (!res.ok) throw new Error(`Failed to fetch MITRE data: ${res.status}`);
  
  const stixBundle: any = await res.json();
  const objects = stixBundle.objects || [];

  const statements: any[] = [];
  
  for (const obj of objects) {
    // Only process active 'attack-pattern' objects (Techniques)
    if (obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_is_subtechnique) {
      const techniqueId = obj.external_references?.find(
        (ref: any) => ref.source_name === 'mitre-attack'
      )?.external_id;
      
      if (techniqueId) {
        // Tactics are stored in the 'kill_chain_phases' array
        const tactic = obj.kill_chain_phases?.[0]?.phase_name ?? "Unknown";
        
        statements.push(env.DB.prepare(`
          INSERT OR REPLACE INTO attack_techniques (technique_id, tactic, name, description)
          VALUES (?, ?, ?, ?)
        `).bind(
          techniqueId,
          tactic.replace(/-/g, ' '), // Format: 'initial-access' -> 'initial access'
          obj.name,
          obj.description?.split('\n')[0] ?? "" // Store the first paragraph for brevity
        ));
      }
    }
  }

  // Process in chunks of 50 to stay under D1 CPU limits
  const CHUNK_SIZE = 50;
  console.log(`Updating ${statements.length} techniques...`);

  for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
    await env.DB.batch(statements.slice(i, i + CHUNK_SIZE));
  }

  console.log("ATT&CK Library hydration complete.");
}
