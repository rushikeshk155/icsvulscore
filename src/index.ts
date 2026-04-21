import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- 1. SEARCH API (The Unified Intelligence View) ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    
    if (make && model) {
      const data = await env.DB.prepare(`
        SELECT 
          c.cve_id, 
          c.cvss_score, 
          c.description, 
          at.tactic, 
          at.name as technique_name,
          CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id
        LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        WHERE m.make LIKE ? AND m.model LIKE ? 
        GROUP BY c.cve_id 
        ORDER BY is_kev DESC, c.cvss_score DESC
      `).bind("%" + make.toLowerCase() + "%", "%" + model.toLowerCase() + "%").all();
      
      return Response.json({ 
        count: data.results.length,
        vulnerabilities: data.results 
      }, {
        headers: { 
          "Access-Control-Allow-Origin": "*", 
          "Content-Type": "application/json" 
        }
      });
    }

    // --- 2. MITRE ATT&CK SYNC (Enterprise + ICS) ---
    if (url.pathname === "/sync-attack-library") {
      try {
        await syncAttackTechniques(env);
        return new Response("MITRE ATT&CK Library (Enterprise + ICS) hydrated successfully.");
      } catch (e: any) {
        return new Response(`ATT&CK Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- 3. CISA KEV SYNC ---
    if (url.pathname === "/sync-kev") {
      try {
        await syncKevData(env);
        return new Response("CISA KEV Table updated successfully.");
      } catch (e: any) {
        return new Response(`KEV Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- 4. HISTORICAL MAPPING BACKFILL ---
    if (url.pathname === "/backfill-attack") {
      try {
        const status = await backfillAttackMappings(env);
        return new Response(status);
      } catch (e: any) {
        return new Response(`Mapping Error: ${e.message}`, { status: 500 });
      }
    }

    // --- 5. NVD MAINTENANCE ROUTES ---
    if (url.pathname === "/sync-incremental") {
      try {
        await updateNVDIncremental(env);
        return new Response("NVD Incremental Sync completed.");
      } catch (e: any) {
        return new Response(`NVD Sync failed: ${e.message}`, { status: 500 });
      }
    }

    if (url.pathname === "/backfill-execute") {
      try {
        await backfillNVD(env);
        return new Response("NVD Backfill process completed.");
      } catch (e: any) {
        return new Response(`Backfill Error: ${e.message}`, { status: 500 });
      }
    }

    // --- 6. HEALTH CHECK ---
    if (url.pathname === "/health") {
      const stats = await env.DB.prepare(`
        SELECT 
          (SELECT COUNT(*) FROM cves) as total_cves,
          (SELECT COUNT(*) FROM attack_techniques) as total_techniques,
          (SELECT COUNT(*) FROM cisa_kev) as total_kev,
          (SELECT COUNT(*) FROM cve_attack_mapping) as mapped_cves
      `).first();
      return Response.json(stats);
    }

    return new Response("ICS Vuln Score API is Online.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  // AUTOMATED DAILY UPDATES
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
