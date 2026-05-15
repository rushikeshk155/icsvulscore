/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 2.1 (UI Optimized)
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- 0. HANDLE CORS PRE-FLIGHT ---
    // Essential for the Frontend UI to talk to this Worker from a different domain
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // --- 1. SEARCH API: Retrieve asset vulnerabilities with Weighted ICS Logic ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    
    if (make && model) {
      const data = await env.DB.prepare(`
        SELECT 
          c.cve_id, 
          c.cvss_score,
          -- CUSTOM RISK SCORE calculation
          MIN(10.0, c.cvss_score + 
            (CASE WHEN k.cve_id IS NOT NULL THEN 2.0 ELSE 0.0 END) + 
            (CASE WHEN at.tactic IN ('impact', 'inhibit response function') THEN 1.5 ELSE 0.0 END)
          ) as ics_weighted_score,
          c.description, 
          at.tactic, 
          at.name as technique_name,
          CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev,
          -- Mapping KEV required action as the primary mitigation
          IFNULL(k.required_action, 'Refer to vendor security advisory for patch details.') as mitigation
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id
        LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        WHERE m.make LIKE ? AND m.model LIKE ? 
        GROUP BY c.cve_id 
        ORDER BY ics_weighted_score DESC, is_kev DESC
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

    // --- 2. MANUAL SYNC: MITRE ATT&CK Library ---
    if (url.pathname === "/sync-attack-library") {
      try {
        await syncAttackTechniques(env);
        return new Response("MITRE Library hydrated.");
      } catch (e: any) {
        return new Response(`Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- 3. MANUAL SYNC: CISA KEV ---
    if (url.pathname === "/sync-kev") {
      try {
        await syncKevData(env);
        return new Response("CISA KEV Table updated.");
      } catch (e: any) {
        return new Response(`KEV Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- 4. MANUAL SYNC: Backfill Intelligence Mappings ---
    if (url.pathname === "/backfill-attack") {
      try {
        const status = await backfillAttackMappings(env);
        return new Response(status);
      } catch (e: any) {
        return new Response(`Mapping Error: ${e.message}`, { status: 500 });
      }
    }

    // --- 5. MAINTENANCE: NVD Sync Routes ---
    if (url.pathname === "/sync-incremental") {
      try {
        await updateNVDIncremental(env);
        return new Response("NVD Sync complete.");
      } catch (e: any) {
        return new Response(`NVD Error: ${e.message}`, { status: 500 });
      }
    }

    // --- 6. DATABASE HEALTH REPORT ---
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

    return new Response("ICS Vuln Score API is Online. Use ?make= &model= for audit data.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
