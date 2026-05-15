/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 2.2 (Firmware & Mitigation Integrated)
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
    // Necessary for browsers to allow the UI to talk to the Worker
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // --- 1. SEARCH API: Firmware-Aware ICS Weighted Logic ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    const firmware = url.searchParams.get("firmware");
    
    if (make && model) {
      let query = `
        SELECT 
          c.cve_id, 
          c.cvss_score,
          -- WEIGHTED SCORING ENGINE
          MIN(10.0, c.cvss_score + 
            (CASE WHEN k.cve_id IS NOT NULL THEN 2.0 ELSE 0.0 END) + 
            (CASE WHEN at.tactic IN ('impact', 'inhibit response function') THEN 1.5 ELSE 0.0 END)
          ) as ics_weighted_score,
          c.description, 
          at.tactic, 
          at.name as technique_name,
          CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev,
          IFNULL(k.required_action, 'Refer to vendor security advisory for patch details.') as mitigation
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id
        LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        WHERE m.make LIKE ? AND m.model LIKE ?
      `;

      const params: any[] = ["%" + make.toLowerCase() + "%", "%" + model.toLowerCase() + "%"];

      // Add Firmware filtering if provided by the UI
      if (firmware && firmware.trim() !== "" && firmware !== "null") {
        query += ` AND m.firmware LIKE ?`;
        params.push("%" + firmware.toLowerCase() + "%");
      }

      query += ` GROUP BY c.cve_id ORDER BY ics_weighted_score DESC, is_kev DESC`;

      const data = await env.DB.prepare(query).bind(...params).all();
      
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

    // --- 2. ADMIN & MAINTENANCE ROUTES ---

    // MITRE ATT&CK Library Sync
    if (url.pathname === "/sync-attack-library") {
      try {
        await syncAttackTechniques(env);
        return new Response("MITRE Library synced successfully.");
      } catch (e: any) {
        return new Response(`Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // CISA KEV Sync
    if (url.pathname === "/sync-kev") {
      try {
        await syncKevData(env);
        return new Response("CISA KEV updated.");
      } catch (e: any) {
        return new Response(`KEV Error: ${e.message}`, { status: 500 });
      }
    }

    // Intelligence Mapping Backfill (Link CVEs to MITRE)
    if (url.pathname === "/backfill-attack") {
      try {
        const status = await backfillAttackMappings(env);
        return new Response(status);
      } catch (e: any) {
        return new Response(`Mapping Error: ${e.message}`, { status: 500 });
      }
    }

    // NVD Data Maintenance
    if (url.pathname === "/sync-incremental") {
        await updateNVDIncremental(env);
        return new Response("NVD Sync complete.");
    }

    if (url.pathname === "/backfill-execute") {
        await backfillNVD(env);
        return new Response("NVD Backfill started.");
    }

    // Database Health Status
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

    return new Response("ICS Vuln API Online. Use UI dashboard for scans.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  /**
   * 2. SCHEDULED HANDLER: Runs daily at midnight
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
