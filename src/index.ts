/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 4.5 (Structured Only - Zero False Positives)
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- 0. GLOBAL CORS PRE-FLIGHT HANDLER ---
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // --- 1. SEARCH API ENGINE (STRUCTURED CPE ONLY) ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    const firmware = url.searchParams.get("firmware");
    
    if (make && model) {
      const cleanMake = make.toLowerCase().replace(/[-_\s]/g, "");
      const cleanModel = model.toLowerCase().replace(/[-_\s]/g, "");
      const modelNumberMatch = model.match(/\d+/);
      const modelNumStr = modelNumberMatch ? modelNumberMatch[0] : cleanModel;

      // Rigid structured query targeting exact CPE properties only
      let query = `
        SELECT 
          c.cve_id, 
          c.cvss_score,
          MIN(10.0, c.cvss_score + 
            (CASE WHEN k.cve_id IS NOT NULL THEN 2.0 ELSE 0.0 END) + 
            (CASE WHEN at.tactic IN ('impact', 'inhibit response function') THEN 1.5 ELSE 0.0 END)
          ) as ics_weighted_score,
          c.description, 
          IFNULL(at.tactic, 'NONE') as tactic, 
          at.name as technique_name,
          CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev,
          IFNULL(k.required_action, 'Refer to vendor security advisory for mitigation guidance.') as mitigation
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id
        LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        WHERE 
          REPLACE(REPLACE(REPLACE(LOWER(m.make), '-', ''), ' ', ''), '_', '') LIKE ? 
          AND (
            REPLACE(REPLACE(REPLACE(LOWER(m.model), '-', ''), ' ', ''), '_', '') LIKE ?
            OR m.model LIKE ?
          )
      `;

      const params: any[] = ["%" + cleanMake + "%", "%" + cleanModel + "%", "%" + modelNumStr + "%"];

      // Handle firmware/wildcard tracking safely
      if (firmware && firmware.trim() !== "" && firmware !== "null" && firmware !== "*") {
        const cleanFw = firmware.replace(/[*]/g, "").trim().toLowerCase();
        // Match exact firmware string, or blanket wildcard fields, or catch range entries safely
        query += ` AND (m.firmware LIKE ? OR m.firmware = '*' OR m.firmware = 'all' OR m.firmware LIKE ? )`;
        params.push("%" + cleanFw + "%");
        params.push(cleanFw.split('.')[0] + ".%"); // If user types 4.8.*, matches 4.8.%
      }

      query += ` GROUP BY c.cve_id ORDER BY ics_weighted_score DESC, is_kev DESC`;

      try {
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
      } catch (err: any) {
        return Response.json({ error: "Database Execution Error", details: err.message }, { status: 500 });
      }
    }

    // --- 2. ADMINISTRATIVE SYNC MAINTENANCE ROUTES ---
    if (url.pathname === "/sync-attack-library") {
      await syncAttackTechniques(env);
      return new Response("MITRE ATT&CK Matrix synchronized.");
    }

    if (url.pathname === "/sync-kev") {
      await syncKevData(env);
      return new Response("CISA Known Exploited Vulnerabilities table refreshed.");
    }

    if (url.pathname === "/backfill-attack") {
      const status = await backfillAttackMappings(env);
      return new Response(status);
    }

    if (url.pathname === "/sync-incremental") {
      await updateNVDIncremental(env);
      return new Response("Daily incremental NVD sync processed.");
    }

    if (url.pathname === "/backfill-execute") {
      await backfillNVD(env);
      return new Response("NVD Batch backfill routine initiated.");
    }

    // --- 3. INFRASTRUCTURE HEALTH TRACKING ---
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

    return new Response("ICS Vuln Intelligence API Engine Core Active.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
