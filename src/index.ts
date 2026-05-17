/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 4.0 (Two-Pass Resilient Search Engine Core)
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

    // --- 1. SEARCH API ENGINE (TWO-PASS RESILIENT ARCHITECTURE) ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    const firmware = url.searchParams.get("firmware");
    
    if (make && model) {
      const cleanMake = make.toLowerCase().replace(/[-_\s]/g, "");
      const cleanModel = model.toLowerCase().replace(/[-_\s]/g, "");
      const modelNumberMatch = model.match(/\d+/);
      const modelNumStr = modelNumberMatch ? modelNumberMatch[0] : cleanModel;

      // ==========================================
      // PASS 1: STRICT STRUCTURED CPE MATCHING
      // ==========================================
      let pass1Query = `
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

      const pass1Params: any[] = ["%" + cleanMake + "%", "%" + cleanModel + "%", "%" + modelNumStr + "%"];

      if (firmware && firmware.trim() !== "" && firmware !== "null" && firmware !== "*") {
        const cleanFw = firmware.replace(/[*]/g, "").trim().toLowerCase();
        pass1Query += ` AND (m.firmware LIKE ? OR m.firmware = '*' OR m.firmware = 'all')`;
        pass1Params.push("%" + cleanFw + "%");
      }

      pass1Query += ` GROUP BY c.cve_id ORDER BY ics_weighted_score DESC, is_kev DESC`;

      try {
        let data = await env.DB.prepare(pass1Query).bind(...pass1Params).all();

        // If Pass 1 successfully located true structured hardware profiles, return them directly!
        if (data.results && data.results.length > 0) {
          return Response.json({ count: data.results.length, vulnerabilities: data.results }, {
            headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" }
          });
        }

        // ==========================================
        // PASS 2: LOOSE DESCRIPTION FALLBACK
        // (Only executes if strict matching returned 0 assets)
        // ==========================================
        let platformAnchor = "";
        if (cleanMake.includes("siemens")) platformAnchor = "s7";
        if (cleanMake.includes("rockwell") || cleanMake.includes("allen")) platformAnchor = "logix";

        let pass2Query = `
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
            IFNULL(k.required_action, 'Refer to vendor security advisory.') as mitigation
          FROM cves c 
          LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id
          LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id
          LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
          WHERE 
            LOWER(c.description) LIKE ? 
            AND LOWER(c.description) LIKE '%' || ? || '%'
            AND LOWER(c.description) LIKE '%' || ? || '%'
        `;

        const pass2Params = ["%" + make.toLowerCase() + "%", modelNumStr, platformAnchor];

        if (firmware && firmware.trim() !== "" && firmware !== "null" && firmware !== "*") {
          const cleanFw = firmware.replace(/[*]/g, "").trim().toLowerCase();
          pass2Query += ` AND LOWER(c.description) LIKE ?`;
          pass2Params.push("%" + cleanFw + "%");
        }

        pass2Query += ` GROUP BY c.cve_id ORDER BY ics_weighted_score DESC, is_kev DESC`;
        
        data = await env.DB.prepare(pass2Query).bind(...pass2Params).all();
        
        return Response.json({ count: data.results.length, vulnerabilities: data.results }, {
          headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" }
        });

      } catch (err: any) {
        return Response.json({ error: "Database Execution Error", details: err.message }, { status: 500 });
      }
    }

    // --- 2. ADMINISTRATIVE SYNC MAINTENANCE ROUTES ---
    if (url.pathname === "/sync-attack-library") {
      try {
        await syncAttackTechniques(env);
        return new Response("MITRE ATT&CK Matrix synchronized.");
      } catch (e: any) {
        return new Response(`ATT&CK Sync failed: ${e.message}`, { status: 500 });
      }
    }

    if (url.pathname === "/sync-kev") {
      try {
        await syncKevData(env);
        return new Response("CISA Known Exploited Vulnerabilities table refreshed.");
      } catch (e: any) {
        return new Response(`KEV Sync failed: ${e.message}`, { status: 500 });
      }
    }

    if (url.pathname === "/backfill-attack") {
      try {
        const status = await backfillAttackMappings(env);
        return new Response(status);
      } catch (e: any) {
        return new Response(`Mapping Engine failure: ${e.message}`, { status: 500 });
      }
    }

    if (url.pathname === "/sync-incremental") {
      try {
        await updateNVDIncremental(env);
        return new Response("Daily incremental NVD sync processed.");
      } catch (e: any) {
        return new Response(`Incremental sync failure: ${e.message}`, { status: 500 });
      }
    }

    if (url.pathname === "/backfill-execute") {
      try {
        await backfillNVD(env);
        return new Response("NVD Batch backfill routine initiated.");
      } catch (e: any) {
        return new Response(`Backfill process error: ${e.message}`, { status: 500 });
      }
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

    // Default Fallback
    return new Response("ICS Vuln Intelligence API Engine Core Active. Connect via your UI dashboard.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  // Daily Cron Trigger for Continuous Sync Execution
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
