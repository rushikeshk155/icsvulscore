/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 3.2 (Fuzzy Normalization & Smart Range Fallbacks)
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- 0. CORSA PRE-FLIGHT BLOCK ---
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // --- 1. CORE INTELLIGENCE SEARCH ROUTE ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    const firmware = url.searchParams.get("firmware");
    
    if (make && model) {
      // Strip dashes, underscores, and spaces to cross-reference entries dynamically
      let cleanMake = make.toLowerCase().replace(/[-_\s]/g, "");
      let cleanModel = model.toLowerCase().replace(/[-_\s]/g, "");
      
      // Separate out potential digits to broaden target framework hits (e.g., extracts "1200")
      const modelNumberMatch = model.match(/\d+/);
      const modelNumStr = modelNumberMatch ? modelNumberMatch[0] : cleanModel;

      let query = `
        SELECT 
          c.cve_id, 
          c.cvss_score,
          -- CALCULATION WEIGHTED ENGINE (BASE + ACTIVE THREAT + SYSTEM EXPLOIT FACTOR)
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
          -- Broad Vendor Checking Rules
          (REPLACE(REPLACE(REPLACE(LOWER(m.make), '-', ''), ' ', ''), '_', '') LIKE ? OR LOWER(c.description) LIKE ?)
          AND 
          -- Broad Model Family Checking Rules
          (REPLACE(REPLACE(REPLACE(LOWER(m.model), '-', ''), ' ', ''), '_', '') LIKE ? 
           OR m.model LIKE ? 
           OR LOWER(c.description) LIKE ?)
      `;

      const params: any[] = [
        "%" + cleanMake + "%",
        "%" + make.toLowerCase() + "%",
        "%" + cleanModel + "%",
        "%" + modelNumStr + "%",
        "%" + model.toLowerCase() + "%"
      ];

      // Deep Evaluation Range Parser
      if (firmware && firmware.trim() !== "" && firmware !== "null" && firmware !== "*") {
        const cleanFw = firmware.replace(/[*]/g, "").trim().toLowerCase();
        
        query += `
          AND (
            m.firmware LIKE ? 
            OR m.firmware = '*' 
            OR m.firmware = 'all'
            -- Catch-all fallback when NVD groups multiple software versions like "< V4.5.0"
            OR (LOWER(c.description) LIKE '%version%' AND LOWER(c.description) LIKE '%<%')
          )
        `;
        params.push("%" + cleanFw + "%");
      }

      // Group outputs and push highest risk values to index 0
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

    // --- 2. ADMIN/SYNC PIPELINE CONTROL MAPS ---
    if (url.pathname === "/sync-attack-library") {
      await syncAttackTechniques(env);
      return new Response("MITRE ATT&CK Matrix synchronized.");
    }

    if (url.pathname === "/sync-kev") {
      await syncKevData(env);
      return new Response("CISA KEV updated.");
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

    // --- 3. RUNTIME APP STATUS CONTROL ---
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

    return new Response("ICS Vuln Intelligence API Engine Core Active. Connect via UI.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
