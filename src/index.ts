/**
 * ICS Vuln Score - Main Worker Handler
 * Features: 
 * - Search API (Make/Model)
 * - NVD Incremental Sync (Daily)
 * - CISA KEV Sync (Exploited Vulns)
 * - MITRE ATT&CK Library (Enterprise + ICS)
 * - Historical Backfill (300k Mapping)
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

export default {
  /**
   * 1. FETCH HANDLER: Handles API requests and Manual Triggers
   */
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- SEARCH API: Retrieve vulnerabilities by asset ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    
    if (make && model) {
      const data = await env.DB.prepare(`
        SELECT c.cve_id, c.cvss_score, c.description, c.last_modified
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        WHERE m.make LIKE ? AND m.model LIKE ? 
        ORDER BY c.cvss_score DESC
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

    // --- TASK 1: MANUAL SYNC - MITRE ATT&CK Library (Enterprise + ICS) ---
    if (url.pathname === "/sync-attack-library") {
      try {
        await syncAttackTechniques(env);
        return new Response("MITRE ATT&CK Library (Enterprise + ICS) hydrated successfully.");
      } catch (e: any) {
        return new Response(`ATT&CK Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- TASK 2: MANUAL SYNC - CISA KEV ---
    if (url.pathname === "/sync-kev") {
      try {
        await syncKevData(env);
        return new Response("CISA KEV Table updated successfully.");
      } catch (e: any) {
        return new Response(`KEV Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- TASK 3: MANUAL SYNC - Backfill ATT&CK Mappings (Historical) ---
    if (url.pathname === "/backfill-attack") {
      try {
        const status = await backfillAttackMappings(env);
        return new Response(status);
      } catch (e: any) {
        return new Response(`Mapping Error: ${e.message}`, { status: 500 });
      }
    }

    // --- MAINTENANCE: NVD Incremental Sync ---
    if (url.pathname === "/sync-incremental") {
      try {
        await updateNVDIncremental(env);
        return new Response("NVD Incremental Sync completed.");
      } catch (e: any) {
        return new Response(`NVD Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- MAINTENANCE: Full NVD Backfill (Historical) ---
    if (url.pathname === "/backfill-execute") {
      try {
        await backfillNVD(env);
        return new Response("NVD Backfill process completed.");
      } catch (e: any) {
        return new Response(`Backfill Error: ${e.message}`, { status: 500 });
      }
    }

    // --- DATABASE HEALTH CHECK ---
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

  /**
   * 2. SCHEDULED HANDLER: Automated Daily/Weekly Updates
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    console.log(`Running scheduled task for: ${controller.cron}`);
    
    // Automatically keep data fresh
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
