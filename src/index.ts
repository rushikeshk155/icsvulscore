/**
 * ICS Vuln Score - Main Worker Handler
 * Features: Search API, Daily Incremental Sync, Backfill, KEV Sync, and ATT&CK Library.
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack"; // Task 1 Function

export default {
  /**
   * 1. FETCH HANDLER: API and Manual Triggers
   */
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- SEARCH API ---
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
        headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" }
      });
    }

    // --- TASK 1: MANUAL SYNC - ATT&CK Library ---
    if (url.pathname === "/sync-attack-library") {
      try {
        await syncAttackTechniques(env);
        return new Response("MITRE ATT&CK Library hydrated successfully.");
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

    // --- MANAUL SYNC: NVD Incremental ---
    if (url.pathname === "/sync-incremental") {
      try {
        await updateNVDIncremental(env);
        return new Response("Daily Incremental Sync completed successfully.");
      } catch (e: any) {
        return new Response(`Sync failed: ${e.message}`, { status: 500 });
      }
    }

    // --- MANUAL SYNC: Backfill (Long-Running) ---
    if (url.pathname === "/backfill-execute") {
      try {
        await backfillNVD(env);
        return new Response("Full Backfill process finished.");
      } catch (e: any) {
        return new Response(`Backfill Error: ${e.message}`, { status: 500 });
      }
    }

    // --- DATABASE HEALTH CHECK ---
    if (url.pathname === "/health") {
      const stats = await env.DB.prepare(`
        SELECT 
          (SELECT COUNT(*) FROM cves) as total_cves,
          (SELECT COUNT(*) FROM attack_techniques) as attack_techniques,
          (SELECT COUNT(*) FROM cisa_kev) as kev_count
      `).first();
      return Response.json(stats);
    }

    return new Response("ICS Vuln Score API is Active.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  /**
   * 2. SCHEDULED HANDLER: Automated Maintenance
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    // Regular maintenance ensures KEV and NVD stay current
    console.log(`Running scheduled task: ${controller.cron}`);
    
    ctx.waitUntil(updateNVDIncremental(env));
    ctx.waitUntil(syncKevData(env));
  }
};
