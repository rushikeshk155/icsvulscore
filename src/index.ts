/**
 * ICS Vuln Score - Main Worker Handler
 * Features: Search API, Daily Incremental Sync, and Long-Running Backfill.
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";

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

    // --- MANAUL SYNC: Incremental (Quick) ---
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
      // Use await to prevent task cancellation for this critical job
      try {
        await backfillNVD(env);
        return new Response("Full Backfill process finished. Check D1 for results.");
      } catch (e: any) {
        return new Response(`Backfill Error: ${e.message}`, { status: 500 });
      }
    }

    // --- DATABASE HEALTH CHECK ---
    if (url.pathname === "/health") {
      const stats = await env.DB.prepare(`
        SELECT COUNT(*) as total, COUNT(last_modified) as healed FROM cves
      `).first();
      return Response.json(stats);
    }

    return new Response("ICS Vuln Score API is Active. Use /backfill-execute to begin healing.", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  /**
   * 2. SCHEDULED HANDLER: Automated Maintenance
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    switch (controller.cron) {
      case "0 0 * * *": 
        console.log("Daily Maintenance: Running Incremental NVD Sync...");
        ctx.waitUntil(updateNVDIncremental(env));
        break;
      case "0 0 */2 * *":
        console.log("Bi-Daily Maintenance: Running KEV Sync...");
        ctx.waitUntil(syncKevData(env));
        break;
    }
  }
};
