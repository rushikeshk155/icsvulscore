/*
  ===========================================================
  DEPRECATED: PREVIOUS BULK SYNC LOGIC
  ===========================================================
  This section is kept for historical reference only. 
  Note: Avoid using raw cron strings like stars in comments 
  to prevent build errors.

  import { fetchAndStoreNVD } from "./fetchNVD_data";
  
  // Logic previously triggered every 30 minutes:
  // ctx.waitUntil(fetchAndStoreNVD(env));
  ===========================================================
*/

import { updateNVDIncremental } from "./updateNVD";
import { syncKevData } from "./updateKEV";

export default {
  /**
   * 1. FETCH HANDLER
   * Handles API requests, Dashboard UI, and Manual Sync Triggers.
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
      
      const maxScore = data.results.length > 0 
        ? Math.max(...data.results.map((r: any) => r.cvss_score || 0)) 
        : 0;

      return Response.json({ 
        max_cvss: maxScore, 
        vulnerabilities: data.results 
      }, {
        headers: { 
          "Access-Control-Allow-Origin": "*",
          "Content-Type": "application/json" 
        }
      });
    }

    // --- MANUAL TRIGGERS (Awaited to prevent Task Cancellation) ---
    if (url.pathname === "/sync-kev") {
      try {
        await syncKevData(env);
        return new Response("KEV Sync completed successfully.");
      } catch (e: any) {
        return new Response("KEV Sync failed: " + e.message, { status: 500 });
      }
    }

    if (url.pathname === "/sync-incremental") {
      try {
        // We AWAIT this so the browser connection stays open until D1 is updated
        await updateNVDIncremental(env);
        return new Response("Incremental NVD Sync completed successfully.");
      } catch (e: any) {
        return new Response("NVD Sync failed: " + e.message, { status: 500 });
      }
    }

    // --- DASHBOARD UI ---
    if (url.pathname === "/") {
      return new Response(`
        <html>
          <body style="font-family: sans-serif; padding: 20px;">
            <h1>Vulnerability Dashboard</h1>
            <p>Status: Active</p>
            <p>Manual Sync: <a href="/sync-incremental">Trigger NVD Sync</a></p>
          </body>
        </html>
      `, {
        headers: { "Content-Type": "text/html" }
      });
    }

    return new Response("Not Found", { status: 404 });
  },

  /**
   * 2. SCHEDULED HANDLER (CRON JOBS)
   * These run in the background via Cloudflare's edge scheduler.
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    switch (controller.cron) {
      case "0 0 * * *": // Daily NVD Update
        console.log("Cron Trigger: Starting Daily NVD Sync...");
        ctx.waitUntil(updateNVDIncremental(env));
        break;

      case "0 0 */2 * *": // Bi-Daily KEV Update
        console.log("Cron Trigger: Starting KEV Sync...");
        ctx.waitUntil(syncKevData(env));
        break;
    }
  }
};
