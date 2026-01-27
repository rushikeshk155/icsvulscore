/*
  ===========================================================
  HISTORICAL REFERENCE: OLD BULK SYNC LOGIC
  ===========================================================
  The code below is fully commented out and will not run.
  It is kept here only for your future reference.

  import { fetchAndStoreNVD } from "./fetchNVD_data";
  
  // scheduled(controller, env, ctx) {
  //   if (controller.cron === "*/30 * * * *") {
  //     ctx.waitUntil(fetchAndStoreNVD(env));
  //   }
  // }
  ===========================================================
*/

// --- ACTIVE IMPORTS ---
import { updateNVDIncremental } from "./updateNVD";
import { syncKevData } from "./updateKEV";

export default {
  /**
   * 1. FETCH HANDLER
   * This is the "Live" part of your Worker that powers the API and UI.
   */
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // --- SEARCH API ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    
    if (make && model) {
      const data = await env.DB.prepare(`
        SELECT c.cve_id, c.cvss_score, c.description
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
        headers: { "Access-Control-Allow-Origin": "*" }
      });
    }

    // --- MANUAL TEST TRIGGERS ---
    if (url.pathname === "/sync-kev") {
      ctx.waitUntil(syncKevData(env));
      return new Response("KEV Sync triggered.");
    }

    if (url.pathname === "/sync-incremental") {
      ctx.waitUntil(updateNVDIncremental(env));
      return new Response("Incremental NVD Sync triggered.");
    }

    // --- DASHBOARD UI ---
    if (url.pathname === "/") {
      return new Response("<h1>Vulnerability Dashboard</h1><p>Active and Synced.</p>", {
        headers: { "Content-Type": "text/html" }
      });
    }

    return new Response("Not Found", { status: 404 });
  },

  /**
   * 2. SCHEDULED HANDLER (CRON JOBS)
   * This runs automatically based on your wrangler.json triggers.
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    switch (controller.cron) {
      case "0 0 * * *": // Daily NVD Update
        console.log("Worker: Starting Daily Incremental Sync...");
        ctx.waitUntil(updateNVDIncremental(env));
        break;

      case "0 0 */2 * *": // Bi-Daily KEV Update
        console.log("Worker: Starting KEV Sync...");
        ctx.waitUntil(syncKevData(env));
        break;
    }
  }
};
