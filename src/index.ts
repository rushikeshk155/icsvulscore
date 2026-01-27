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
   * Powers the Dashboard UI and the Search API.
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

    // --- MANUAL TRIGGERS (For Testing) ---
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
      return new Response(`
        <html>
          <body style="font-family: sans-serif; padding: 20px;">
            <h1>Vulnerability Dashboard</h1>
            <p>Status: Active and Monitoring</p>
            <p>Search using: <code>/?make=vendor&model=product</code></p>
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
   * Automatically triggered by Cloudflare's edge scheduler.
   */
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    switch (controller.cron) {
      case "0 0 * * *": // Matches Daily Trigger
        console.log("Cron Trigger: Starting Daily Incremental NVD Sync...");
        ctx.waitUntil(updateNVDIncremental(env));
        break;

      case "0 0 */2 * *": // Matches Bi-Daily Trigger
        console.log("Cron Trigger: Starting KEV Sync...");
        ctx.waitUntil(syncKevData(env));
        break;
      
      default:
        console.log(`Cron Trigger: No action defined for schedule: ${controller.cron}`);
    }
  }
};
