/*
  ===========================================================
  HISTORICAL REFERENCE: OLD BULK SYNC LOGIC (DEPRECATED)
  ===========================================================
  import { fetchAndStoreNVD } from "./fetchNVD_data";
  // case "*/30 * * * *": ctx.waitUntil(fetchAndStoreNVD(env));
  ===========================================================
*/

import { updateNVDIncremental } from "./updateNVD";
import { syncKevData } from "./updateKEV";

export default {
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
      return new Response("<h1>Vulnerability Dashboard</h1><p>Active with Incremental Updates.</p>", {
        headers: { "Content-Type": "text/html" }
      });
    }

    return new Response("Not Found", { status: 404 });
  },

  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    switch (controller.cron) {
      case "0 0 * * *": // Daily NVD Update
        ctx.waitUntil(updateNVDIncremental(env));
        break;
      case "0 0 */2 * *": // Bi-Daily KEV Update
        ctx.waitUntil(syncKevData(env));
        break;
    }
  }
};
