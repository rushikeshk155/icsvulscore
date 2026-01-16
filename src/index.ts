// src/index.ts
import { fetchAndStoreNVD } from "./fetchNVD_data";
import { syncKevData } from "./updateKEV";

export default {
  // 1. DASHBOARD & API
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Dashboard UI logic... (your existing HTML code here)
    if (url.pathname === "/" && request.method === "GET" && !url.searchParams.has("make")) {
        // ... (return HTML Dashboard)
    }

    // Search API...
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    if (make && model) {
      const data = await env.DB.prepare(`
        SELECT c.cve_id, c.cvss_score 
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        WHERE m.make LIKE ? AND m.model LIKE ? 
        ORDER BY c.cvss_score DESC
      `).bind("%" + make.toLowerCase() + "%", "%" + model.toLowerCase() + "%").all();
      
      const maxScore = data.results.length > 0 ? Math.max(...data.results.map((r:any) => r.cvss_score)) : 0;
      return Response.json({ max_cvss: maxScore, vulnerabilities: data.results });
    }

    // Manual Trigger for testing
    if (url.pathname === "/sync-kev") {
       ctx.waitUntil(syncKevData(env));
       return new Response("KEV Sync triggered in background.");
    }

    return new Response("Dashboard at /");
  },

  // 2. CRON TRIGGERS
  async scheduled(controller: ScheduledController, env: any, ctx: ExecutionContext) {
    switch (controller.cron) {
      case "*/30 * * * *": // Every 30 mins
        ctx.waitUntil(fetchAndStoreNVD(env));
        break;

      case "0 0 */2 * *": // Every 2 days
        ctx.waitUntil(syncKevData(env));
        break;
    }
  }
};
