export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // DASHBOARD UI
    if (url.pathname === "/" && request.method === "GET" && !url.searchParams.has("make")) {
      return new Response(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>ICS Risk Dashboard</title>
          <style>
            body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #f4f7f9; }
            .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
            button { width: 100%; background: #1a73e8; color: white; padding: 12px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
            #results { margin-top: 30px; display: none; }
            .score-box { text-align: center; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .critical { background: #dc3545; color: white; }
            .safe { background: #28a745; color: white; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            td, th { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
          </style>
        </head>
        <body>
          <div class="card">
            <h2>🛡️ ICS Asset Risk Search</h2>
            <input type="text" id="make" placeholder="Make (e.g. Siemens)">
            <input type="text" id="model" placeholder="Model (e.g. S7-1500)">
            <button onclick="search()">Check Risk Level</button>
            <div id="results">
              <div id="scoreDisplay" class="score-box"></div>
              <h3>Vulnerability Details:</h3>
              <table id="cveTable"><thead><tr><th>CVE ID</th><th>Score</th></tr></thead><tbody id="cveList"></tbody></table>
            </div>
          </div>
          <script>
            async function search() {
              const make = document.getElementById('make').value;
              const model = document.getElementById('model').value;
              const res = await fetch('/api/search?make=' + make + '&model=' + model);
              const data = await res.json();
              document.getElementById('results').style.display = 'block';
              const sBox = document.getElementById('scoreDisplay');
              sBox.className = 'score-box ' + (data.max_cvss >= 7 ? 'critical' : 'safe');
              sBox.innerHTML = 'Max CVSS Score: <h1 style="margin:0">' + data.max_cvss + '</h1>';
              document.getElementById('cveList').innerHTML = data.vulnerabilities.map(v => 
                '<tr><td>' + v.cve_id + '</td><td>' + v.cvss_score + '</td></tr>').join('');
            }
          </script>
        </body>
        </html>
      `, { headers: { "Content-Type": "text/html" } });
    }

    // API SEARCH LOGIC
    if (url.pathname === "/api/search") {
      const make = url.searchParams.get("make");
      const model = url.searchParams.get("model");
      const data = await env.DB.prepare("SELECT c.cve_id, c.cvss_score FROM cves c JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id WHERE m.make LIKE ? AND m.model LIKE ? ORDER BY c.cvss_score DESC")
        .bind("%" + make.toLowerCase() + "%", "%" + model.toLowerCase() + "%").all();
      const maxScore = data.results.length > 0 ? Math.max(...data.results.map(r => r.cvss_score)) : 0;
      return Response.json({ max_cvss: maxScore, vulnerabilities: data.results });
    }

    // SYNC TRIGGER
    if (url.pathname === "/sync") {
      try {
        await this.scheduled(null, env);
        return new Response("Sync completed successfully!");
      } catch (err) {
        return new Response("Sync Failed: " + err.message, { status: 500 });
      }
    }

    return new Response("Dashboard at / | Sync at /sync");
  },

  async scheduled(event, env) {
    const countResult = await env.DB.prepare("SELECT COUNT(*) as total FROM cves").first();
    const currentRows = countResult.total || 0;
    
    // We stick to 500 rows for maximum reliability
    const nvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=500&startIndex=" + currentRows;
    
    const response = await fetch(nvdUrl, { 
      headers: { 
        "apiKey": env.NVD_API_KEY, 
        "User-Agent": "Cloudflare-Worker-ICS-PoC" 
      } 
    });

    // SAFETY CHECK: Get the raw text first to see if it's empty
    const text = await response.text();
    if (!text || text.trim().length === 0) {
      console.log("NVD returned an empty response. This happens when the server is busy.");
      return;
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.log("Failed to parse JSON. NVD may have sent an incomplete file. Retrying in 30 mins.");
      return;
    }

    const vulnerabilities = data.vulnerabilities || [];
    const statements = [];
    
    for (const item of vulnerabilities) {
      const cve = item.cve;
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 0;

      statements.push(env.DB.prepare("INSERT OR REPLACE INTO cves (cve_id, cvss_score, description) VALUES (?, ?, ?)").bind(cve.id, score, cve.descriptions[0].value));
      
      if (cve.configurations) {
        for (const config of cve.configurations) {
          for (const node of (config.nodes || [])) {
            for (const match of (node.cpeMatch || [])) {
              const p = match.criteria.split(':');
              if (p.length > 5) {
                statements.push(env.DB.prepare("INSERT INTO cve_cpe_mapping (cve_id, part, make, model, firmware, cpe_full) VALUES (?, ?, ?, ?, ?, ?)").bind(cve.id, p[2], p[3], p[4], p[5], match.criteria));
              }
            }
          }
        }
      }
    }
    
    if (statements.length > 0) {
      await env.DB.batch(statements);
      console.log(`Successfully added 500 rows. Current total: ${currentRows + vulnerabilities.length}`);
    }
  }
};
