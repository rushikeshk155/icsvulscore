export default {
  /**
   * Handler 1: The Fetch Handler (Dashboard & Search API)
   * This serves the UI and handles the browser requests.
   */
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. SERVE THE DASHBOARD (Main Page)
    if (url.pathname === "/" && request.method === "GET" && !url.searchParams.has("make")) {
      return new Response(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>ICS Vulnerability Dashboard</title>
          <style>
            body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: #f4f7f9; margin: 0; padding: 20px; color: #2c3e50; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
            h2 { color: #1a73e8; margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 15px; }
            .search-section { display: flex; gap: 15px; margin-bottom: 30px; background: #eef2f7; padding: 25px; border-radius: 10px; }
            input { flex: 1; padding: 12px 15px; border: 1px solid #cbd5e0; border-radius: 8px; font-size: 16px; outline: none; }
            input:focus { border-color: #1a73e8; box-shadow: 0 0 0 3px rgba(26,115,232,0.2); }
            button { padding: 12px 28px; background-color: #1a73e8; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
            button:hover { background-color: #1557b0; transform: translateY(-1px); }
            #results { display: none; animation: fadeIn 0.4s ease-out; }
            .score-banner { text-align: center; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
            .critical { background-color: #fff5f5; border: 2px solid #feb2b2; color: #c53030; }
            .medium { background-color: #fffaf0; border: 2px solid #fbd38d; color: #9c4221; }
            .low { background-color: #f0fff4; border: 2px solid #9ae6b4; color: #22543d; }
            .score-num { font-size: 64px; font-weight: 800; margin: 5px 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; border-radius: 8px; overflow: hidden; }
            th { text-align: left; background: #f8fafc; padding: 15px; border-bottom: 2px solid #edf2f7; color: #4a5568; }
            td { padding: 15px; border-bottom: 1px solid #f1f5f9; font-size: 14px; vertical-align: top; }
            .cve-pill { display: inline-block; padding: 4px 10px; background: #ebf8ff; color: #2b6cb0; border-radius: 5px; font-weight: bold; text-decoration: none; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>🛡️ ICS Vulnerability Tracker</h2>
            <div class="search-section">
              <input type="text" id="make" placeholder="Vendor (e.g., Siemens)">
              <input type="text" id="model" placeholder="Model (e.g., S7-1500)">
              <button onclick="runSearch()">Search Asset</button>
            </div>

            <div id="results">
              <div id="scoreBox" class="score-banner">
                <div id="scoreLabel" style="text-transform: uppercase; letter-spacing: 1px; font-weight: bold;">Max CVSS Score</div>
                <div id="scoreVal" class="score-num">0.0</div>
                <div id="assetName" style="font-size: 18px; opacity: 0.8;"></div>
              </div>
              <h3>Vulnerabilities Found</h3>
              <table id="cveTable">
                <thead>
                  <tr>
                    <th style="width: 150px;">CVE ID</th>
                    <th>Vulnerability Description</th>
                  </tr>
                </thead>
                <tbody id="cveBody"></tbody>
              </table>
            </div>
          </div>

          <script>
            async function runSearch() {
              const make = document.getElementById('make').value;
              const model = document.getElementById('model').value;
              if(!make || !model) return alert('Enter both Vendor and Model');

              const res = await fetch(\`?make=\${make}&model=\${model}\`);
              const data = await res.json();

              const resArea = document.getElementById('results');
              const sBox = document.getElementById('scoreBox');
              const sVal = document.getElementById('scoreVal');
              const list = document.getElementById('cveBody');
              
              resArea.style.display = 'block';
              sVal.innerText = data.max_cvss;
              document.getElementById('assetName').innerText = \`Analysis for \${make.toUpperCase()} \${model.toUpperCase()}\`;

              // Apply Risk Color
              sBox.className = 'score-banner ' + 
                (data.max_cvss >= 7 ? 'critical' : data.max_cvss >= 4 ? 'medium' : 'low');

              // Populate Table
              list.innerHTML = data.vulnerabilities.length > 0 
                ? data.vulnerabilities.map(v => \`
                  <tr>
                    <td><a class="cve-pill" href="https://nvd.nist.gov/vuln/detail/\${v.cve_id}" target="_blank">\${v.cve_id}</a></td>
                    <td>\${v.description}</td>
                  </tr>
                \`).join('')
                : '<tr><td colspan="2" style="text-align:center; padding: 40px;">No vulnerabilities found for this asset.</td></tr>';
            }
          </script>
        </body>
        </html>
      `, { headers: { "Content-Type": "text/html" } });
    }

    // 2. MANUAL SYNC TRIGGER (/sync)
    if (url.pathname === "/sync") {
      try {
        await this.scheduled(null, env);
        return new Response("Sync process completed! Check your D1 dashboard.");
      } catch (err) {
        return new Response("Sync Failed: " + err.message, { status: 500 });
      }
    }

    // 3. API SEARCH LOGIC
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");

    if (make && model) {
      // Find all CVEs matching the Make/Model
      const data = await env.DB.prepare(\`
        SELECT c.cve_id, c.cvss_score, c.description
        FROM cves c
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id
        WHERE m.make LIKE ? AND m.model LIKE ?
        ORDER BY c.cvss_score DESC
      \`).bind(\`%\${make.toLowerCase()}%\`, \`%\${model.toLowerCase()}%\`).all();

      const maxScore = data.results.length > 0 ? Math.max(...data.results.map(r => r.cvss_score)) : 0;

      return new Response(JSON.stringify({
        query: { make, model },
        max_cvss: maxScore,
        vulnerabilities: data.results
      }), { headers: { "Content-Type": "application/json" } });
    }

    return new Response("Worker Active. Visit main URL for Dashboard.");
  },

  /**
   * Handler 2: The Scheduled Handler (Background Sync)
   * This logic runs automatically via Cron or manually via /sync.
   */
  async scheduled(event, env) {
    // 1. Determine current progress to avoid re-downloading
    const countResult = await env.DB.prepare("SELECT COUNT(*) as total FROM cves").first();
    const currentRows = countResult.total || 0;

    // 2. Fetch the NEXT 2,000 records from NVD using startIndex
    const nvdUrl = \`https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex=\${currentRows}\`;
    
    const response = await fetch(nvdUrl, {
      headers: { 
        "apiKey": env.NVD_API_KEY,
        "User-Agent": "Cloudflare-Worker-ICS-PoC" 
      }
    });

    if (!response.ok) throw new Error("NVD API Error: " + response.status);
    
    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];

    // 3. Batch insert for high performance
    const statements = [];
    
    for (const item of vulnerabilities) {
      const cve = item.cve;
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 0;

      // Statement for the main CVE table
      statements.push(
        env.DB.prepare(\`INSERT OR REPLACE INTO cves (cve_id, cvss_score, description) VALUES (?, ?, ?)\`)
           .bind(cve.id, score, cve.descriptions[0].value)
      );

      // Statements for the Make/Model/Firmware mapping table
      if (cve.configurations) {
        for (const config of cve.configurations) {
          for (const node of (config.nodes || [])) {
            for (const match of (node.cpeMatch || [])) {
              const p = match.criteria.split(':');
              if (p.length > 5) {
                statements.push(
                  env.DB.prepare(\`INSERT INTO cve_cpe_mapping (cve_id, part, make, model, firmware, cpe_full) VALUES (?, ?, ?, ?, ?, ?)\`)
                    .bind(cve.id, p[2], p[3], p[4], p[5], match.criteria)
                );
              }
            }
          }
        }
      }
    }
    
    // Execute all statements in one high-speed database transaction
    if (statements.length > 0) {
      await env.DB.batch(statements);
    }
  }
};
