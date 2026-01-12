async scheduled(event, env) {
    // 1. Get current count (will be 0 after your wipe)
    const countResult = await env.DB.prepare("SELECT COUNT(*) as total FROM cves").first();
    const currentRows = countResult.total || 0;
    
    console.log(`Starting sync from index: ${currentRows}`);

    // 2. Fetch 200 rows (Fast and stable)
    const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200&startIndex=${currentRows}`;
    
    const response = await fetch(nvdUrl, { 
      headers: { 
        "apiKey": env.NVD_API_KEY, 
        "User-Agent": "Cloudflare-Worker-ICS-PoC" 
      } 
    });

    if (!response.ok) {
      console.log(`NVD API Error: ${response.status}`);
      return;
    }

    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];

    if (vulnerabilities.length === 0) {
      console.log("NVD returned no data for this index range.");
      return;
    }

    // 3. Prepare Batch
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
    
    // 4. Execute and log progress
    await env.DB.batch(statements);
    console.log(`Successfully added ${vulnerabilities.length} rows. New total will be ${currentRows + vulnerabilities.length}`);
  }
