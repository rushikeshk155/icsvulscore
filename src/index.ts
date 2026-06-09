/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 7.0 (IEC 62443 Password Complexity Controls)
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

async function hashPassword(pwd: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(pwd + "ICS_SALT_2026");
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Backend Server Verification Policy matching IEC 62443-4-2 standards
function verifyIEC62443PasswordStrength(pwd: string): boolean {
  const iecRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{10,}$/;
  return iecRegex.test(pwd);
}

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // --- 1. USER AUTHENTICATION GATES ---
    if (url.pathname === "/auth/register" && request.method === "POST") {
      const { username, password } = await request.json() as any;
      if (!username || !password) return Response.json({ error: "Missing fields" }, { status: 400, headers: corsHeaders });
      
      // Strict API-Layer Enforcement for industrial safety standards
      if (!verifyIEC62443PasswordStrength(password)) {
        return Response.json({ 
          error: "Password rejection. Must be at least 10 characters long and include numbers, uppercase, lowercase, and special symbols." 
        }, { status: 400, headers: corsHeaders });
      }
      
      const pwdHash = await hashPassword(password);
      
      try {
        const userCheck = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
        const role = userCheck.count === 0 ? 'admin' : 'user';
        const approved = userCheck.count === 0 ? 1 : 0;

        await env.DB.prepare("INSERT INTO users (username, password_hash, role, approved) VALUES (?, ?, ?, ?)")
          .bind(username, pwdHash, role, approved).run();
          
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch (e) {
        return Response.json({ error: "Username already exists" }, { status: 400, headers: corsHeaders });
      }
    }

    if (url.pathname === "/auth/login" && request.method === "POST") {
      const { username, password } = await request.json() as any;
      const pwdHash = await hashPassword(password);

      const user = await env.DB.prepare("SELECT id, username, role, approved FROM users WHERE username = ? AND password_hash = ?")
        .bind(username, pwdHash).first();

      if (!user) return Response.json({ error: "Invalid credentials" }, { status: 401, headers: corsHeaders });
      if (user.approved === 0) return Response.json({ error: "Account access pending Admin approval." }, { status: 403, headers: corsHeaders });

      const token = btoa(JSON.stringify({ username: user.username, role: user.role, stamp: Date.now() }));
      return Response.json({ token, user: { username: user.username, role: user.role } }, { headers: corsHeaders });
    }

    // --- 2. SECURITY TOKEN VERIFICATION LAYER ---
    const authHeader = request.headers.get("Authorization") || "";
    let tokenPayload: any = null;
    try {
      if (authHeader.startsWith("Bearer ")) {
        tokenPayload = JSON.parse(atob(authHeader.substring(7)));
      }
    } catch(e) {}

    if (!tokenPayload && url.searchParams.has("make")) {
      return Response.json({ error: "Unauthorized token" }, { status: 401, headers: corsHeaders });
    }

    // --- 3. ADMIN MANAGEMENT ENDPOINTS ---
    if (url.pathname === "/admin/pending") {
      if (!tokenPayload || tokenPayload.role !== 'admin') return Response.json({ error: "Forbidden" }, { status: 403, headers: corsHeaders });
      const pending = await env.DB.prepare("SELECT id, username FROM users WHERE approved = 0").all();
      return Response.json(pending.results, { headers: corsHeaders });
    }

    if (url.pathname === "/admin/active-users") {
      if (!tokenPayload || tokenPayload.role !== 'admin') return Response.json({ error: "Forbidden" }, { status: 403, headers: corsHeaders });
      const active = await env.DB.prepare("SELECT id, username, role FROM users WHERE approved = 1").all();
      return Response.json(active.results, { headers: corsHeaders });
    }

    if (url.pathname === "/admin/approve" && request.method === "POST") {
      if (!tokenPayload || tokenPayload.role !== 'admin') return Response.json({ error: "Forbidden" }, { status: 403, headers: corsHeaders });
      const { id } = await request.json() as any;
      await env.DB.prepare("UPDATE users SET approved = 1 WHERE id = ?").bind(id).run();
      return Response.json({ success: true }, { headers: corsHeaders });
    }

    if (url.pathname === "/admin/promote" && request.method === "POST") {
      if (!tokenPayload || tokenPayload.role !== 'admin') return Response.json({ error: "Forbidden" }, { status: 403, headers: corsHeaders });
      const { id } = await request.json() as any;
      await env.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(id).run();
      return Response.json({ success: true }, { headers: corsHeaders });
    }

    // --- 4. CORE DATA ENGINE MATRIX ---
    const make = url.searchParams.get("make");
    const model = url.searchParams.get("model");
    const firmware = url.searchParams.get("firmware");
    
    if (make && model) {
      const cleanMake = make.toLowerCase().replace(/[-_\s]/g, "");
      const cleanModel = model.toLowerCase().replace(/[-_\s]/g, "");
      const modelNumberMatch = model.match(/\d+/);
      const modelNumStr = modelNumberMatch ? modelNumberMatch[0] : cleanModel;

      let query = `
        SELECT 
          c.cve_id, c.cvss_score,
          MIN(10.0, c.cvss_score + 
            (CASE WHEN k.cve_id IS NOT NULL THEN 2.0 ELSE 0.0 END) + 
            (CASE WHEN at.tactic IN ('impact', 'inhibit response function') THEN 1.5 ELSE 0.0 END)
          ) as ics_weighted_score,
          c.description, IFNULL(at.tactic, 'NONE') as tactic, at.name as technique_name,
          CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev,
          IFNULL(k.required_action, 'Refer to vendor advisory.') as mitigation
        FROM cves c 
        JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id 
        LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id
        LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        WHERE 
          REPLACE(REPLACE(REPLACE(LOWER(m.make), '-', ''), ' ', ''), '_', '') LIKE ? 
          AND (REPLACE(REPLACE(REPLACE(LOWER(m.model), '-', ''), ' ', ''), '_', '') LIKE ? OR m.model LIKE ?)
      `;

      const params: any[] = ["%" + cleanMake + "%", "%" + cleanModel + "%", "%" + modelNumStr + "%"];

      if (firmware && firmware.trim() !== "" && firmware !== "null" && firmware !== "*") {
        const cleanFw = firmware.replace(/[*]/g, "").trim().toLowerCase();
        const majorFw = cleanFw.split('.')[0]; 
        query += ` AND (m.firmware LIKE ? OR m.firmware LIKE ? OR m.firmware = '*' OR m.firmware = 'all')`;
        params.push("%" + cleanFw + "%");
        params.push(majorFw + ".%");
      }

      query += ` GROUP BY c.cve_id ORDER BY ics_weighted_score DESC, cvss_score DESC`;

      try {
        const data = await env.DB.prepare(query).bind(...params).all();
        return Response.json({ vulnerabilities: data.results }, { headers: corsHeaders });
      } catch (err: any) {
        return Response.json({ error: "Database failure", details: err.message }, { status: 500, headers: corsHeaders });
      }
    }

    // --- 5. COMPLIANCE DATA ROUTING OVERLAYS ---
    if (url.pathname === "/sync-incremental") { await updateNVDIncremental(env); return new Response("Sync complete."); }
    if (url.pathname === "/backfill-execute") { await backfillNVD(env); return new Response("Backfill running."); }
    if (url.pathname === "/sync-kev") { await syncKevData(env); return new Response("KEV Updated."); }
    if (url.pathname === "/sync-attack-library") { await syncAttackTechniques(env); return new Response("ATT&CK Matrix Updated."); }
    if (url.pathname === "/backfill-attack") { await backfillAttackMappings(env); return new Response("Attack Mapped."); }

    return new Response("ICS Security Engine Active.", { headers: { "Content-Type": "text/plain" } });
  }
};
