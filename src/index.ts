/**
 * ICS Vuln Score - Main Worker Handler
 * Version: 9.0 (True Out-of-Band Email Delivery Loop)
 */

import { updateNVDIncremental } from "./updateNVD";
import { backfillNVD } from "./backfillNVD";
import { syncKevData } from "./updateKEV";
import { syncAttackTechniques } from "./syncAttack";
import { backfillAttackMappings } from "./backfillAttackMappings";

const SECRET_CRYPTO_KEY = "IEC_62443_SIGNING_BLOCK";
const RESEND_API_KEY = "re_YourFreeApiKeyHere_123456789"; // Replace with your actual free Resend key

async function hashPassword(pwd: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(pwd + "ICS_SALT_2026");
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function verifyIEC62443PasswordStrength(pwd: string): boolean {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{10,}$/.test(pwd);
}

// Out-of-Band Automated Mailing Dispatcher Function
async function sendVerificationEmail(targetEmail: string, username: string, link: string) {
  const emailPayload = {
    from: "ICS Security Portal <onboarding@resend.dev>", // Resend provides this default sandbox domain for free testing
    to: [targetEmail],
    subject: "CRITICAL: Verify Your ICS Auditor Access Request",
    html: `
      <div style="font-family:sans-serif; padding:24px; background-color:#0b1120; color:#f1f5f9; border-radius:16px; max-width:500px; margin:0 auto;">
        <h2 style="color:#3b82f6; margin-bottom:4px; font-style:italic; text-transform:uppercase;">ICS Portal Verification</h2>
        <p style="font-size:11px; color:#64748b; font-family:monospace; text-transform:uppercase; margin-top:0;">IEC 62443 Access Controls</p>
        <hr style="border:0; border-top:1px solid #1e293b; margin:20px 0;" />
        <p style="font-size:14px; line-height:1.6;">Hello <strong>${username}</strong>,</p>
        <p style="font-size:14px; line-height:1.6;">An account request has been initiated using this corporate email identity. To prove ownership of this email asset, click the activation link below within the next 15 minutes:</p>
        <div style="text-align:center; margin:32px 0;">
          <a href="${link}" style="background-color:#2563eb; color:#ffffff; font-weight:bold; padding:12px 32px; border-radius:8px; text-decoration:none; font-size:13px; display:inline-block; text-transform:uppercase; tracking-wider:0.05em;">Verify Email Address</a>
        </div>
        <p style="font-size:11px; color:#64748b; font-family:monospace; text-align:center; margin-top:32px;">If you did not request this access, please ignore this communication or flag it to network security operators.</p>
      </div>
    `
  };

  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(emailPayload)
  });
}

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    // --- 1. EMAIL VERIFICATION CAPTURE ---
    if (url.pathname === "/auth/verify") {
      const rawToken = url.searchParams.get("token");
      if(!rawToken) return new Response("Missing activation token.", { status: 400 });
      
      try {
        const token = decodeURIComponent(rawToken);
        const decoded = JSON.parse(atob(token));
        if(decoded.secret !== SECRET_CRYPTO_KEY) throw new Error("Invalid signature.");

        const fifteenMinutesInMs = 15 * 60 * 1000;
        if (Date.now() - decoded.stamp > fifteenMinutesInMs) {
          await env.DB.prepare("DELETE FROM users WHERE username = ? AND email_verified = 0").bind(decoded.username).run();
          return new Response("<html><body style='font-family:sans-serif; background:#0b1120; color:#ef4444; text-align:center; padding-top:100px;'><h2>✕ Verification Link Expired</h2><p style='color:#94a3b8;'>The 15-minute lease time ended. Re-register.</p></body></html>", { status: 400, headers: { "Content-Type": "text/html" } });
        }

        await env.DB.prepare("UPDATE users SET email_verified = 1 WHERE username = ?").bind(decoded.username).run();
        return new Response("<html><body style='font-family:sans-serif; background:#0b1120; color:#34d399; text-align:center; padding-top:100px;'><h2>✓ Email Verified Successfully</h2><p style='color:#94a3b8;'>Your identity request is now in the Admin Approval Queue.</p></body></html>", { headers: { "Content-Type": "text/html" } });
      } catch(e) {
        return new Response("Token verification error.", { status: 400 });
      }
    }

    // --- 2. REGISTRATION PIPELINE (WITH HIDDEN DELIVERY) ---
    if (url.pathname === "/auth/register" && request.method === "POST") {
      const { username, password, email } = await request.json() as any;
      if (!username || !password || !email) return Response.json({ error: "Missing fields" }, { status: 400, headers: corsHeaders });
      if (!verifyIEC62443PasswordStrength(password)) return Response.json({ error: "Weak password." }, { status: 400, headers: corsHeaders });
      
      const pwdHash = await hashPassword(password);
      
      try {
        const userCheck = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
        const isFirstUser = userCheck.count === 0;
        
        const role = isFirstUser ? 'admin' : 'user';
        const approved = isFirstUser ? 1 : 0;
        const emailVerified = isFirstUser ? 1 : 0;

        await env.DB.prepare("INSERT INTO users (username, password_hash, email, role, approved, email_verified) VALUES (?, ?, ?, ?, ?, ?)")
          .bind(username, pwdHash, email, role, approved, emailVerified).run();
          
        const activationToken = btoa(JSON.stringify({ username, secret: SECRET_CRYPTO_KEY, stamp: Date.now() }));
        const activationLink = `${url.origin}/auth/verify?token=${encodeURIComponent(activationToken)}`;

        // If it's a secondary user/operator, fire the external API out-of-band email quietly!
        if (!isFirstUser) {
          ctx.waitUntil(sendVerificationEmail(email, username, activationLink));
        }

        return Response.json({ success: true }, { headers: corsHeaders });
      } catch (e) {
        return Response.json({ error: "Username or Email already registered." }, { status: 400, headers: corsHeaders });
      }
    }

    if (url.pathname === "/auth/login" && request.method === "POST") {
      const { username, password } = await request.json() as any;
      const pwdHash = await hashPassword(password);

      const user = await env.DB.prepare("SELECT username, role, approved, email_verified FROM users WHERE username = ? AND password_hash = ?")
        .bind(username, pwdHash).first();

      if (!user) return Response.json({ error: "Invalid credentials" }, { status: 401, headers: corsHeaders });
      if (user.email_verified === 0) return Response.json({ error: "Access Denied. Check your mail inbox to verify ownership first." }, { status: 403, headers: corsHeaders });
      if (user.approved === 0) return Response.json({ error: "Email verified! Awaiting Admin approval." }, { status: 403, headers: corsHeaders });

      const token = btoa(JSON.stringify({ username: user.username, role: user.role, stamp: Date.now() }));
      return Response.json({ token, user: { username: user.username, role: user.role } }, { headers: corsHeaders });
    }

    // --- 3. IDENTITY CONTROL VERIFIER ---
    const authHeader = request.headers.get("Authorization") || ""; let tokenPayload: any = null;
    try { if (authHeader.startsWith("Bearer ")) tokenPayload = JSON.parse(atob(authHeader.substring(7))); } catch(e) {}
    if (!tokenPayload && url.searchParams.has("make")) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });

    // --- 4. EXCLUSIVE ADMINISTRATIVE CONTROL ROUTING ---
    if (url.pathname === "/admin/pending") {
      if (!tokenPayload || tokenPayload.role !== 'admin') return Response.json({ error: "Forbidden" }, { status: 403, headers: corsHeaders });
      const pending = await env.DB.prepare("SELECT id, username, email FROM users WHERE approved = 0 AND email_verified = 1").all();
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

    // --- 5. SEARCH ENGINE ROUTING ---
    const make = url.searchParams.get("make"); const model = url.searchParams.get("model"); const firmware = url.searchParams.get("firmware");
    if (make && model) {
      const cleanMake = make.toLowerCase().replace(/[-_\s]/g, ""); const cleanModel = model.toLowerCase().replace(/[-_\s]/g, "");
      const modelNumStr = model.match(/\d+/)?.[0] || cleanModel;
      let query = `SELECT c.cve_id, c.cvss_score, MIN(10.0, c.cvss_score + (CASE WHEN k.cve_id IS NOT NULL THEN 2.0 ELSE 0.0 END) + (CASE WHEN at.tactic IN ('impact', 'inhibit response function') THEN 1.5 ELSE 0.0 END)) as ics_weighted_score, c.description, IFNULL(at.tactic, 'NONE') as tactic FROM cves c JOIN cve_cpe_mapping m ON c.cve_id = m.cve_id LEFT JOIN cve_attack_mapping cam ON c.cve_id = cam.cve_id LEFT JOIN attack_techniques at ON cam.technique_id = at.technique_id LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id WHERE REPLACE(REPLACE(REPLACE(LOWER(m.make), '-', ''), ' ', ''), '_', '') LIKE ? AND (REPLACE(REPLACE(REPLACE(LOWER(m.model), '-', ''), ' ', ''), '_', '') LIKE ? OR m.model LIKE ?)`;
      const params: any[] = ["%" + cleanMake + "%", "%" + cleanModel + "%", "%" + modelNumStr + "%"];
      if (firmware && firmware.trim() !== "" && firmware !== "null" && firmware !== "*") {
        const cleanFw = firmware.replace(/[*]/g, "").trim().toLowerCase(); const majorFw = cleanFw.split('.')[0];
        query += ` AND (m.firmware LIKE ? OR m.firmware LIKE ? OR m.firmware = '*' OR m.firmware = 'all')`;
        params.push("%" + cleanFw + "%"); params.push(majorFw + ".%");
      }
      query += ` GROUP BY c.cve_id ORDER BY ics_weighted_score DESC, cvss_score DESC`;
      try { return Response.json({ vulnerabilities: (await env.DB.prepare(query).bind(...params).all()).results }, { headers: corsHeaders }); } 
      catch (err: any) { return Response.json({ error: "Database failure" }, { status: 500, headers: corsHeaders }); }
    }

    // --- 6. SYNC OVERLAYS ---
    if (url.pathname === "/sync-incremental") { await updateNVDIncremental(env); return new Response("Done."); }
    if (url.pathname === "/backfill-execute") { await backfillNVD(env); return new Response("Running."); }
    if (url.pathname === "/sync-kev") { await syncKevData(env); return new Response("Updated KEV."); }
    if (url.pathname === "/sync-attack-library") { await syncAttackTechniques(env); return new Response("Updated MITRE."); }
    if (url.pathname === "/backfill-attack") { await backfillAttackMappings(env); return new Response("Mapped."); }

    return new Response("ICS API Secure Gate.", { headers: { "Content-Type": "text/plain" } });
  }
};
