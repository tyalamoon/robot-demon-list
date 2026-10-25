import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://robotdemonlist.com",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (origin && origin !== "https://robotdemonlist.com" && origin !== "https://www.robotdemonlist.com") {
    return json({ error: "Origin not allowed." }, 403);
  }

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: { ...corsHeaders, "Access-Control-Allow-Origin": origin || "https://robotdemonlist.com" } });
  }
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const secret = Deno.env.get("RECAPTCHA_SECRET_KEY");
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!secret || !supabaseUrl || !anonKey) {
    console.error("Missing required server environment configuration.");
    return json({ error: "Submission service is not configured." }, 500);
  }

  let body: { captchaToken?: unknown; submission?: Record<string, unknown> };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  const captchaToken = typeof body.captchaToken === "string" ? body.captchaToken : "";
  const submission = body.submission;
  if (!captchaToken || captchaToken.length > 10000 || !submission || typeof submission !== "object") {
    return json({ error: "Complete the CAPTCHA and submission fields." }, 400);
  }

  try {
    const verifyBody = new URLSearchParams({ secret, response: captchaToken });
    const verifyResponse = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: verifyBody,
    });
    if (!verifyResponse.ok) return json({ error: "CAPTCHA verification is temporarily unavailable." }, 502);
    const verification = await verifyResponse.json();
    if (!verification.success || (verification.hostname && !["robotdemonlist.com", "www.robotdemonlist.com"].includes(verification.hostname))) {
      return json({ error: "CAPTCHA verification failed. Please try again." }, 400);
    }

    const playerName = typeof submission.player_name === "string" ? submission.player_name.trim() : "";
    const levelName = typeof submission.level_name === "string" ? submission.level_name.trim() : "";
    const percent = submission.percent;
    const proofUrl = typeof submission.proof_url === "string" ? submission.proof_url.trim() : "";
    const notes = typeof submission.notes === "string" ? submission.notes : "";

    let parsedProof: URL | null = null;
    try { parsedProof = new URL(proofUrl); } catch { /* invalid URL */ }
    if (!playerName || playerName.length > 40 || !levelName || levelName.length > 100 ||
        !Number.isInteger(percent) || Number(percent) < 0 || Number(percent) > 100 ||
        !parsedProof || !["http:", "https:"].includes(parsedProof.protocol) ||
        proofUrl.length > 2048 || notes.length > 4000) {
      return json({ error: "One or more submission fields are invalid." }, 400);
    }

    const authorization = req.headers.get("Authorization");
    const db = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: authorization ? { headers: { Authorization: authorization } } : undefined,
    });
    const { error } = await db.from("record_submissions").insert({
      player_name: playerName,
      level_name: levelName,
      percent: Number(percent),
      proof_url: proofUrl,
      notes,
      status: "pending",
    });

    if (error) {
      console.error("Record submission insert failed:", error.message);
      return json({ error: "The record could not be saved. Please try again." }, 400);
    }
    return json({ success: true });
  } catch (error) {
    console.error("Record submission function error:", error);
    return json({ error: "Submission failed unexpectedly. Please try again." }, 500);
  }
});
