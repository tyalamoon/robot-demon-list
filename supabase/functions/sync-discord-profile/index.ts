import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigins = new Set([
  "https://robotdemonlist.com",
  "https://www.robotdemonlist.com",
]);

function response(body: unknown, status = 200, origin = "https://robotdemonlist.com") {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Content-Type": "application/json",
      "Vary": "Origin",
    },
  });
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin") || "https://robotdemonlist.com";
  if (!allowedOrigins.has(origin)) return response({ error: "Origin not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response("ok", {
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin",
    },
  });
  if (req.method !== "POST") return response({ error: "Method not allowed." }, 405, origin);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const authorization = req.headers.get("Authorization") || "";
  const token = authorization.replace(/^Bearer\s+/i, "");
  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    console.error("Missing required server environment configuration.");
    return response({ error: "Discord linking service is not configured." }, 500, origin);
  }
  if (!token) return response({ error: "Sign in to your RDL account first." }, 401, origin);

  try {
    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await authClient.auth.getUser(token);
    if (authError || !authData.user) return response({ error: "Your RDL session is invalid. Sign in again." }, 401, origin);

    const user = authData.user;
    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // The access-token user response can omit linked identities in some sessions.
    // Read the authoritative Auth user record with the service-role client before
    // deciding whether Discord is linked or clearing an existing public profile.
    const { data: adminUserData, error: adminUserError } =
      await adminClient.auth.admin.getUserById(user.id);
    if (adminUserError || !adminUserData.user) {
      console.error("Could not load Auth user for Discord sync:", adminUserError?.message || "User not found");
      return response({ error: "Could not verify your linked Discord identity. Please try again." }, 500, origin);
    }

    const identities = [
      ...(adminUserData.user.identities || []),
      ...(user.identities || []),
    ];
    const discordIdentity = identities.find(identity => identity.provider === "discord");

    if (!discordIdentity) {
      const { error } = await adminClient.from("rdl_discord_profiles").delete().eq("user_id", user.id);
      if (error) throw error;
      return response({ success: true, linked: false }, 200, origin);
    }

    const identityData = discordIdentity.identity_data || {};
    const discordId = String(identityData.sub || discordIdentity.id || "").trim();
    const username = String(identityData.username || identityData.user_name || identityData.name || identityData.full_name || "").trim();
    const globalName = String(identityData.global_name || identityData.full_name || identityData.name || "").trim();

    if (!discordId || !username || discordId.length > 100 || username.length > 100 || globalName.length > 100) {
      return response({ error: "Discord identity details were incomplete. Unlink and link Discord again." }, 400, origin);
    }

    const { error } = await adminClient.from("rdl_discord_profiles").upsert({
      user_id: user.id,
      discord_id: discordId,
      discord_username: username,
      discord_global_name: globalName || null,
      updated_at: new Date().toISOString(),
    }, { onConflict: "user_id" });
    if (error) {
      console.error("Discord profile sync failed:", error.message);
      return response({ error: "Could not save your verified Discord profile. It may already be linked to another RDL account." }, 409, origin);
    }

    return response({ success: true, linked: true, username, global_name: globalName || null }, 200, origin);
  } catch (error) {
    console.error("Discord profile sync error:", error);
    return response({ error: "Discord profile sync failed. Please try again." }, 500, origin);
  }
});
