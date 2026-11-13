import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  let body: any;
  try { body = await req.json(); } catch { return reply({ error: "نام کاربری یا رمز عبور اشتباه است." }, 400); }
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!username || !password) return reply({ error: "نام کاربری یا رمز عبور اشتباه است." }, 400);

  const admin = createClient(url, service);
  const { data: profile } = await admin.from("profiles")
    .select("email,is_active").eq("username", username).maybeSingle();
  if (!profile?.email || profile.is_active === false)
    return reply({ error: "نام کاربری یا رمز عبور اشتباه است." }, 401);

  const tokenResponse = await fetch(`${url}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: anon },
    body: JSON.stringify({ email: profile.email, password }),
  });
  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok) return reply({ error: "نام کاربری یا رمز عبور اشتباه است." }, 401);
  return reply(tokenData);
});
