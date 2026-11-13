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

  const url = Deno.env.get("SUPABASE_URL");
  const anon = Deno.env.get("SUPABASE_ANON_KEY");
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anon || !service) return reply({ error: "تنظیمات داخلی Supabase ناقص است." }, 500);

  const authHeader = req.headers.get("Authorization") || "";
  const caller = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
  const { data: authData, error: authError } = await caller.auth.getUser();
  if (authError || !authData.user) return reply({ error: "نشست معتبر نیست؛ لینک دعوت را دوباره باز کنید." }, 401);
  if (!authData.user.email_confirmed_at) return reply({ error: "ابتدا ایمیل حساب را از طریق لینک دعوت تأیید کنید." }, 403);

  const admin = createClient(url, service);
  const { data: profile, error: profileError } = await admin
    .from("profiles").select("id,role").eq("id", authData.user.id).single();
  if (profileError || !profile) return reply({ error: "پروفایل کاربر پیدا نشد." }, 404);
  if (profile.role !== "employee") return reply({ error: "این مسیر فقط برای فعال‌سازی حساب کارمند است." }, 403);

  const { error } = await admin.from("profiles").update({
    invitation_accepted: true,
    is_active: true,
  }).eq("id", authData.user.id);
  if (error) return reply({ error: "فعال‌سازی حساب ناموفق بود: " + error.message }, 500);

  return reply({ ok: true, message: "حساب کارمند فعال شد." });
});
