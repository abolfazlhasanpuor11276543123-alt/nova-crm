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
  let stage = "startup";
  try {

  stage = "read_environment";
  const url = Deno.env.get("SUPABASE_URL");
  const anon = Deno.env.get("SUPABASE_ANON_KEY");
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const activationUrl = Deno.env.get("NOVA_ACTIVATION_URL");
  if (!url || !anon || !service) return reply({ error: "تنظیمات داخلی Supabase ناقص است.", stage }, 500);
  if (!activationUrl) return reply({ error: "NOVA_ACTIVATION_URL تنظیم نشده است.", stage }, 500);
  try {
    const parsedActivationUrl = new URL(activationUrl);
    if (parsedActivationUrl.protocol !== "https:") return reply({ error: "NOVA_ACTIVATION_URL باید آدرس HTTPS باشد.", stage }, 500);
  } catch {
    return reply({ error: "مقدار NOVA_ACTIVATION_URL یک آدرس معتبر نیست.", stage }, 500);
  }

  stage = "authenticate_manager";
  const authHeader = req.headers.get("Authorization") || "";
  const caller = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
  const { data: authData, error: authError } = await caller.auth.getUser();
  if (authError || !authData.user) return reply({ error: "ابتدا وارد حساب مدیر شوید." }, 401);

  stage = "check_manager_profile";
  const admin = createClient(url, service);
  const { data: profile, error: profileError } = await admin
    .from("profiles").select("role,is_active").eq("id", authData.user.id).single();
  if (profileError || profile?.role !== "manager" || profile?.is_active === false)
    return reply({ error: "این عملیات فقط برای مدیر فعال مجاز است." }, 403);

  stage = "validate_request";
  let body: any;
  try { body = await req.json(); } catch { return reply({ error: "درخواست نامعتبر است." }, 400); }
  const full_name = String(body.full_name || "").trim();
  const username = String(body.username || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  const phone = String(body.phone || "").trim();
  if (!full_name || !email || !/^[a-z0-9._-]{3,30}$/.test(username))
    return reply({ error: "نام، ایمیل و نام کاربری معتبر (۳ تا ۳۰ حرف انگلیسی/عدد/._-) الزامی است." }, 400);

  stage = "check_duplicate_username";
  const { data: duplicate } = await admin.from("profiles").select("id").eq("username", username).maybeSingle();
  if (duplicate) return reply({ error: "این نام کاربری قبلاً استفاده شده است." }, 409);

  // Supabase Auth sends the invitation through the project's configured SMTP.
  // Do not generate a custom link or call an external mailer here.
  stage = "send_invitation_via_supabase_auth_smtp";
  const { data: invited, error: inviteError } = await admin.auth.admin.inviteUserByEmail(email, {
    redirectTo: activationUrl,
    data: { full_name, username },
  });
  if (inviteError || !invited?.user?.id) {
    const detail = inviteError?.message || "شناسه کاربر دریافت نشد";
    console.error("NOVA_INVITATION_SEND_ERROR", { stage, detail });
    return reply({ error: "ارسال دعوت‌نامه از طریق SMTP سوپابیس ناموفق بود: " + detail, stage }, 502);
  }

  const userId = invited.user.id;
  stage = "save_employee_profile";
  const { error: saveError } = await admin.from("profiles").upsert({
    id: userId, email, full_name, username, phone, role: "employee", is_active: false, invitation_accepted: false,
  }, { onConflict: "id" });
  if (saveError) {
    // Keep the Auth user intact; never delete/recreate an account as an email failure workaround.
    console.error("NOVA_PROFILE_SAVE_ERROR", saveError.message, "user_id", userId);
    return reply({ ok: false, user_created: true, user_id: userId, username,
      error: "دعوت‌نامه ارسال شد و حساب Auth ساخته شد، اما ذخیره پروفایل ناموفق بود: " + saveError.message, stage }, 500);
  }

  return reply({ ok: true, user_id: userId, username, email_sent: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("NOVA_ADMIN_CREATE_USER_UNHANDLED", { stage, message });
    return reply({ error: "خطای پیش‌بینی‌نشده هنگام ثبت کارمند.", stage, detail: message }, 500);
  }
});
