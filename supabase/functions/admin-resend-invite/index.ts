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
  const mailAuth = createClient(url, anon);
  const { data: authData, error: authError } = await caller.auth.getUser();
  if (authError || !authData.user) return reply({ error: "ابتدا وارد حساب مدیر شوید." }, 401);

  stage = "check_manager_profile";
  const admin = createClient(url, service);
  const { data: manager, error: managerError } = await admin
    .from("profiles").select("role,is_active").eq("id", authData.user.id).single();
  if (managerError || manager?.role !== "manager" || manager?.is_active === false)
    return reply({ error: "این عملیات فقط برای مدیر فعال مجاز است." }, 403);

  stage = "validate_request";
  let body: any;
  try { body = await req.json(); } catch { return reply({ error: "درخواست نامعتبر است." }, 400); }
  const userId = String(body.user_id || "").trim();
  if (!userId) return reply({ error: "شناسه کارمند ارسال نشده است." }, 400);

  stage = "load_employee_profile";
  const { data: profile, error: profileError } = await admin
    .from("profiles").select("id,role,full_name,username,email").eq("id", userId).single();
  if (profileError || !profile) return reply({ error: "کارمند موردنظر پیدا نشد." }, 404);
  if (profile.role !== "employee" || profile.id === authData.user.id)
    return reply({ error: "ارسال لینک فقط برای حساب کارمند مجاز است." }, 403);

  stage = "load_auth_user";
  const { data: target, error: targetError } = await admin.auth.admin.getUserById(userId);
  if (targetError || !target.user) return reply({ error: "حساب کاربری در سامانه احراز هویت پیدا نشد." }, 404);
  const email = target.user.email || profile.email;
  if (!email) return reply({ error: "برای این کارمند ایمیل ثبت نشده است." }, 400);

  const accepted = !!target.user.email_confirmed_at;
  if (!accepted) {
    stage = "resend_activation_email_via_supabase_auth";
    // Invited users are unconfirmed Auth users. Resend the signup confirmation
    // through Supabase Auth/SMTP; the existing account and profile remain untouched.
    const { error } = await mailAuth.auth.resend({
      type: "signup",
      email,
      options: { emailRedirectTo: activationUrl },
    });
    if (error) { console.error("NOVA_RESEND_ACTIVATION_ERROR", { stage, detail: error.message }); return reply({ error: "ارسال مجدد ایمیل تأیید از طریق SMTP سوپابیس ناموفق بود: " + error.message, stage }, 502); }
    return reply({ ok: true, user_id: userId, email, mode: "activation" });
  }

  // Active employees receive a password-recovery email, not a new invitation.
  // The existing activation page accepts the resulting session and lets them set a new password.
  stage = "send_password_recovery_via_supabase_auth";
  const { error: recoveryError } = await mailAuth.auth.resetPasswordForEmail(email, {
    redirectTo: activationUrl,
  });
  if (recoveryError)
    return reply({ error: "ارسال لینک بازیابی رمز از طریق SMTP سوپابیس ناموفق بود: " + recoveryError.message, stage }, 502);

  return reply({ ok: true, user_id: userId, email, mode: "recovery" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("NOVA_ADMIN_RESEND_INVITE_UNHANDLED", { stage, message });
    return reply({ error: "خطای پیش‌بینی‌نشده هنگام ارسال مجدد ایمیل.", stage, detail: message }, 500);
  }
});
