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
  const authHeader = req.headers.get("Authorization") || "";
  const caller = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
  const { data: authData, error: authError } = await caller.auth.getUser();
  if (authError || !authData.user) return reply({ error: "ابتدا وارد حساب مدیر شوید." }, 401);

  const admin = createClient(url, service);
  const { data: manager, error: managerError } = await admin
    .from("profiles").select("role,is_active").eq("id", authData.user.id).single();
  if (managerError || manager?.role !== "manager" || manager?.is_active === false)
    return reply({ error: "این عملیات فقط برای مدیر فعال مجاز است." }, 403);

  let body: any;
  try { body = await req.json(); } catch { return reply({ error: "درخواست نامعتبر است." }, 400); }
  const targetId = String(body.user_id || "").trim();
  if (!targetId) return reply({ error: "شناسه کارمند ارسال نشده است." }, 400);
  if (targetId === authData.user.id) return reply({ error: "امکان حذف حساب خودتان وجود ندارد." }, 400);

  const { data: employee, error: employeeError } = await admin
    .from("profiles").select("id,role").eq("id", targetId).maybeSingle();
  if (employeeError) return reply({ error: employeeError.message }, 500);
  if (!employee || employee.role !== "employee")
    return reply({ error: "فقط حساب کارمند قابل اخراج است." }, 403);

  const { error: deleteError } = await admin.auth.admin.deleteUser(targetId);
  if (deleteError) return reply({ error: "حذف حساب انجام نشد: " + deleteError.message }, 500);
  return reply({ ok: true });
});
