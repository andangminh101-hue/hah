const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8"
};
const json = (body, status=200) => new Response(JSON.stringify(body), {status, headers:corsHeaders});
const keyId = key => "KEY:" + String(key || "").trim().toUpperCase();
function authorized(req, env) {
  const got = req.headers.get("Authorization") || "";
  return !!env.ADMIN_TOKEN && got === `Bearer ${env.ADMIN_TOKEN}`;
}
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, {headers:corsHeaders});
    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET") return json({ok:true, service:"MINH AN MOD KEY API"});
    if (url.pathname === "/verify" && request.method === "POST") {
      let body; try { body = await request.json(); } catch { return json({ok:false,message:"Dữ liệu không hợp lệ."},400); }
      const key = String(body.key || "").trim().toUpperCase();
      const deviceId = String(body.deviceId || "").trim();
      if (!key || !deviceId || deviceId.length > 200) return json({ok:false,message:"Thiếu KEY hoặc mã thiết bị."},400);
      const raw = await env.KEYS.get(keyId(key));
      if (!raw) return json({ok:false,message:"KEY không tồn tại."},401);
      const record = JSON.parse(raw);
      if (record.revoked) return json({ok:false,message:"KEY đã bị thu hồi."},401);
      if (record.expiresAt && Date.now() > record.expiresAt) return json({ok:false,message:"KEY đã hết hạn."},401);
      if (record.deviceId && record.deviceId !== deviceId) return json({ok:false,message:"KEY đã được kích hoạt trên thiết bị khác."},401);
      if (!record.deviceId) { record.deviceId = deviceId; record.activatedAt = Date.now(); await env.KEYS.put(keyId(key), JSON.stringify(record)); }
      return json({ok:true,message:"Xác thực thành công",expiresAt:record.expiresAt || null});
    }
    if (url.pathname.startsWith("/admin/") && !authorized(request, env)) return json({ok:false,message:"Không có quyền quản trị."},401);
    if (url.pathname === "/admin/create" && request.method === "POST") {
      let body; try { body = await request.json(); } catch { return json({ok:false,message:"Dữ liệu không hợp lệ."},400); }
      const days = Number(body.days);
      if (!Number.isInteger(days) || days < 1 || days > 3650) return json({ok:false,message:"Số ngày phải từ 1 đến 3650."},400);
      const label = String(body.label || "").slice(0,80);
      let key;
      do { key = "MA-" + crypto.randomUUID().replaceAll("-", "").slice(0,20).toUpperCase(); } while (await env.KEYS.get(keyId(key)));
      const now = Date.now();
      const record = {key, label, createdAt:now, expiresAt:now+days*86400000, revoked:false, deviceId:null, activatedAt:null};
      await env.KEYS.put(keyId(key), JSON.stringify(record));
      return json({ok:true,key,record});
    }
    if (url.pathname === "/admin/list" && request.method === "GET") {
      let cursor, items=[];
      do {
        const page = await env.KEYS.list({prefix:"KEY:", cursor, limit:1000});
        for (const k of page.keys) { const raw=await env.KEYS.get(k.name); if(raw) items.push(JSON.parse(raw)); }
        cursor=page.list_complete ? undefined : page.cursor;
      } while(cursor);
      items.sort((a,b)=>b.createdAt-a.createdAt);
      return json({ok:true,items});
    }
    if (url.pathname === "/admin/revoke" && request.method === "POST") {
      let body; try { body = await request.json(); } catch { return json({ok:false,message:"Dữ liệu không hợp lệ."},400); }
      const key=String(body.key||"").trim().toUpperCase();
      const raw=await env.KEYS.get(keyId(key)); if(!raw) return json({ok:false,message:"Không tìm thấy KEY."},404);
      const record=JSON.parse(raw); record.revoked=true; record.revokedAt=Date.now(); await env.KEYS.put(keyId(key),JSON.stringify(record));
      return json({ok:true,message:"Đã thu hồi KEY."});
    }
    return json({ok:false,message:"Không tìm thấy endpoint."},404);
  }
};
