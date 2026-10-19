const COOKIE = "book_session";

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function cookieOptions(value, maxAge = 43200) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function getRole(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(/(?:^|;\s*)book_session=([^;]+)/);
  if (!match) return null;

  const token = decodeURIComponent(match[1]);
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [role, expires, signature] = parts;
  if (!["owner", "viewer"].includes(role)) return null;
  if (Number(expires) < Date.now()) return null;

  const expected = await sign(
    `${role}.${expires}`,
    env.SESSION_SECRET || ""
  );

  return signature === expected ? role : null;
}

async function createSession(role, env) {
  const expires = String(Date.now() + 12 * 60 * 60 * 1000);
  const signature = await sign(
    `${role}.${expires}`,
    env.SESSION_SECRET || ""
  );
  return `${role}.${expires}.${signature}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      if (!env.BOOK_DATA || !env.SESSION_SECRET || !env.BOOK_PASSWORD) {
        return json({
          error: "إعدادات الخادم غير مكتملة. يرجى ضبط أسرار المشروع في Cloudflare."
        }, 503);
      }

      if (request.method === "POST" && url.pathname === "/api/login") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ error: "البيانات غير صحيحة." }, 400);
        }

        let role = null;

        if (body.password === env.BOOK_PASSWORD) {
          role = "owner";
        } else if (
          env.BOOK_VIEW_PASSWORD &&
          body.password === env.BOOK_VIEW_PASSWORD
        ) {
          role = "viewer";
        }

        if (!role) {
          return json({ error: "كلمة المرور غير صحيحة." }, 401);
        }

        const token = await createSession(role, env);

        await env.BOOK_DATA.put(
          `visit:${Date.now()}:${crypto.randomUUID()}`,
          JSON.stringify({ at: new Date().toISOString(), role })
        );

        return json(
          { ok: true, role },
          200,
          { "Set-Cookie": cookieOptions(token) }
        );
      }

      if (request.method === "POST" && url.pathname === "/api/logout") {
        return json(
          { ok: true },
          200,
          { "Set-Cookie": cookieOptions("", 0) }
        );
      }

      const role = await getRole(request, env);

      if (!role) {
        return json({ error: "يرجى تسجيل الدخول أولًا." }, 401);
      }

      if (request.method === "GET" && url.pathname === "/api/content") {
        const raw = await env.BOOK_DATA.get("book:content");
        let memories = [];

        if (raw) {
          try {
            memories = JSON.parse(raw);
          } catch {
            memories = [];
          }
        }

        return json({ role, memories });
      }

      if (request.method === "POST" && url.pathname === "/api/content") {
        if (role !== "owner") {
          return json({ error: "لا تملك صلاحية تعديل الدفتر." }, 403);
        }

        const text = await request.text();

        if (text.length > 3_000_000) {
          return json({ error: "حجم البيانات كبير جدًا." }, 413);
        }

        let body;
        try {
          body = JSON.parse(text);
        } catch {
          return json({ error: "البيانات غير صحيحة." }, 400);
        }

        if (!Array.isArray(body.memories)) {
          return json({ error: "قائمة الصفحات غير صحيحة." }, 400);
        }

        await env.BOOK_DATA.put(
          "book:content",
          JSON.stringify(body.memories)
        );

        return json({ ok: true });
      }

      if (request.method === "GET" && url.pathname === "/api/visits") {
        if (role !== "owner") {
          return json({ error: "غير مسموح." }, 403);
        }

        const listed = await env.BOOK_DATA.list({
          prefix: "visit:",
          limit: 100
        });

        const visits = [];

        for (const key of listed.keys) {
          const value = await env.BOOK_DATA.get(key.name);
          if (value) {
            try {
              visits.push(JSON.parse(value));
            } catch {}
          }
        }

        visits.sort((a, b) => b.at.localeCompare(a.at));

        return json({ visits });
      }

      return json({ error: "المسار غير موجود." }, 404);
    }

    return env.ASSETS.fetch(request);
  }
};
