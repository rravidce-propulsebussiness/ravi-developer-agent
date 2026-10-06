import http from "node:http";
import crypto from "node:crypto";
import { chromium } from "playwright";

const HOST = process.env.RUNNER_HOST || "127.0.0.1";
const PORT = Number(process.env.RUNNER_PORT || 8788);
const RUNNER_TOKEN = String(process.env.RUNNER_TOKEN || "");
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const CHROME_PATH = String(process.env.CHROME_PATH || "").trim();
const HEADLESS = String(process.env.HEADLESS || "true").toLowerCase() !== "false";
const MAX_SESSIONS = Math.max(1, Math.min(64, Number(process.env.MAX_SESSIONS || 8)));
const SESSION_IDLE_MS = Math.max(0, Number(process.env.SESSION_IDLE_MS || 1_800_000));

if (RUNNER_TOKEN.length < 32) {
  throw new Error("RUNNER_TOKEN must be at least 32 characters.");
}
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("RUNNER_PORT is invalid.");
}
if (HOST === "0.0.0.0" && !PUBLIC_BASE_URL.startsWith("https://")) {
  throw new Error("PUBLIC_BASE_URL must be HTTPS when the runner binds publicly.");
}

const sessions = new Map();
const viewTokens = new Map();
let browserPromise;

function validDomainPattern(value) {
  if (typeof value !== "string") return false;
  if (value !== value.toLowerCase() || value.includes("://") || /[/?#:@\\\\]/.test(value)) return false;
  if (value === "localhost" || value.endsWith(".localhost")) return false;
  if ((value.match(/\*/g) || []).length > 1) return false;
  return /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
}

function hostnameAllowed(hostname, patterns) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  return patterns.some((pattern) =>
    pattern.startsWith("*.")
      ? host.endsWith(pattern.slice(1)) && host !== pattern.slice(2)
      : host === pattern
  );
}

function safeEqualToken(value) {
  const a = Buffer.from(String(value || ""));
  const b = Buffer.from(RUNNER_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function authorized(req) {
  const header = String(req.headers.authorization || "");
  return header.startsWith("Bearer ") && safeEqualToken(header.slice(7));
}

function json(res, status, body, extraHeaders = {}) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(payload);
}

function text(res, status, body, type = "text/plain; charset=utf-8", extraHeaders = {}) {
  const payload = Buffer.from(body);
  res.writeHead(status, {
    "content-type": type,
    "content-length": String(payload.length),
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(payload);
}

async function readJson(req, limit = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error("request_too_large"), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!size) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("invalid_json"), { statusCode: 400 });
  }
}

async function getBrowser() {
  if (!browserPromise) {
    browserPromise = chromium.launch({
      headless: HEADLESS,
      executablePath: CHROME_PATH || undefined,
      args: [
        "--disable-dev-shm-usage",
        "--no-default-browser-check",
        "--disable-background-networking",
      ],
    }).catch((error) => {
      browserPromise = undefined;
      throw error;
    });
  }
  const browser = await browserPromise;
  if (!browser.isConnected()) {
    browserPromise = undefined;
    return getBrowser();
  }
  return browser;
}

function makeId(bytes = 18) {
  return crypto.randomBytes(bytes).toString("base64url").replace(/[-_]/g, "").slice(0, bytes * 2);
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) throw Object.assign(new Error("session_not_found"), { statusCode: 404 });
  session.lastUsedAt = Date.now();
  return session;
}

function findPage(session, targetId) {
  const id = targetId || session.activeTargetId;
  if (id && session.pages.has(id)) return { targetId: id, page: session.pages.get(id) };
  const first = session.pages.entries().next();
  if (!first.done) return { targetId: first.value[0], page: first.value[1] };
  throw Object.assign(new Error("page_not_found"), { statusCode: 404 });
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return false;
  sessions.delete(sessionId);
  try { await session.context.close(); } catch {}
  for (const [token, view] of viewTokens) {
    if (view.sessionId === sessionId) viewTokens.delete(token);
  }
  return true;
}

async function createSession(allowedDomains) {
  const normalized = [...new Set((allowedDomains || []).map((x) => String(x).trim().toLowerCase()))].sort();
  if (!normalized.length || normalized.length > 50 || normalized.some((x) => !validDomainPattern(x))) {
    throw Object.assign(new Error("invalid_allowed_domains"), { statusCode: 400 });
  }
  if (sessions.size >= MAX_SESSIONS) {
    throw Object.assign(new Error("session_capacity_reached"), { statusCode: 429 });
  }

  const browser = await getBrowser();
  const context = await browser.newContext({
    serviceWorkers: "block",
    viewport: { width: 1440, height: 1000 },
  });

  await context.route("**/*", async (route) => {
    const requestUrl = route.request().url();
    let parsed;
    try { parsed = new URL(requestUrl); } catch { return route.abort("blockedbyclient"); }
    if (["data:", "blob:", "about:"].includes(parsed.protocol)) return route.continue();
    if (!["http:", "https:"].includes(parsed.protocol)) return route.abort("blockedbyclient");
    if (!hostnameAllowed(parsed.hostname, normalized)) return route.abort("blockedbyclient");
    return route.continue();
  });

  const sessionId = makeId();
  sessions.set(sessionId, {
    sessionId,
    context,
    allowedDomains: normalized,
    pages: new Map(),
    activeTargetId: null,
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  });
  return sessions.get(sessionId);
}

function safeTab(targetId, page) {
  return {
    id: targetId,
    type: "page",
    title: "",
    url: page.url(),
  };
}

async function withPage(session, targetId, fn) {
  const found = findPage(session, targetId);
  const output = await fn(found.page, found.targetId);
  session.activeTargetId = found.targetId;
  session.lastUsedAt = Date.now();
  return output;
}

function pageMetadata(page, targetId) {
  return Promise.resolve(page.title()).then((title) => ({
    targetId,
    url: page.url(),
    title,
  }));
}

function isSensitiveField(field) {
  const haystack = [field.type, field.autocomplete, field.name, field.id, field.ariaLabel].join(" ").toLowerCase();
  return field.type === "password" ||
    /(password|passwd|secret|token|otp|one[- ]?time|verification|2fa|mfa|cc-|card|cvv|cvc)/.test(haystack);
}

async function performAction(session, body) {
  const action = String(body.action || "");
  const targetId = body.targetId ? String(body.targetId) : undefined;

  if (action === "activate") {
    const found = findPage(session, targetId);
    session.activeTargetId = found.targetId;
    await found.page.bringToFront();
    return { targetId: found.targetId, active: true };
  }

  if (action === "closeTab") {
    const found = findPage(session, targetId);
    session.pages.delete(found.targetId);
    if (session.activeTargetId === found.targetId) session.activeTargetId = session.pages.keys().next().value || null;
    await found.page.close();
    return { targetId: found.targetId, closed: true };
  }

  return withPage(session, targetId, async (page, resolvedTargetId) => {
    if (action === "screenshot") {
      const png = await page.screenshot({ type: "png" });
      return { ...(await pageMetadata(page, resolvedTargetId)), pngBase64: Buffer.from(png).toString("base64") };
    }
    if (action === "pageText") {
      const visibleText = await page.evaluate(() => document.body?.innerText || "");
      return { ...(await pageMetadata(page, resolvedTargetId)), text: String(visibleText).slice(0, 50000) };
    }
    if (action === "click") {
      const selector = String(body.selector || "");
      if (!selector) throw Object.assign(new Error("selector_required"), { statusCode: 400 });
      await page.locator(selector).first().click({ timeout: 10_000 });
      await page.waitForTimeout(300);
      return { ...(await pageMetadata(page, resolvedTargetId)), clicked: true };
    }
    if (action === "type") {
      const selector = String(body.selector || "");
      const value = String(body.text || "");
      if (!selector) throw Object.assign(new Error("selector_required"), { statusCode: 400 });
      if (value.length > 10000) throw Object.assign(new Error("text_too_long"), { statusCode: 400 });
      const locator = page.locator(selector).first();
      const field = await locator.evaluate((el) => ({
        type: String(el.type || "").toLowerCase(),
        autocomplete: String(el.autocomplete || "").toLowerCase(),
        name: String(el.name || "").toLowerCase(),
        id: String(el.id || "").toLowerCase(),
        ariaLabel: String(el.getAttribute("aria-label") || "").toLowerCase(),
      }));
      if (isSensitiveField(field)) {
        throw Object.assign(new Error("sensitive_field_not_supported"), { statusCode: 400 });
      }
      if (body.clearFirst) await locator.fill("");
      await locator.type(value);
      return { ...(await pageMetadata(page, resolvedTargetId)), typed: true, characters: value.length };
    }
    if (action === "select") {
      const selector = String(body.selector || "");
      const values = Array.isArray(body.values) ? body.values.map(String).slice(0, 20) : [];
      if (!selector || !values.length) throw Object.assign(new Error("selector_and_values_required"), { statusCode: 400 });
      const selected = await page.locator(selector).first().selectOption(values);
      return { ...(await pageMetadata(page, resolvedTargetId)), selected };
    }
    if (action === "press") {
      const allowed = new Set(["Enter","Escape","Tab","Backspace","Delete","ArrowUp","ArrowDown","ArrowLeft","ArrowRight"]);
      const key = String(body.key || "");
      if (!allowed.has(key)) throw Object.assign(new Error("key_not_allowed"), { statusCode: 400 });
      await page.keyboard.press(key);
      await page.waitForTimeout(200);
      return { ...(await pageMetadata(page, resolvedTargetId)), pressed: key };
    }
    if (action === "wait") {
      const timeoutMs = Math.max(100, Math.min(10000, Number(body.timeoutMs || 3000)));
      if (body.selector) await page.locator(String(body.selector)).first().waitFor({ timeout: timeoutMs });
      else await page.waitForTimeout(timeoutMs);
      return { ...(await pageMetadata(page, resolvedTargetId)), ready: true };
    }
    throw Object.assign(new Error("unknown_action"), { statusCode: 400 });
  });
}

function createView(sessionId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + 5 * 60_000;
  viewTokens.set(token, { sessionId, expiresAt });
  return {
    url: `${PUBLIC_BASE_URL}/view/${encodeURIComponent(token)}`,
    expiresAt,
  };
}

function resolveView(token) {
  const record = viewTokens.get(token);
  if (!record || record.expiresAt < Date.now()) {
    viewTokens.delete(token);
    throw Object.assign(new Error("view_expired"), { statusCode: 404 });
  }
  return record;
}

function viewHtml(token) {
  const safeToken = JSON.stringify(token);
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ravi Developer Agent Live View</title>
<style>
html,body{width:100%;height:100%;margin:0;background:#07111c;color:#fff;font-family:system-ui,sans-serif;overflow:hidden}
#wrap{position:relative;width:100%;height:100%;display:grid;place-items:center}
#frame{display:block;max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain}
#status{position:absolute;left:12px;bottom:12px;padding:6px 9px;border-radius:999px;background:rgba(0,0,0,.55);font-size:12px;backdrop-filter:blur(8px)}
</style>
</head>
<body>
<div id="wrap"><img id="frame" alt="Live browser view"><div id="status">Connecting…</div></div>
<script>
const token=${safeToken};
const img=document.getElementById("frame");
const status=document.getElementById("status");
let stopped=false;
async function tick(){
  if(stopped) return;
  try{
    const r=await fetch("/view/"+encodeURIComponent(token)+"/frame?ts="+Date.now(),{cache:"no-store"});
    if(!r.ok) throw new Error(String(r.status));
    const blob=await r.blob();
    const old=img.src;
    img.src=URL.createObjectURL(blob);
    if(old.startsWith("blob:")) URL.revokeObjectURL(old);
    status.textContent="Live · read only";
  }catch(e){
    status.textContent="Live view disconnected";
    stopped=true;
    return;
  }
  setTimeout(tick,650);
}
tick();
</script>
</body>
</html>`;
}

async function handleApi(req, res, url) {
  if (!authorized(req)) return json(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, { ok: true, browser: Boolean(browserPromise), sessions: sessions.size, maxSessions: MAX_SESSIONS });
  }

  if (req.method === "POST" && url.pathname === "/v1/sessions") {
    const body = await readJson(req);
    const session = await createSession(body.allowedDomains);
    return json(res, 201, {
      sessionId: session.sessionId,
      allowedDomains: session.allowedDomains,
      backend: "selfhosted",
    });
  }

  const match = url.pathname.match(/^\/v1\/sessions\/([A-Za-z0-9]+)(?:\/(.*))?$/);
  if (!match) return json(res, 404, { error: "not_found" });
  const sessionId = match[1];
  const tail = match[2] || "";
  const session = getSession(sessionId);

  if (req.method === "GET" && tail === "") {
    return json(res, 200, {
      sessionId,
      allowedDomains: session.allowedDomains,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      tabs: session.pages.size,
    });
  }

  if (req.method === "DELETE" && tail === "") {
    await closeSession(sessionId);
    return json(res, 200, { closed: true });
  }

  if (req.method === "GET" && tail === "tabs") {
    const tabs = [];
    for (const [targetId, page] of session.pages) {
      tabs.push({ ...(safeTab(targetId, page)), title: await page.title() });
    }
    return json(res, 200, { tabs, activeTargetId: session.activeTargetId });
  }

  if (req.method === "POST" && tail === "tabs") {
    const body = await readJson(req);
    const target = new URL(String(body.url || ""));
    if (!["http:", "https:"].includes(target.protocol)) {
      throw Object.assign(new Error("unsupported_url_scheme"), { statusCode: 400 });
    }
    if (target.username || target.password) {
      throw Object.assign(new Error("credentials_in_url_not_allowed"), { statusCode: 400 });
    }
    if (!hostnameAllowed(target.hostname, session.allowedDomains)) {
      throw Object.assign(new Error("hostname_not_allowed"), { statusCode: 403 });
    }
    const page = await session.context.newPage();
    const targetId = makeId(12);
    session.pages.set(targetId, page);
    session.activeTargetId = targetId;
    try {
      await page.goto(target.toString(), { waitUntil: "domcontentloaded", timeout: 30_000 });
    } catch (error) {
      const message = String(error?.message || error);
      if (!/ERR_ABORTED|Navigation interrupted/i.test(message)) throw error;
    }
    return json(res, 201, { tab: { ...(safeTab(targetId, page)), title: await page.title() } });
  }

  if (req.method === "POST" && tail === "actions") {
    const body = await readJson(req);
    const output = await performAction(session, body);
    return json(res, 200, output);
  }

  if (req.method === "POST" && tail === "live-view") {
    if (!PUBLIC_BASE_URL.startsWith("https://")) {
      throw Object.assign(new Error("public_base_url_https_required"), { statusCode: 503 });
    }
    const view = createView(sessionId);
    return json(res, 200, view);
  }

  return json(res, 404, { error: "not_found" });
}

async function handler(req, res) {
  const url = new URL(req.url || "/", "http://runner.local");
  try {
    if (req.method === "GET" && url.pathname.startsWith("/view/")) {
      const parts = url.pathname.split("/").filter(Boolean);
      const token = parts[1] || "";
      const record = resolveView(token);
      const session = getSession(record.sessionId);

      if (parts.length === 2) {
        return text(res, 200, viewHtml(token), "text/html; charset=utf-8");
      }
      if (parts.length === 3 && parts[2] === "frame") {
        const found = findPage(session);
        const png = await found.page.screenshot({ type: "png" });
        res.writeHead(200, {
          "content-type": "image/png",
          "content-length": String(png.length),
          "cache-control": "no-store, max-age=0",
          "x-content-type-options": "nosniff",
        });
        return res.end(png);
      }
      return json(res, 404, { error: "not_found" });
    }

    return await handleApi(req, res, url);
  } catch (error) {
    const status = Number(error?.statusCode || 500);
    const message = status >= 500 ? "runner_error" : String(error?.message || "request_failed");
    if (status >= 500) console.error(error);
    return json(res, status, { error: message });
  }
}

const server = http.createServer(handler);
server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;
server.requestTimeout = 30_000;

server.listen(PORT, HOST, () => {
  console.log(`Ravi self-hosted browser runner listening on http://${HOST}:${PORT}`);
});

const cleanup = setInterval(async () => {
  const now = Date.now();
  for (const [token, record] of viewTokens) {
    if (record.expiresAt < now) viewTokens.delete(token);
  }
  if (!SESSION_IDLE_MS) return;
  for (const [sessionId, session] of sessions) {
    if (now - session.lastUsedAt > SESSION_IDLE_MS) await closeSession(sessionId);
  }
}, 30_000);
cleanup.unref();

async function shutdown() {
  server.close();
  clearInterval(cleanup);
  for (const sessionId of [...sessions.keys()]) await closeSession(sessionId);
  try {
    const browser = await browserPromise;
    if (browser) await browser.close();
  } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
