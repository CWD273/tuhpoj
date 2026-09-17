/**
 * Cloudflare Worker: URL Proxy
 *
 * Usage:
 *   https://your-worker.your-subdomain.workers.dev/?url=https://example.com
 *
 * Deploy:
 *   1. npm install -g wrangler
 *   2. wrangler init my-proxy   (or drop this file in as src/index.js)
 *   3. wrangler deploy
 */

// ---- Configuration -------------------------------------------------------

// Set to true to restrict which hosts can be proxied. Leave the array empty
// to allow any host (NOT recommended for a publicly reachable Worker).
const RESTRICT_HOSTS = false;
const ALLOWED_HOSTS = [
  // "example.com",
  // "api.example.com",
];

// Headers stripped from the upstream response before returning it to the
// client (mostly security headers that would otherwise block the page from
// being framed/read cross-origin, plus ones that don't make sense to relay).
const STRIP_RESPONSE_HEADERS = [
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "strict-transport-security",
  "set-cookie", // don't leak upstream cookies to the client via your domain
];

// Headers stripped from the incoming client request before forwarding it
// upstream (avoid leaking info about your Worker/host).
const STRIP_REQUEST_HEADERS = ["cf-connecting-ip", "cf-ray", "cf-visitor", "x-forwarded-for"];

// ---- Worker entry point ---------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return handleOptions(request);
    }

    const requestUrl = new URL(request.url);
    const targetParam = requestUrl.searchParams.get("url");

    if (!targetParam) {
      return jsonResponse(
        { error: "Missing required 'url' query parameter." },
        400
      );
    }

    let targetUrl;
    try {
      targetUrl = new URL(targetParam);
    } catch (err) {
      return jsonResponse({ error: "Invalid URL provided." }, 400);
    }

    // Only allow http/https targets
    if (!["http:", "https:"].includes(targetUrl.protocol)) {
      return jsonResponse({ error: "Only http/https URLs are supported." }, 400);
    }

    // Block obviously internal/loopback targets to reduce SSRF risk
    if (isPrivateOrLocalHost(targetUrl.hostname)) {
      return jsonResponse({ error: "Refusing to proxy internal/local addresses." }, 400);
    }

    // Optional allowlist enforcement
    if (RESTRICT_HOSTS && !ALLOWED_HOSTS.includes(targetUrl.hostname)) {
      return jsonResponse(
        { error: `Host '${targetUrl.hostname}' is not in the allowlist.` },
        403
      );
    }

    // Build the outgoing request
    const outgoingHeaders = new Headers(request.headers);
    STRIP_REQUEST_HEADERS.forEach((h) => outgoingHeaders.delete(h));
    outgoingHeaders.set("host", targetUrl.hostname);

    const init = {
      method: request.method,
      headers: outgoingHeaders,
      redirect: "follow",
    };

    // Forward body for methods that can have one
    if (!["GET", "HEAD"].includes(request.method)) {
      init.body = request.body;
    }

    try {
      const upstreamResponse = await fetch(targetUrl.toString(), init);
      return buildProxiedResponse(upstreamResponse, request, targetUrl, requestUrl.origin);
    } catch (err) {
      return jsonResponse(
        { error: "Failed to fetch target URL.", detail: String(err) },
        502
      );
    }
  },
};

// ---- Helpers ---------------------------------------------------------------

function buildProxiedResponse(upstreamResponse, originalRequest, targetUrl, proxyOrigin) {
  const headers = new Headers(upstreamResponse.headers);
  STRIP_RESPONSE_HEADERS.forEach((h) => headers.delete(h));

  // CORS: allow the requesting origin (or * if none supplied)
  const origin = originalRequest.headers.get("Origin");
  headers.set("Access-Control-Allow-Origin", origin || "*");
  headers.set("Vary", "Origin");

  const contentType = headers.get("content-type") || "";

  // Only HTML responses get link/resource rewriting. Other content types
  // (images, fonts, JSON, plain CSS, etc.) are streamed through as-is.
  if (!contentType.includes("text/html")) {
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers,
    });
  }

  // Rewriting removes the original Content-Length; let the runtime recompute
  // it (chunked transfer) rather than send a stale value.
  headers.delete("content-length");

  const rewriter = new HTMLRewriter()
    .on("a", new AttributeRewriter("href", targetUrl, proxyOrigin))
    .on("link", new AttributeRewriter("href", targetUrl, proxyOrigin))
    .on("img", new AttributeRewriter("src", targetUrl, proxyOrigin))
    .on("img", new SrcsetRewriter("srcset", targetUrl, proxyOrigin))
    .on("script", new AttributeRewriter("src", targetUrl, proxyOrigin))
    .on("source", new AttributeRewriter("src", targetUrl, proxyOrigin))
    .on("source", new SrcsetRewriter("srcset", targetUrl, proxyOrigin))
    .on("form", new AttributeRewriter("action", targetUrl, proxyOrigin))
    .on("iframe", new AttributeRewriter("src", targetUrl, proxyOrigin))
    .on("video", new AttributeRewriter("src", targetUrl, proxyOrigin))
    .on("video", new AttributeRewriter("poster", targetUrl, proxyOrigin))
    .on("audio", new AttributeRewriter("src", targetUrl, proxyOrigin))
    .on('meta[http-equiv="refresh" i]', new MetaRefreshRewriter(targetUrl, proxyOrigin))
    .on("base", new BaseTagRemover());

  const transformed = rewriter.transform(
    new Response(upstreamResponse.body, { status: upstreamResponse.status })
  );

  return new Response(transformed.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers,
  });
}

// Rewrites a single URL-bearing attribute (href/src/action/poster) so it
// routes back through the proxy with the resolved absolute URL as ?url=.
class AttributeRewriter {
  constructor(attributeName, targetUrl, proxyOrigin) {
    this.attributeName = attributeName;
    this.targetUrl = targetUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const value = element.getAttribute(this.attributeName);
    if (!value) return;

    // Leave alone: same-page anchors, javascript:, mailto:, tel:, data: URIs
    if (/^(#|javascript:|mailto:|tel:|data:)/i.test(value.trim())) return;

    const rewritten = rewriteUrl(value, this.targetUrl, this.proxyOrigin);
    if (rewritten) element.setAttribute(this.attributeName, rewritten);
  }
}

// srcset is a comma-separated list of "url descriptor" pairs; each URL needs
// rewriting independently.
class SrcsetRewriter {
  constructor(attributeName, targetUrl, proxyOrigin) {
    this.attributeName = attributeName;
    this.targetUrl = targetUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const value = element.getAttribute(this.attributeName);
    if (!value) return;

    const rewritten = value
      .split(",")
      .map((part) => {
        const trimmed = part.trim();
        if (!trimmed) return trimmed;
        const [url, descriptor] = trimmed.split(/\s+/, 2);
        const newUrl = rewriteUrl(url, this.targetUrl, this.proxyOrigin) || url;
        return descriptor ? `${newUrl} ${descriptor}` : newUrl;
      })
      .join(", ");

    element.setAttribute(this.attributeName, rewritten);
  }
}

// <meta http-equiv="refresh" content="5;url=/next.html">
class MetaRefreshRewriter {
  constructor(targetUrl, proxyOrigin) {
    this.targetUrl = targetUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const content = element.getAttribute("content");
    if (!content) return;

    const match = content.match(/^(\s*\d+\s*;\s*url\s*=\s*)(.+)$/i);
    if (!match) return;

    const rewritten = rewriteUrl(match[2].trim(), this.targetUrl, this.proxyOrigin);
    if (rewritten) element.setAttribute("content", `${match[1]}${rewritten}`);
  }
}

// Drop any <base> tag from the source page — it would otherwise change how
// the browser resolves any URL we didn't rewrite (inline styles, JS-added
// nodes, etc.) and conflict with our rewriting.
class BaseTagRemover {
  element(element) {
    element.remove();
  }
}

// Resolves rawUrl against the original target page, then wraps it as a
// proxy URL: {proxyOrigin}/?url=<encoded absolute url>
function rewriteUrl(rawUrl, targetUrl, proxyOrigin) {
  try {
    const absolute = new URL(rawUrl, targetUrl);
    if (!["http:", "https:"].includes(absolute.protocol)) return null;
    return `${proxyOrigin}/?url=${encodeURIComponent(absolute.toString())}`;
  } catch (err) {
    return null;
  }
}

function handleOptions(request) {
  const headers = {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      request.headers.get("Access-Control-Request-Headers") || "*",
    "Access-Control-Max-Age": "86400",
  };
  return new Response(null, { status: 204, headers });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function isPrivateOrLocalHost(hostname) {
  const h = hostname.toLowerCase();

  if (h === "localhost" || h === "0.0.0.0" || h === "::1") return true;

  // IPv4 checks
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [parseInt(ipv4[1], 10), parseInt(ipv4[2], 10)];
    if (a === 127) return true; // loopback
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 169 && b === 254) return true; // link-local
  }

  return false;
}
