import crypto from "node:crypto";
import { getMedia }                from "./core/anilist.js";
import { mapAnimeIds }             from "./core/mapper.js";
import mkissaHandler               from "./providers/mkissa.js";
import reanimeHandler              from "./providers/reanime.js";
import anikotoHandler              from "./providers/anikoto.js";
import animeggHandler              from "./providers/animegg.js";
import animenosubHandler           from "./providers/animenosub.js";
import anizoneHandler              from "./providers/anizone.js";
import aniwavesHandler             from "./providers/aniwaves.js";
import senshiHandler               from "./providers/senshi.js";
import kaaHandler                  from "./providers/kickassanime.js";
import animedunyaHandler           from "./providers/animedunya.js";
import animeonsenHandler           from "./providers/animeonsen.js";
import anipmHandler                from "./providers/anipm.js";
import { getEpisodesResponse, getFilteredEpisodesResponse } from "./core/episode-cache.js";
import { resolveProviders }         from "./core/episode-strategy.js";
import { getAsync, setAsync, isFresh, mapTTL, WATCH_TTL, _CACHE_ENABLED } from "./core/smartcache.js";

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "public, max-age=300",
    },
  });
}

function rewriteRequest(request, newPath) {
  const u = new URL(request.url);
  u.pathname = newPath;
  return new Request(u.toString(), { method: request.method, headers: request.headers });
}

const watchInflight = new Map();
const SIGNED_STREAM_WATCH_TTL = 60_000;

// ── Worker proxy (?worker=1|true|<custom-url>) ───────────────────────────────
// When enabled, stream + subtitle URLs in the response are prefixed with the
// worker base, e.g. https://worker.example.dev/https://host/path/master.m3u8
const DEFAULT_WORKER_BASE = (process.env.WORKER_PROXY_URL || "https://bold-hill-8d64.ntb7nmytsd.workers.dev").replace(/\/+$/, "");

// ── Encrypted mode (?data=en) ─────────────────────────────────────────────
// Stream/subtitle URLs are replaced with AES-256-GCM tokens that only the
// EN worker can decrypt — no upstream URL ever appears in the response.
//   token = "v1." + b64url(iv) + "." + b64url(ciphertext + authtag)
//   key   = SHA-256(SECRET)              -> AES-256-GCM
//   iv    = SHA-256("iv:" + url)[0..12]  -> deterministic (same URL = same token)
const WORKER_URL_EN = (
  process.env.WORKER_URL_EN || "https://lively-union-8780-zoen.ryklcd0086.workers.dev"
).replace(/\/+$/, ""); // strip trailing slash
const TOKEN_SECRET = "bbef4e4840ab0a33b6c129f0de8b1a6735471c82f43e9babc4adc64c5959a64a";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function encryptUrlToken(rawUrl) {
  const key = crypto.createHash("sha256").update(TOKEN_SECRET).digest();
  const iv = crypto.createHash("sha256").update(`iv:${rawUrl}`).digest().subarray(0, 12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(rawUrl, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${b64url(iv)}.${b64url(Buffer.concat([ct, tag]))}`;
}

function workerBase(request) {
  const raw = new URL(request.url).searchParams.get("worker");
  if (!raw) return null;
  const value = raw.trim();
  if (/^(1|true)$/i.test(value)) return DEFAULT_WORKER_BASE;
  if (/^https?:\/\/.+/i.test(value)) return value.replace(/\/+$/, "");
  return null;
}

function proxiedUrl(url, base, encrypt = false) {
  if (typeof url !== "string" || !url) return url;
  if (encrypt) {
    // EN mode: tokenize absolute http(s) URLs only — relative paths cannot
    // be decrypted by the worker, so they pass through untouched
    if (!/^https?:\/\//i.test(url)) return url;
    return `${WORKER_URL_EN}/${encryptUrlToken(url)}`;
  }
  if (!base) return url;
  if (/^https?:\/\//i.test(url) || url.startsWith("//")) return `${base}/${url.replace(/^\/+/, "")}`;
  return url;
}

function proxySubtitle(sub, base, encrypt = false) {
  if (!sub || typeof sub !== "object") return sub;
  return { ...sub, url: proxiedUrl(sub.url, base, encrypt) };
}

function proxyStream(stream, base, encrypt = false) {
  if (!stream || typeof stream !== "object") return stream;
  const next = { ...stream, url: proxiedUrl(stream.url, base, encrypt) };
  if (Array.isArray(next.subtitles)) next.subtitles = next.subtitles.map((s) => proxySubtitle(s, base, encrypt));
  return next;
}

function applyWorkerProxy(data, base, encrypt = false) {
  if (!data || typeof data !== "object") return data;
  const out = { ...data };
  if (encrypt) out.encrypted = true;
  if (Array.isArray(out.streams)) out.streams = out.streams.map((s) => proxyStream(s, base, encrypt));
  // mkissa returns sources[] where extractedUrl is the playable stream
  if (Array.isArray(out.sources)) out.sources = out.sources.map((s) =>
    s && typeof s === "object" ? { ...s, extractedUrl: proxiedUrl(s.extractedUrl, base, encrypt) } : s
  );
  if (Array.isArray(out.subtitles)) out.subtitles = out.subtitles.map((s) => proxySubtitle(s, base, encrypt));
  if (typeof out.stream_url === "string") out.stream_url = proxiedUrl(out.stream_url, base, encrypt);
  return out;
}

async function withWorker(request, response) {
  const base = workerBase(request);
  const encrypt = (new URL(request.url).searchParams.get("data") || "").trim().toLowerCase() === "en";
  if (!base && !encrypt) return response;

  // 302-style redirect routes (e.g. /stream/reanime/...) → rewrite Location
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) return response;
    const headers = new Headers(response.headers);
    headers.set("Location", proxiedUrl(location, base, encrypt));
    return new Response(null, { status: response.status, headers });
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return response;

  try {
    const data = await response.json();
    return json(applyWorkerProxy(data, base, encrypt), response.status);
  } catch {
    return response;
  }
}

async function cachedWatch(cacheKey, handlerFn, ttl = WATCH_TTL) {
  const entry = await getAsync(cacheKey);
  if (entry && isFresh(entry)) return json(entry.data);

  if (watchInflight.has(cacheKey)) {
    await watchInflight.get(cacheKey).catch(() => {});
    const warm = await getAsync(cacheKey);
    if (warm && isFresh(warm)) return json(warm.data);
    return handlerFn();
  }

  const promise = (async () => {
    const response = await handlerFn();
    if (response.status === 200) {
      try {
        const data = await response.clone().json();
        await setAsync(cacheKey, data, ttl);
      } catch {}
    }
    return response;
  })();

  watchInflight.set(cacheKey, promise);
  try   { return await promise; }
  finally { watchInflight.delete(cacheKey); }
}

async function routeRequest(request, env) {
  const url  = new URL(request.url);
  const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin":  "*",
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "*",
        },
      });
    }

    let m = path.match(/^\/map\/(\d+)\/?$/);
    if (m) {
      const anilistId = m[1];
      const cacheKey  = `map:${anilistId}`;
      const entry     = await getAsync(cacheKey);
      if (entry && isFresh(entry)) return json(entry.data);

      try {
        const [data, media] = await Promise.all([
          mapAnimeIds(anilistId),
          getMedia(anilistId).catch(() => null),
        ]);
        await setAsync(cacheKey, data, mapTTL(media?.status ?? "RELEASING"));
        return json(data);
      } catch (e) {
        if (entry) return json(entry.data);
        return json({ error: e.message }, 500);
      }
    }

    m = path.match(/^\/episodes\/((?:[\w-]+\/)+)(\d+)\/?$/i);
    if (m) {
      const rawNames  = m[1].replace(/\/$/, "").split("/");
      const anilistId = m[2];
      const includeMap = url.searchParams.get("map") !== "false";
      const { resolved, unknown } = resolveProviders(rawNames);

      if (resolved.size === 0) {
        return json({ error: "No valid providers specified", unknown }, 400);
      }

      try {
        const data = await getFilteredEpisodesResponse(anilistId, resolved, includeMap);
        if (unknown.length) data._unknownProviders = unknown;
        return json(data);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    m = path.match(/^\/episodes\/(\d+)\/?$/);
    if (m) {
      const anilistId = m[1];
      try {
        return json(await getEpisodesResponse(anilistId, env));
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    m = path.match(/^\/watch\/mkissa\/(\d+)\/(sub|dub)\/mkissa-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:mkissa:${id}:${audio}:${ep}`,
        () => mkissaHandler.fetch(request)
      );
    }

    if (path.match(/^\/captcha\/mkissa\/?$/)) {
      return mkissaHandler.fetch(request);
    }

    m = path.match(/^\/watch\/reanime\/(\d+)\/(sub|dub)\/reanime-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:reanime:${id}:${audio}:${ep}`,
        () => reanimeHandler.fetch(rewriteRequest(request, `/watch/${id}/${audio}/${ep}`))
      );
    }

    m = path.match(/^\/stream\/reanime\/(\d+)\/(sub|dub)\/(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return reanimeHandler.fetch(rewriteRequest(request, `/stream/${id}/${audio}/${ep}`));
    }

    m = path.match(/^\/watch\/anikoto\/(\d+)\/(sub|dub)\/anikoto-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:anikoto:${id}:${audio}:${ep}`,
        () => anikotoHandler.fetch(request),
        SIGNED_STREAM_WATCH_TTL
      );
    }

    m = path.match(/^\/watch\/animegg\/(\d+)\/(sub|dub)\/animegg-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:animegg:${id}:${audio}:${ep}`,
        () => animeggHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/animenosub\/(\d+)\/(sub|dub)\/animenosub-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:animenosub:${id}:${audio}:${ep}`,
        () => animenosubHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/anizone\/(\d+)\/(sub|dub)\/anizone-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:anizone:${id}:${audio}:${ep}`,
        () => anizoneHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/aniwaves\/(\d+)\/(sub|dub)\/aniwaves-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:aniwaves:${id}:${audio}:${ep}`,
        () => aniwavesHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/senshi\/(\d+)\/(sub|dub)\/senshi-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:senshi:${id}:${audio}:${ep}`,
        () => senshiHandler.fetch(request),
        SIGNED_STREAM_WATCH_TTL
      );
    }

    m = path.match(/^\/watch\/kaa\/(\d+)\/(sub|dub)\/kaa-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:kaa:${id}:${audio}:${ep}`,
        () => kaaHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/animedunya\/(\d+)\/(sub|dub)\/animedunya-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:animedunya:${id}:${audio}:${ep}`,
        () => animedunyaHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/animeonsen\/(\d+)\/(sub|dub)\/animeonsen-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:animeonsen:${id}:${audio}:${ep}`,
        () => animeonsenHandler.fetch(request)
      );
    }

    m = path.match(/^\/watch\/anipm\/(\d+)\/(sub|dub)\/anipm-(\d+)\/?$/);
    if (m) {
      const [, id, audio, ep] = m;
      return cachedWatch(
        `watch:anipm:${id}:${audio}:${ep}`,
        () => anipmHandler.fetch(request),
        SIGNED_STREAM_WATCH_TTL
      );
    }

    if (path.startsWith("/watch/")) return json({ error: "Not found" }, 404);

    return json({
      name: `Anivexa API ${env?.API_VERSION ?? "unknown"}`,
      cache: _CACHE_ENABLED,
      providers: [
        "mkissa",
        "reanime",
        "anikoto",
        "animegg",
        "animenosub",
        "anizone",
        "aniwaves",
        "senshi",
        "kaa",
        "animedunya",
        "animeonsen",
        "anipm",
      ],
      routes: [
        "/map/:anilistId",
        "/episodes/:anilistId",
        "/episodes/:provider[/:provider...]/:anilistId?map=true|false",
        "/watch/mkissa/:id/sub|dub/mkissa-:ep",
        "/watch/reanime/:id/sub|dub/reanime-:ep",
        "/stream/reanime/:id/sub|dub/:ep",
        "/watch/anikoto/:id/sub|dub/anikoto-:ep",
        "/watch/animegg/:id/sub|dub/animegg-:ep",
        "/watch/animenosub/:id/sub|dub/animenosub-:ep",
        "/watch/anizone/:id/sub|dub/anizone-:ep",
        "/watch/aniwaves/:id/sub|dub/aniwaves-:ep",
        "/watch/senshi/:id/sub|dub/senshi-:ep",
        "/watch/kaa/:id/sub|dub/kaa-:ep",
        "/watch/animedunya/:id/sub|dub/animedunya-:ep",
        "/watch/animeonsen/:id/sub|dub/animeonsen-:ep",
        "/watch/anipm/:id/sub|dub/anipm-:ep",
      ],
      worker: "Append ?worker=1|true (or ?worker=<custom-worker-url>) to any /watch or /stream route to route stream + subtitle URLs through the proxy worker",
      encrypted: "Append ?data=en to any /watch or /stream route: stream + subtitle URLs come back as AES-256-GCM tokens that play through the EN decryptor worker (no upstream URL in the response)",
    });
}

export default {
  async fetch(request, env) {
    const response = await routeRequest(request, env);
    return withWorker(request, response);
  },
};
