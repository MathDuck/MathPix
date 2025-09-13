import { route } from "./router";
import { Env } from "./env.d";
import { runCleanup } from "./utils";

async function serveAsset(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
    try {
        // @ts-ignore - fourni par Wrangler
        const asset = await (globalThis as any).__STATIC_CONTENT.get(pathname.slice(1), "arrayBuffer");
        if (!asset) return null;
        let type = "application/octet-stream";
        if (pathname.endsWith(".css")) type = "text/css";
        else if (pathname.endsWith(".js")) type = "application/javascript";
        else if (pathname.endsWith(".html")) type = "text/html";
        const headers: Record<string, string> = { "content-type": `${type}; charset=utf-8` };
        if (/\.[a-f0-9]{8,}\.js$/i.test(pathname) || /\.[a-f0-9]{8,}\.css$/i.test(pathname)) {
            headers['cache-control'] = 'public, max-age=31536000, immutable';
        } else if (type !== 'text/html') {
            headers['cache-control'] = 'public, max-age=3600';
        } else {
            headers['cache-control'] = 'no-cache';
        }
        return new Response(asset, { headers });
    } catch { return null; }
}

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const asset = await serveAsset(request);
        if (asset) return asset;
        return route(request, env, ctx);
    },

    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
        if (env.CLEANUP_ENABLED === "true") {
            ctx.waitUntil(runCleanup(env));
        }
    }
};