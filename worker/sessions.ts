import { Env } from "./env.d";
import { randomId, SESSION_TTL_HOURS } from "./utils";

export type Session = {
    id: string;
    user_id?: string;
    expires_at: number;
};

function sign(value: string, secret: string) {
    const data = new TextEncoder().encode(value + secret);
    return crypto.subtle.digest("SHA-256", data).then(buf => {
        return Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, "0")).join("");
    });
}

export async function createSession(env: Env, user: { id?: string }, opts?: { hours?: number }) {
    const id = randomId(32);
    const hours = (opts?.hours && opts.hours > 0) ? opts.hours : SESSION_TTL_HOURS;
    const ttlMs = hours * 60 * 60 * 1000;
    const exp = Date.now() + ttlMs;
    await env.DB.prepare(
        "INSERT INTO sessions (id,user_id,expires_at,created_at) VALUES (?,?,?,strftime('%s','now'))"
    ).bind(id, user.id ?? null, Math.floor(exp / 1000)).run();
    return { id, expires_at: exp };
}

export async function getSession(env: Env, req: Request) {
    const cookie = req.headers.get("cookie") || "";
    const match = /sessionId=([^;]+)/.exec(cookie);
    if (!match) return null;
    const [val, sig] = decodeURIComponent(match[1]).split(".");
    if (!sig) return null;
    const validSig = await sign(val, env.COOKIE_SECRET);
    if (validSig !== sig) return null;

    const row = await env.DB.prepare(
        "SELECT id,user_id,expires_at FROM sessions WHERE id=?"
    ).bind(val).first<{ id: string; user_id?: string; expires_at: number }>();
    if (!row) return null;
    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at < now) {
        await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(row.id).run();
        return null;
    }
    return row;
}

export async function destroySession(env: Env, sid: string) {
    await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(sid).run();
}

export async function sessionCookie(env: Env, sid: string, opts?: { hours?: number }) {
    const sig = await sign(sid, env.COOKIE_SECRET);
    const cookieVal = encodeURIComponent(`${sid}.${sig}`);
    const isHttps = (env.BASE_URL || '').startsWith('https://');
    const hours = (opts?.hours && opts.hours > 0) ? opts.hours : SESSION_TTL_HOURS;
    const attrsArr = [
        `sessionId=${cookieVal}`,
        "Path=/",
        "HttpOnly",
        isHttps ? "Secure" : null,
        "SameSite=Lax",
        `Max-Age=${hours * 60 * 60}`
    ].filter(Boolean) as string[];
    const attrs = attrsArr.join("; ");
    return attrs;
}

export function clearCookie() {
    return [
        "sessionId=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    ].join("; ");
}