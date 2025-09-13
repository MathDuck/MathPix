import { Env } from "./env.d";
import { randomId } from "./utils";

async function hashToken(token: string) {
    const data = new TextEncoder().encode(token);
    const buf = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function refreshApiToken(env: Env, user_id: string) {
    try { await env.DB.prepare("ALTER TABLE api_tokens ADD COLUMN token_plain TEXT").run(); } catch { }
    await env.DB.prepare("DELETE FROM api_tokens WHERE user_id=?").bind(user_id).run();
    const token = "mt_" + randomId(48);
    const token_hash = await hashToken(token);
    await env.DB.prepare(
        "INSERT INTO api_tokens (id,user_id,token_hash,token_plain,created_at) VALUES (?,?,?,?,strftime('%s','now'))"
    ).bind("t_" + randomId(12), user_id, token_hash, token).run();
    return token;
}

export async function hasApiToken(env: Env, user_id: string): Promise<boolean> {
    const row = await env.DB.prepare("SELECT 1 as x FROM api_tokens WHERE user_id=? LIMIT 1").bind(user_id).first();
    return !!row;
}

export async function revokeApiToken(env: Env, user_id: string) {
    await env.DB.prepare("DELETE FROM api_tokens WHERE user_id=?").bind(user_id).run();
}

export async function getApiTokenMeta(env: Env, user_id: string): Promise<{ created_at: number; last_used_at?: number } | null> {
    const row = await env.DB.prepare("SELECT created_at,last_used_at FROM api_tokens WHERE user_id=? LIMIT 1").bind(user_id).first<{ created_at: number; last_used_at?: number }>();
    return row || null;
}

export async function getApiTokenPlain(env: Env, user_id: string): Promise<string | null> {
    try { await env.DB.prepare("ALTER TABLE api_tokens ADD COLUMN token_plain TEXT").run(); } catch { }
    const row = await env.DB.prepare("SELECT token_plain FROM api_tokens WHERE user_id=? LIMIT 1").bind(user_id).first<{ token_plain: string | null }>();
    return row?.token_plain || null;
}

export async function findTokenOwner(env: Env, token: string) {
    const token_hash = await hashToken(token);
    const row = await env.DB.prepare(
        "SELECT u.id as user_id, u.role, u.disabled FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?"
    ).bind(token_hash).first<{ user_id: string; role: string; disabled: number }>();
    if (!row || row.disabled) return null;
    await env.DB.prepare("UPDATE api_tokens SET last_used_at=strftime('%s','now') WHERE token_hash=?").bind(token_hash).run();
    return row;
}