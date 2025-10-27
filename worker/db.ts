import { Env } from "./env.d";

// Rôle désormais entièrement dynamique (toutes les valeurs proviennent de role_policies)
export type Role = string;

export async function getUserByEmail(env: Env, email: string) {
    return env.DB.prepare(
        "SELECT id,email,username,role,password_hash,disabled,created_at,avatar_key,email_verified FROM users WHERE email=?"
    ).bind(email).first();
}

export async function getUserByUsername(env: Env, username: string) {
    return env.DB.prepare(
        "SELECT id,email,username,role,password_hash,disabled,created_at,avatar_key,email_verified FROM users WHERE username=?"
    ).bind(username).first();
}

export async function getUserByEmailOrUsername(env: Env, identifier: string) {
    if (/@/.test(identifier)) {
        return getUserByEmail(env, identifier);
    }
    return getUserByUsername(env, identifier);
}

export async function getUserById(env: Env, id: string) {
    return env.DB.prepare(
        "SELECT id,email,username,role,disabled,avatar_key,email_verified FROM users WHERE id=?"
    ).bind(id).first();
}

export async function createUser(env: Env, o: { id: string; email: string; username?: string; role: Role; password_hash: string }) {
    const res = await env.DB.prepare(
        "INSERT INTO users (id,email,username,role,password_hash,disabled,created_at,email_verified) VALUES (?,?,?,?,?,0,strftime('%s','now'),0)"
    ).bind(o.id, o.email, o.username ?? null, o.role, o.password_hash).run();
    await env.DB.prepare(
        "INSERT OR IGNORE INTO users_stats (user_id, images_total, images_today, last_upload_at, bytes_total, last_updated_at) VALUES (?,0,0,NULL,0,strftime('%s','now'))"
    ).bind(o.id).run();
    return res;
}

export async function createImage(env: Env, o: {
    id: string; owner_id?: string; key: string; ext: string; content_type: string;
    size: number; ip: string; auto_delete_at?: number; original_name?: string | null;
}) {
    return await env.DB.prepare(
        "INSERT INTO images (id,owner_id,key,ext,content_type,original_name,size,created_at,ip,auto_delete_at) VALUES (?,?,?,?,?,?,?,strftime('%s','now'),?,?)"
    ).bind(o.id, o.owner_id ?? null, o.key, o.ext, o.content_type, o.original_name ?? null, o.size, o.ip, o.auto_delete_at ?? null).run();
}

// --- users_stats helpers ---
export async function bumpUserStatsOnUpload(env: Env, user_id: string | undefined, bytes: number) {
    if (!user_id) return;
    await env.DB.prepare(`
        INSERT INTO users_stats (user_id, images_total, images_today, last_upload_at, bytes_total, last_updated_at)
        VALUES (?, 1, 1, strftime('%s','now'), ?, strftime('%s','now'))
        ON CONFLICT(user_id) DO UPDATE SET
            images_total = users_stats.images_total + 1,
            images_today = CASE
                WHEN date(users_stats.last_updated_at,'unixepoch','localtime') = date('now','localtime')
                THEN users_stats.images_today + 1
                ELSE 1
            END,
            last_upload_at = strftime('%s','now'),
            bytes_total = users_stats.bytes_total + ?,
            last_updated_at = strftime('%s','now')
    `).bind(user_id, bytes, bytes).run();
}

export async function bumpUserStatsOnDelete(env: Env, user_id: string | undefined, bytes: number | undefined) {
    if (!user_id) return;
    await env.DB.prepare(`
        UPDATE users_stats SET
            images_total = CASE WHEN images_total > 0 THEN images_total - 1 ELSE 0 END,
            bytes_total = CASE WHEN ? IS NOT NULL AND bytes_total > ? THEN bytes_total - ? ELSE bytes_total END,
            last_updated_at = strftime('%s','now')
        WHERE user_id=?
    `).bind(bytes ?? null, bytes ?? null, bytes ?? null, user_id).run();
}

export async function countUploadsToday(env: Env, ref: { user_id?: string; ip: string }) {
    return env.DB.prepare(
        `SELECT COUNT(*) as c FROM images
     WHERE date(created_at,'unixepoch','localtime') = date('now','localtime')
     AND ( (owner_id IS NOT NULL AND owner_id = COALESCE(?, owner_id)) OR (owner_id IS NULL AND ip = ?) )`
    ).bind(ref.user_id ?? null, ref.ip).first<{ c: number }>();
}

export async function lastUploadAt(env: Env, ref: { user_id?: string; ip: string }) {
    return env.DB.prepare(
        `SELECT MAX(created_at) as ts FROM images
     WHERE ( (owner_id IS NOT NULL AND owner_id = COALESCE(?, owner_id)) OR (owner_id IS NULL AND ip = ?) )`
    ).bind(ref.user_id ?? null, ref.ip).first<{ ts: number }>();
}

export async function getImageById(env: Env, id: string) {
    return env.DB.prepare("SELECT * FROM images WHERE id=?").bind(id).first();
}

export async function deleteImageRecord(env: Env, id: string) {
    return env.DB.prepare("DELETE FROM images WHERE id=?").bind(id).run();
}

export async function listImagesByOwner(env: Env, owner_id: string, limit = 100, offset = 0) {
    return env.DB.prepare(
        "SELECT * FROM images WHERE owner_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?"
    ).bind(owner_id, limit, offset).all();
}

export async function adminListUsers(env: Env, q?: string, limit = 50, offset = 0) {
    if (limit > 200) limit = 200;
    if (offset < 0) offset = 0;
    const hasQ = !!q;
    const like = hasQ ? `%${q}%` : null;
    const rows = hasQ
        ? await env.DB.prepare(
            "SELECT id,email,username,role,disabled,created_at FROM users WHERE email LIKE ? OR username LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ).bind(like, like, limit, offset).all()
        : await env.DB.prepare(
            "SELECT id,email,username,role,disabled,created_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ).bind(limit, offset).all();
    let total: number;
    const countNeeded = hasQ || (rows.results || []).length === limit || offset > 0;
    if (!countNeeded) {
        total = (rows.results || []).length;
    } else {
        total = hasQ
            ? ((await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE email LIKE ? OR username LIKE ?").bind(like, like).first<{ c: number }>())?.c || 0)
            : ((await env.DB.prepare("SELECT COUNT(*) as c FROM users").first<{ c: number }>())?.c || 0);
    }
    return { results: rows.results || [], total };
}

export async function setUserDisabled(env: Env, id: string, disabled: boolean) {
    return env.DB.prepare("UPDATE users SET disabled=? WHERE id=?").bind(disabled ? 1 : 0, id).run();
}

export async function createAudit(env: Env, o: {
    type: string; user_id?: string; ip: string; meta?: string;
}) {
    return env.DB.prepare(
        "INSERT INTO audit_logs (type,user_id,ip,meta,created_at) VALUES (?,?,?,?,strftime('%s','now'))"
    ).bind(o.type, o.user_id ?? null, o.ip, o.meta ?? null).run();
}

export async function scheduleForDeletion(env: Env, nowSec: number) {
    const FIFTEEN_DAYS = 15 * 24 * 60 * 60;
    const cutoff = nowSec - FIFTEEN_DAYS;
    return await env.DB.prepare(
        `SELECT id,key FROM images
             WHERE (auto_delete_at IS NOT NULL AND auto_delete_at <= ?)
                OR (owner_id IS NULL AND COALESCE(last_access_at, created_at) <= ?)
             LIMIT 500`
    ).bind(nowSec, cutoff).all();
}

// --- Role policies ---
export interface RolePolicy { role: string; label: string | null; daily: number | null; cooldown_sec: number | null; auto_delete_sec: number | null; }

export async function getAllRolePolicies(env: Env): Promise<RolePolicy[]> {
    const rows = await env.DB.prepare("SELECT role,label,daily,cooldown_sec,auto_delete_sec FROM role_policies ORDER BY role").all<RolePolicy>();
    return rows.results || [];
}

export async function getRolePolicy(env: Env, role: string): Promise<RolePolicy | null> {
    const row = await env.DB.prepare("SELECT role,label,daily,cooldown_sec,auto_delete_sec FROM role_policies WHERE role=?").bind(role).first<RolePolicy>();
    return row || null;
}

export async function upsertRolePolicy(env: Env, p: { role: string; label?: string | null; daily: number | null; cooldown_sec: number | null; auto_delete_sec: number | null; }) {
    await env.DB.prepare(`INSERT INTO role_policies (role,label,daily,cooldown_sec,auto_delete_sec,updated_at) VALUES (?,?,?,?,?,strftime('%s','now'))
        ON CONFLICT(role) DO UPDATE SET label=excluded.label,daily=excluded.daily,cooldown_sec=excluded.cooldown_sec,auto_delete_sec=excluded.auto_delete_sec,updated_at=excluded.updated_at`).bind(p.role, p.label ?? null, p.daily, p.cooldown_sec, p.auto_delete_sec).run();
}