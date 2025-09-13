// Utils propres (quotas dynamiques + helpers)
import { countUploadsToday, lastUploadAt, deleteImageRecord, scheduleForDeletion } from './db';
import { logDiscord } from './discord';
import { Env } from './env';
import { getSession } from './sessions';

// Constantes
export const AVATAR_COOLDOWN_SEC = 30;
export const PBKDF2_ITERATIONS = 100_000;
export const SESSION_TTL_HOURS = 72;
export const LOGIN_WINDOW_SEC = 15 * 60;
export const LOGIN_FAIL_THRESHOLD = 5;
export const IP_BLOCK_SCORE_CAP = 1000;

// Time helpers
export const now = () => Date.now();
export const nowSec = () => Math.floor(Date.now() / 1000);
export const days = (n: number) => n * 86_400_000;
export const seconds = (n: number) => n * 1000;

// JSON / parsing
export function JSONResponse(obj: unknown, status = 200, headers?: Record<string, string>) {
    const base: Record<string, string> = { 'content-type': 'application/json; charset=utf-8' };
    if (headers) for (const [k, v] of Object.entries(headers)) base[k.toLowerCase()] = v;
    return new Response(JSON.stringify(obj), { status, headers: base });
}
export function safeJsonParse<T = any>(txt: string | null | undefined, fallback: T): T { if (!txt) return fallback; try { return JSON.parse(txt) as T; } catch { return fallback; } }

// IDs aléatoires
const ALPH = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ALPH_LEN = ALPH.length;
export function randomId(len = 10): string { const arr = crypto.getRandomValues(new Uint8Array(len)); const out = new Array(len); for (let i = 0; i < len; i++) out[i] = ALPH[arr[i] % ALPH_LEN]; return out.join(''); }

// Réseau
export function getClientIp(req: Request) { return req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || '0.0.0.0'; }
export function getUA(req: Request) { return req.headers.get('user-agent') || 'unknown'; }

// Extensions images
const IMAGE_TYPE_EXT: Record<string, string> = { 'image/png': '.png', 'image/webp': '.webp', 'image/avif': '.avif', 'image/jpeg': '.jpg' };
const ALLOWED_FILE_EXT = new Set(['png', 'webp', 'avif', 'jpg', 'jpeg']);
export function getExtFromType(type: string, filename?: string): string { if (filename) { const m = filename.toLowerCase().match(/\.([a-z0-9]+)$/); if (m && ALLOWED_FILE_EXT.has(m[1])) { if (m[1] === 'jpeg') return '.jpg'; return '.' + m[1]; } } return IMAGE_TYPE_EXT[type] || ''; }

// Admin
export async function requireAdminGlobal(env: Env, req: Request) { const s = await getSession(env, req); if (!s?.user_id) return null; const ur = await env.DB.prepare('SELECT role FROM users WHERE id=?').bind(s.user_id).first() as { role?: string } | null; return ur?.role === 'admin' ? s : null; }

// Codes erreurs
export enum ErrorCode { ACCESS_BLOCKED = 'access_blocked', QUOTA_DAILY = 'quota_daily', QUOTA_COOLDOWN = 'quota_cooldown', QUOTA_GENERIC = 'quota_generic', UPLOAD_MISSING_FILE = 'upload_missing_file', UPLOAD_UNSUPPORTED_TYPE = 'upload_unsupported_type', UPLOAD_UNKNOWN_EXTENSION = 'upload_unknown_extension', UPLOAD_FAILED = 'upload_failed', AUTH_REQUIRED = 'auth_required', FORBIDDEN = 'forbidden', NOT_FOUND = 'not_found', INVALID_DATA = 'invalid_data', AVATAR_COOLDOWN = 'avatar_cooldown', PASSWORD_INVALID_CURRENT = 'password_invalid_current' }
export function apiError(code: ErrorCode, http: number, message: string, extra?: Record<string, unknown>) { return JSONResponse({ error: message, code, ...(extra || {}) }, http); }

// Cooldown avatar via audit_logs fallback
export async function checkAvatarCooldown(env: Env, userId: string, cooldown: number) { const n = nowSec(); const last = await env.DB.prepare("SELECT created_at FROM audit_logs WHERE user_id=? AND type IN ('User avatar updated','User avatar removed') ORDER BY created_at DESC, id DESC LIMIT 1").bind(userId).first(); if (last) { const createdAt = Number((last as any).created_at) || 0; const diff = n - createdAt; if (diff < cooldown) return { ok: false, wait: cooldown - diff }; } return { ok: true } as const; }

// Validators
export const validateEmail = (e: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
export const validatePassword = (p: string) => typeof p === 'string' && p.length >= 8;
export const validateCaptcha = (a: string, expect: string) => a && expect && a.trim() === expect.trim();
export const validateUsername = (u: string) => /^[A-Za-z][A-Za-z0-9_]{2,31}$/.test(u);

// Upload parsing
export interface ParsedUploadOk { ok: true; buf: ArrayBuffer; contentType: string; filename?: string; }
export interface ParsedUploadErr { ok: false; error: string; status?: number; }
export type ParsedUpload = ParsedUploadOk | ParsedUploadErr;
function parseFormDataFilename(cd?: string | null): string | null { if (!cd) return null; const m = cd.match(/filename="?([^";]+)"?/i); return m ? m[1] : null; }
export async function parseIncomingImage(req: Request): Promise<ParsedUpload> { const ctype = req.headers.get('content-type') || ''; try { if (ctype.startsWith('multipart/form-data')) { const fd = await req.formData(); const file = fd.get('file'); if (!(file instanceof File)) return { ok: false, error: 'Missing file', status: 400 }; const buf = await file.arrayBuffer(); const fallback = parseFormDataFilename(req.headers.get('content-disposition')); const filename = (file.name && file.name !== 'blob') ? file.name : fallback || undefined; return { ok: true, buf, contentType: file.type, filename }; } if (ctype === 'application/json') { const body: any = await req.json().catch(() => ({})); if (!body.url) return { ok: false, error: 'Invalid data', status: 400 }; const remote = await fetch(String(body.url)); if (!remote.ok) return { ok: false, error: 'Download failed', status: 400 }; const contentType = remote.headers.get('content-type') || ''; const buf = await remote.arrayBuffer(); let filename: string | undefined; try { filename = new URL(String(body.url)).pathname.split('/').pop() || undefined; } catch { } return { ok: true, buf, contentType, filename }; } return { ok: false, error: 'Unsupported type', status: 415 }; } catch { return { ok: false, error: 'Upload parse error', status: 400 }; } }

// Réponses helpers
export interface ResponseHelpers { requestId: string; json: (obj: any, status?: number, headers?: Record<string, string>) => Response; auditMeta: (extra?: any) => string; }
export function responseHelpers(existingRequestId?: string): ResponseHelpers { const requestId = existingRequestId || randomId(12); function json(obj: any, status = 200, headers?: Record<string, string>) { const h = Object.assign({}, headers || {}); h['x-request-id'] = requestId; return JSONResponse(obj, status, h); } function auditMeta(extra?: any) { try { if (extra && typeof extra === 'object') return JSON.stringify({ ...extra, request_id: requestId }); } catch { } return JSON.stringify({ request_id: requestId }); } return { requestId, json, auditMeta }; }

// R2
export async function putImage(env: Env, key: string, body: ArrayBuffer | ReadableStream, type: string) { await env.R2.put(key, body, { httpMetadata: { contentType: type }, customMetadata: { key } }); }
export const getImage = (env: Env, key: string) => env.R2.get(key);
export const deleteImageR2 = (env: Env, key: string) => env.R2.delete(key);

// Quotas dynamiques
export type QuotaInfo = { role: string; daily: number | null; cooldownSec: number | null; autoDeleteSec: number | null };
const FALLBACK_ROLE_POLICIES: Record<string, { daily: number | null; cooldownSec: number | null; autoDeleteSec: number | null }> = {
    anon: { daily: 10, cooldownSec: 60, autoDeleteSec: 7 * 24 * 60 * 60 }
};
const rolePolicyCache = new Map<string, { p: QuotaInfo; ts: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000;
export function clearRolePolicyCache(role?: string) { if (role) { rolePolicyCache.delete(role); } else { rolePolicyCache.clear(); } }
async function fetchRolePolicy(env: Env, role: string): Promise<QuotaInfo> { const cached = rolePolicyCache.get(role); const nowMs = Date.now(); if (cached && (nowMs - cached.ts) < CACHE_TTL_MS) return cached.p; try { const row = await env.DB.prepare('SELECT daily,cooldown_sec,auto_delete_sec FROM role_policies WHERE role=?').bind(role).first<{ daily: number | null; cooldown_sec: number | null; auto_delete_sec: number | null }>(); if (row) { const p: QuotaInfo = { role: role as any, daily: row.daily, cooldownSec: row.cooldown_sec, autoDeleteSec: row.auto_delete_sec }; rolePolicyCache.set(role, { p, ts: nowMs }); return p; } } catch { } const fb = FALLBACK_ROLE_POLICIES[role] || FALLBACK_ROLE_POLICIES.anon; const p: QuotaInfo = { role: role as any, daily: fb.daily, cooldownSec: fb.cooldownSec, autoDeleteSec: fb.autoDeleteSec }; rolePolicyCache.set(role, { p, ts: nowMs }); return p; }
export const roleQuotasDynamic = (env: Env, role: string) => fetchRolePolicy(env, role);
export async function checkQuota(env: Env, ref: { user_id?: string; ip: string; role: string }) { const quota = await roleQuotasDynamic(env, ref.role); if (quota.daily !== null) { const cRow = await countUploadsToday(env, { user_id: ref.user_id, ip: ref.ip }); if ((cRow?.c ?? 0) >= quota.daily) return { ok: false as const, reason: 'daily', extra: quota.daily }; } if (quota.cooldownSec !== null) { const last = await lastUploadAt(env, { user_id: ref.user_id, ip: ref.ip }); if (last?.ts) { const diff = nowSec() - last.ts; if (diff < quota.cooldownSec) return { ok: false as const, reason: 'cooldown', extra: quota.cooldownSec - diff }; } } return { ok: true as const, q: quota }; }

// IP blocks
const MAX_SCORE = 100; const DECAY = 10;
export async function bumpIpScore(env: Env, ip: string, delta = 5) { await env.DB.prepare(`INSERT INTO ip_blocks (ip, score, updated_at) VALUES (?, ?, strftime('%s','now')) ON CONFLICT(ip) DO UPDATE SET score = MIN(score + excluded.score, ${IP_BLOCK_SCORE_CAP}), updated_at = excluded.updated_at`).bind(ip, delta).run(); }
export async function getIpScore(env: Env, ip: string) { const row = await env.DB.prepare('SELECT score FROM ip_blocks WHERE ip=?').bind(ip).first<{ score: number }>(); return row?.score ?? 0; }
export async function isIpBlocked(env: Env, ip: string) { return (await getIpScore(env, ip)) >= MAX_SCORE; }
export async function decayIpScores(env: Env) { await env.DB.prepare("UPDATE ip_blocks SET score = MAX(score - ?, 0), updated_at = strftime('%s','now')").bind(DECAY).run(); }

// Cleanup planifié
export async function runCleanup(env: Env) { const started = nowSec(); const list = await scheduleForDeletion(env, nowSec()); let deleted = 0; if (list && 'results' in list) { for (const row of (list as any).results as any[]) { try { await deleteImageR2(env, row.key); await deleteImageRecord(env, row.id); await logDiscord(env, 'Auto delete image', { id: row.id, key: row.key }); deleted++; } catch (err) { await logDiscord(env, 'Cleanup error', { id: row.id, error: String(err) }); } } } await decayIpScores(env); let captchaPurged = 0; try { const delRes = await env.DB.prepare("DELETE FROM captcha_challenges WHERE expires_at < strftime('%s','now')").run(); captchaPurged = (delRes as any)?.meta?.changes || 0; } catch { } const finished = nowSec(); try { await env.DB.prepare('INSERT INTO maintenance_runs (task,started_at,finished_at,status,items,meta) VALUES (?,?,?,?,?,?)').bind('cleanup', started, finished, 'ok', deleted, JSON.stringify({ ip_decay: true, captcha_purged: captchaPurged })).run(); } catch { } if (captchaPurged > 0) { try { await logDiscord(env, 'Captcha purge', { purged: captchaPurged }); } catch { } } }

// Captcha
export async function createCaptcha(env: Env, answer: string) { const token = randomId(32); const expires = nowSec() + 5 * 60; const answerHash = await hashAnswer(env, token, answer); await env.DB.prepare("INSERT INTO captcha_challenges (token, answer_hash, expires_at, created_at) VALUES (?,?,?,strftime('%s','now'))").bind(token, answerHash, expires).run(); return { token }; }
export async function verifyCaptcha(env: Env, token: string, answer: string) { if (!token || !answer) return false; const row = await env.DB.prepare('SELECT answer_hash, expires_at FROM captcha_challenges WHERE token=?').bind(token).first<{ answer_hash: string; expires_at: number }>(); if (!row) return false; if (row.expires_at < nowSec()) { await env.DB.prepare('DELETE FROM captcha_challenges WHERE token=?').bind(token).run(); return false; } const got = await hashAnswer(env, token, answer); const ok = timingSafeEqual(row.answer_hash, got); await env.DB.prepare('DELETE FROM captcha_challenges WHERE token=?').bind(token).run(); return ok; }
async function hashAnswer(env: Env, token: string, answer: string) { const data = new TextEncoder().encode(`${token}|${answer}|${env.COOKIE_SECRET}`); const buf = await crypto.subtle.digest('SHA-256', data); return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function timingSafeEqual(a: string, b: string) { if (a.length !== b.length) return false; let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i); return diff === 0; }

// Regex communs & helpers DB light
export const REGEX_IMAGE_ID_EXT = /^([A-Za-z0-9]+)\.([a-z0-9]+)$/;
export const REGEX_FINGERPRINT_CSS = /\.[a-f0-9]{8,}\.css$/i;
export const REGEX_FINGERPRINT_JS = /\.[a-f0-9]{8,}\.js$/i;
export async function dbOne<T = any>(env: any, sql: string, ...params: any[]): Promise<T | null> { return (await env.DB.prepare(sql).bind(...params).first()) as T | null; }
export async function dbAll<T = any>(env: any, sql: string, ...params: any[]): Promise<{ results: T[] }> { return (await env.DB.prepare(sql).bind(...params).all()) as { results: T[] }; }