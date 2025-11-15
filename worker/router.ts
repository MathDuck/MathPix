import { Env } from "./env.d";
import { listBackups, performDbBackup } from "./backup";
import { getClientIp, getExtFromType, randomId, requireAdminGlobal, apiError, ErrorCode, checkAvatarCooldown, checkQuota, parseIncomingImage, putImage, getImage, deleteImageR2, isIpBlocked, createCaptcha, bumpIpScore, runCleanup, validateEmail, validatePassword, roleQuotasDynamic, AVATAR_COOLDOWN_SEC, PBKDF2_ITERATIONS, responseHelpers, clearRolePolicyCache } from "./utils";
import { translate } from "./i18n";
import { optimizeLossless } from "./image_opt";
import { sendEmail } from "./email";
import { getSession } from "./sessions";
import { handleRegister, handleLogin, handleLogout, handlePasswordResetConfirm, handlePasswordResetRequest } from "./auth";
import { createAudit, createImage, deleteImageRecord, getImageById, listImagesByOwner, setUserDisabled, adminListUsers, bumpUserStatsOnUpload, bumpUserStatsOnDelete, getAllRolePolicies, upsertRolePolicy } from "./db";
import { logDiscord } from "./discord";
import { authFromApiToken } from "./auth_api";
import { setUserAvatar, setUserEmailRequest, consumeEmailChange, changePassword, userInfo, userStats } from "./db.user";
import { refreshApiToken, hasApiToken, revokeApiToken, getApiTokenMeta, getApiTokenPlain } from "./db.tokens";

async function getAuth(env: Env, req: Request) {
    if (!(req as any)._roleCache) (req as any)._roleCache = {};
    const cache = (req as any)._roleCache as { role?: string; user_id?: string };
    if (cache.role) return cache;
    const session = await getSession(env, req);
    if (session?.user_id) {
        const userRoleRow = await env.DB.prepare("SELECT role FROM users WHERE id=?").bind(session.user_id).first<{ role: string }>();
        cache.user_id = session.user_id;
        cache.role = (userRoleRow?.role ?? 'user');
        return cache as any;
    }
    const apiAuth = await authFromApiToken(env, req);
    if (apiAuth) { cache.user_id = apiAuth.user_id; cache.role = apiAuth.role; return cache as any; }
    cache.role = 'anon';
    return cache as any;
}

function simpleMath() {
    const left = Math.floor(Math.random() * 9) + 1;
    const right = Math.floor(Math.random() * 9) + 1;
    return { prompt: `${left} + ${right} = ?`, answer: String(left + right) };
}

export async function route(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const clientIp = getClientIp(req);
    function baseUrlForRequest(): string {
        const configured = (env.BASE_URL && /^https?:\/\//.test(env.BASE_URL)) ? env.BASE_URL.replace(/\/$/, '') : null;
        if (/^(localhost|127\.|0\.0\.0\.0)/i.test(url.hostname)) return `${url.protocol}//${url.host}`;
        if (configured) {
            try {
                const cfgHost = new URL(configured).host;
                return (url.host === cfgHost) ? configured : `${url.protocol}//${url.host}`;
            } catch { /* fallthrough */ }
        }
        return `${url.protocol}//${url.host}`;
    }
    const base = baseUrlForRequest();
    const { requestId, json, auditMeta } = responseHelpers();

    const __usernameCache: Record<string, string | null> = {};
    async function getUsernameCached(id?: string | null): Promise<string | null> {
        if (!id) return null; if (id in __usernameCache) return __usernameCache[id];
        try { const row = await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(id).first<{ username: string | null }>(); __usernameCache[id] = row?.username || null; return __usernameCache[id]; } catch { __usernameCache[id] = null; return null; }
    }
    async function logDiscordUser(title: string, user_id: string | undefined | null, fields: Record<string, any> = {}, opts?: { description?: string }) {
        const username = await getUsernameCached(user_id || undefined);
        await logDiscord(env, title, { user_id, username, ...fields }, opts);
    }

    async function maintAudit(type: string, meta: Record<string, any>, userId?: string | null) {
        const payload = { ...meta, request_id: requestId };
        try { await createAudit(env, { type: `maint_${type}`, user_id: userId || undefined, ip: clientIp, meta: JSON.stringify(payload) }); } catch { }
        try { await logDiscord(env, `Maintenance ${type}`, { user_id: userId, requestId, ...meta }); } catch { }
    }

    async function requireSessionUser() {
        const s = await getSession(env, req);
        return (s?.user_id) ? s : null;
    }


    if (await isIpBlocked(env, clientIp)) {
        await logDiscord(env, "IP blocked request", { ip: clientIp, path, requestId });
        return apiError(ErrorCode.ACCESS_BLOCKED, 403, translate('access.blocked'));
    }

    if (req.method === "GET" && path === "/api/session") {
        const session = await getSession(env, req);
        let sessionRole: string = "anon";
        if (session?.user_id) {
            const userRow = await env.DB.prepare("SELECT id,email,username,created_at,avatar_key,role FROM users WHERE id=?").bind(session.user_id).first<any>();
            if (!userRow) {
                const quotasAnon = await roleQuotasDynamic(env, 'anon');
                const labAnon = await env.DB.prepare('SELECT label FROM role_policies WHERE role=?').bind('anon').first<{ label: string | null }>().catch(() => null);
                return json({ role: "anon", role_label: labAnon?.label || null, quotas: quotasAnon, user_id: null });
            }
            sessionRole = userRow.role || "user";
            const quotas = await roleQuotasDynamic(env, sessionRole);
            const avatar_url = userRow?.avatar_key ? `/a/${userRow.avatar_key.split('/').pop()}` : null;
            let label: string | null = null; try { const r = await env.DB.prepare('SELECT label FROM role_policies WHERE role=?').bind(sessionRole).first<{ label: string | null }>(); label = r?.label || null; } catch { }
            return json({ role: sessionRole, role_label: label, quotas, user_id: session.user_id, email: userRow?.email, username: userRow?.username, created_at: userRow?.created_at ? userRow.created_at * 1000 : null, avatar_url });
        }
        const q = await roleQuotasDynamic(env, sessionRole);
        let label: string | null = null; try { const r = await env.DB.prepare('SELECT label FROM role_policies WHERE role=?').bind(sessionRole).first<{ label: string | null }>(); label = r?.label || null; } catch { }
        return json({ role: sessionRole, role_label: label, quotas: q, user_id: null });
    }

    if (req.method === "GET" && path === "/api/captcha") {
        const math = simpleMath();
        const captchaRecord = await createCaptcha(env, math.answer);
        return json({ prompt: math.prompt, token: captchaRecord.token });
    }

    if (req.method === "POST" && path === "/api/register") {
        const body: any = await req.clone().json().catch(() => ({}));
        const captchaToken = body.captchaToken || body.token || body.expect || ""; // token only (answer stored server side)
        return handleRegister(req, env, captchaToken);
    }
    if (req.method === "POST" && path === "/api/login") {
        return handleLogin(req, env);
    }
    if (req.method === "POST" && path === "/api/logout") {
        return handleLogout(req, env);
    }
    if (req.method === "POST" && path === "/api/password/reset/request") {
        return handlePasswordResetRequest(req, env);
    }
    if (req.method === "POST" && path === "/api/password/reset/confirm") {
        return handlePasswordResetConfirm(req, env);
    }
    if (req.method === "POST" && path === "/api/upload") {
        const auth = await getAuth(env, req);
        const role = auth.role;
        const user_id = auth.user_id;
        const hasBearer = (req.headers.get('authorization') || '').toLowerCase().startsWith('bearer ');
        const quotas = await checkQuota(env, { user_id, ip: clientIp, role });
        if (!quotas.ok) {
            await bumpIpScore(env, clientIp, 2);
            await createAudit(env, { type: "quota_block", user_id, ip: clientIp, meta: JSON.stringify({ reason: quotas.reason, extra: quotas.extra }) });
            if (quotas.reason === "daily") return apiError(ErrorCode.QUOTA_DAILY, 429, translate('quota.daily'), { limit: quotas.extra });
            if (quotas.reason === "cooldown") return apiError(ErrorCode.QUOTA_COOLDOWN, 429, translate('quota.cooldown'), { wait: quotas.extra });
            return apiError(ErrorCode.QUOTA_GENERIC, 429, translate('quota.limit'));
        }
        const parsed = await parseIncomingImage(req);
        if (!parsed.ok) {
            const perr = parsed as any as { ok: false; error: string; status?: number };
            const status = perr.status || 400;
            const code = status === 415 ? ErrorCode.UPLOAD_UNSUPPORTED_TYPE : ErrorCode.INVALID_DATA;
            return apiError(code, status, perr.error);
        }
        let { buf, contentType, filename } = parsed;
        if (!contentType || !/(image\/png|image\/webp|image\/avif|image\/jpeg)/.test(contentType)) {
            await bumpIpScore(env, clientIp, 3);
            return apiError(ErrorCode.UPLOAD_UNSUPPORTED_TYPE, 415, translate('upload.unsupported_full'));
        }
        const extension = getExtFromType(contentType, filename);
        if (!extension) return apiError(ErrorCode.UPLOAD_UNKNOWN_EXTENSION, 400, translate('upload.unknown_ext'));

        const imageId = randomId(10);
        const key = `images/${imageId}${extension}`;

        try {
            const original_bytes_initial = (buf as ArrayBuffer).byteLength;
            let sizeBytes = original_bytes_initial;
            let optNote: string | undefined; let saved = 0; let original_bytes = original_bytes_initial; let final_bytes = original_bytes_initial;
            if (contentType === 'image/png') {
                const SIX_MB = 6 * 1024 * 1024;
                if (original_bytes_initial > SIX_MB) {
                    const opt = await optimizeLossless(contentType, buf as ArrayBuffer);
                    if (opt && opt.data && opt.optimizedBytes > 0) {
                        original_bytes = opt.originalBytes || original_bytes_initial;
                        if (opt.optimizedBytes <= opt.originalBytes) {
                            if (opt.optimizedBytes < opt.originalBytes) buf = opt.data;
                            final_bytes = (buf as ArrayBuffer).byteLength;
                            saved = original_bytes - final_bytes;
                            optNote = opt.note || 'lossless';
                        }
                    }
                }
            }
            if (final_bytes === original_bytes_initial) final_bytes = (buf as ArrayBuffer).byteLength;
            if (saved <= 0) saved = 0;
            const saved_pct = original_bytes > 0 ? +((saved / original_bytes) * 100).toFixed(2) : 0;
            await putImage(env, key, buf!, contentType);
            const quotaValues = quotas.ok ? quotas.q : null;
            const autoDeleteSec = quotaValues?.autoDeleteSec ?? null;
            const auto_delete_at = autoDeleteSec ? Math.floor(Date.now() / 1000) + autoDeleteSec : null;
            let originalName: string | undefined = filename || undefined;
            if (originalName) {
                originalName = originalName.replace(/[\u0000-\u001F\u007F]/g, '').slice(0, 180);
            }
            await createImage(env, { id: imageId, owner_id: user_id, key, ext: extension, content_type: contentType, size: sizeBytes, ip: clientIp, auto_delete_at: auto_delete_at ?? undefined, original_name: originalName });
            await bumpUserStatsOnUpload(env, user_id, sizeBytes);
            const via_api = hasBearer && !req.headers.get('referer');
            await createAudit(env, { type: "upload", user_id, ip: clientIp, meta: auditMeta({ id: imageId, key, role, original_bytes, final_bytes, saved_bytes: saved, saved_pct, optimization: optNote, via_api }) });
            await logDiscordUser("Image uploaded", user_id, { id: imageId, role, ip: clientIp, original_bytes, final_bytes, saved_bytes: saved, saved_pct, size: sizeBytes, requestId, optimized_saved: saved, via_api });
            return json({ ok: true, id: imageId, url: `/i/${imageId}${extension}`, original_bytes, final_bytes, saved_bytes: saved, saved_pct, via_api });
        } catch (e) {
            await bumpIpScore(env, clientIp, 5);
            return apiError(ErrorCode.UPLOAD_FAILED, 500, translate('upload.failed'));
        }
    }

    if (req.method === "GET" && path.startsWith("/i/")) {
        const shortName = path.slice(3); // id.ext
        const match = /^([A-Za-z0-9]+)\.([a-z0-9]+)$/.exec(shortName);
        if (!match) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const imageId = match[1];
        const img = await getImageById(env, imageId);
        if (!img) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const obj = await getImage(env, (img as any).key as string);
        if (!obj) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const headers = new Headers();
        headers.set("content-type", (img as any).content_type as string);
        headers.set("cache-control", "public, max-age=31536000, immutable");
        try {
            const noTrack = (new URL(req.url)).searchParams.get('no_track') === '1';
            if (!noTrack) {
                (ctx as any)?.waitUntil?.(env.DB.prepare("UPDATE images SET last_access_at=strftime('%s','now') WHERE id=?").bind(imageId).run());
            }
        } catch { }
        return new Response(obj.body, { status: 200, headers });
    }

    if (req.method === "GET" && path === "/api/images") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const list = await listImagesByOwner(env, session.user_id, 100, 0);
        const out = (list.results || []).map((r: any) => ({
            id: r.id,
            url: `/i/${r.id}${r.ext}`,
            created_at: r.created_at,
            auto_delete_at: r.auto_delete_at
        }));
        return json({ images: out });
    }

    if (req.method === 'GET' && path === '/api/admin/image/optim') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const u = new URL(req.url); const id = u.searchParams.get('id');
        if (!id) return apiError(ErrorCode.INVALID_DATA, 400, translate('admin.missing_id'));
        try {
            const pattern = `%"id":"${id}"%`;
            const row = await env.DB.prepare("SELECT meta FROM audit_logs WHERE type='upload' AND meta LIKE ? ORDER BY id DESC LIMIT 1").bind(pattern).first<{ meta: string }>();
            if (!row?.meta) return json({ ok: true, optim: null });
            let metaObj: any = null; try { metaObj = JSON.parse(row.meta); } catch { }
            if (!metaObj) return json({ ok: true, optim: null });
            const original_bytes = metaObj.original_bytes || metaObj.originalBytes || metaObj.orig_size || null;
            const final_bytes = metaObj.final_bytes || metaObj.size || metaObj.finalSize || metaObj.sizeBytes || null;
            const saved_bytes = metaObj.saved_bytes ?? (original_bytes && final_bytes ? original_bytes - final_bytes : null);
            const saved_pct = metaObj.saved_pct ?? (original_bytes && final_bytes && original_bytes > 0 ? +(((original_bytes - final_bytes) / original_bytes) * 100).toFixed(2) : null);
            return json({ ok: true, optim: { original_bytes, final_bytes, saved_bytes, saved_pct } });
        } catch {
            return json({ ok: true, optim: null });
        }
    }

    if (req.method === 'POST' && path === '/api/admin/discord/test') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        let body: any = {}; try { body = await req.clone().json(); } catch { }
        const message: string | undefined = typeof body.message === 'string' && body.message.trim() ? body.message.trim().slice(0, 500) : undefined;
        await logDiscord(env, 'Test webhook', { user_id: s.user_id, requestId, time: Date.now(), has_msg: !!message }, message ? { description: message } : undefined);
        try {
            const nowSec = Math.floor(Date.now() / 1000);
            await env.DB.prepare("INSERT INTO maintenance_runs (task,started_at,finished_at,status,items,meta) VALUES (?,?,?,?,?,?)")
                .bind('discord_test_webhook', nowSec, nowSec, 'ok', 1, JSON.stringify({ request_id: requestId, has_msg: !!message, len: message ? message.length : 0 }))
                .run();
        } catch { }
        return json({ ok: true, note: env.DISCORD_WEBHOOK_URL ? 'Webhook attempted' : 'DISCORD_WEBHOOK_URL missing', message: message || null });
    }

    if (req.method === "DELETE" && path.startsWith("/api/image/")) {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const imageId = path.split("/").pop()!;
        const img = await getImageById(env, imageId);
        if (!img) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const isOwner = img.owner_id && session.user_id === img.owner_id;
        let isAdmin = false;
        if (session.user_id) {
            const userRoleRow = await env.DB.prepare("SELECT role FROM users WHERE id=?").bind(session.user_id).first<{ role: string }>();
            isAdmin = userRoleRow?.role === "admin";
        }
        if (!isOwner && !isAdmin) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        await deleteImageR2(env, (img as any).key as string);
        await deleteImageRecord(env, imageId);
        await bumpUserStatsOnDelete(env, img.owner_id as string | undefined, (img as any).size as number | undefined);
        await createAudit(env, { type: "delete_image", user_id: session.user_id, ip: clientIp, meta: auditMeta({ id: imageId }) });
        await createAudit(env, { type: "delete_image", user_id: session.user_id, ip: clientIp, meta: auditMeta({ id: imageId }) });
        await logDiscordUser("Image deleted", session.user_id, { id: imageId, by: session.user_id, requestId });
        return json({ ok: true });
    }

    // --- ADMIN ---
    if (req.method === "GET" && path === "/api/admin/users") {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const u = new URL(req.url);
        const q = u.searchParams.get("q") || undefined;
        const limit = Math.min(parseInt(u.searchParams.get("limit") || "50", 10) || 50, 200);
        const page = Math.max(parseInt(u.searchParams.get("page") || "1", 10) || 1, 1);
        const offset = (page - 1) * limit;
        const res = await adminListUsers(env, q, limit, offset);
        return json({ users: res.results, total: res.total, page, limit, pages: Math.ceil(res.total / limit) });
    }

    // --- ROLE POLICIES ---
    if (req.method === 'GET' && path === '/api/admin/role-policies') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const rows = await getAllRolePolicies(env);
        return json({ policies: rows });
    }
    if (req.method === 'POST' && path === '/api/admin/role-policies') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        let body: any = {}; try { body = await req.json(); } catch { }
        const role: string = (body.role || '').trim();
        const label: string | null = body.label && typeof body.label === 'string' ? body.label.trim().slice(0, 40) : null;
        if (!role || /[^a-z0-9_\-]/i.test(role) || role.length > 32) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        if (['anon', 'admin'].includes(role)) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        function norm(val: any) {
            if (val === null || val === undefined || val === '') return null;
            const n = Number(val);
            if (!Number.isFinite(n)) return null;
            if (n === -1) return null;
            return n >= 0 ? n : null;
        }
        const daily = norm(body.daily);
        const cooldown_sec = norm(body.cooldown_sec);
        const auto_delete_sec = norm(body.auto_delete_sec);
        await upsertRolePolicy(env, { role, label, daily, cooldown_sec, auto_delete_sec });
        clearRolePolicyCache(role);
        await createAudit(env, { type: 'admin_role_policy_upsert', user_id: s.user_id, ip: clientIp, meta: auditMeta({ role, label, daily, cooldown_sec, auto_delete_sec }) });
        return json({ ok: true });
    }

    // Create new role
    if (req.method === 'PUT' && path === '/api/admin/role-policies') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        let body: any = {}; try { body = await req.json(); } catch { }
        const role: string = (body.role || '').trim();
        const label: string | null = body.label && typeof body.label === 'string' ? body.label.trim().slice(0, 40) : null;
        if (!role || /[^a-z0-9_\-]/i.test(role) || role.length > 32) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        if (['anon', 'admin'].includes(role)) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        await upsertRolePolicy(env, { role, label, daily: null, cooldown_sec: null, auto_delete_sec: null });
        clearRolePolicyCache(role);
        await createAudit(env, { type: 'admin_role_policy_create', user_id: s.user_id, ip: clientIp, meta: auditMeta({ role, label }) });
        return json({ ok: true });
    }

    // Delete role (reassign users to 'user')
    if (req.method === 'DELETE' && path.startsWith('/api/admin/role-policies/')) {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const role = decodeURIComponent(path.split('/').pop() || '').trim();
        if (!role) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        if (['anon', 'admin', 'user'].includes(role)) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        try {
            await env.DB.prepare('UPDATE users SET role="user" WHERE role=?').bind(role).run();
            await env.DB.prepare('DELETE FROM role_policies WHERE role=?').bind(role).run();
            clearRolePolicyCache(role);
            await createAudit(env, { type: 'admin_role_policy_delete', user_id: s.user_id, ip: clientIp, meta: auditMeta({ role, reassigned_to: 'user' }) });
            return json({ ok: true });
        } catch (e) {
            return apiError(ErrorCode.INVALID_DATA, 400, 'Delete failed');
        }
    }

    if (req.method === "GET" && path === "/api/admin/summary") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const ifNoneMatch = req.headers.get('if-none-match');
        const now = Math.floor(Date.now() / 1000);
        const since24h = now - 86400;
        const sinceHour = now - 3600;
        const aggPromise = env.DB.prepare(`
            SELECT
              (SELECT COUNT(*) FROM users) AS users_total,
              (SELECT COUNT(*) FROM users WHERE disabled=1) AS users_disabled,
              (SELECT COUNT(*) FROM images) AS images_total,
              (SELECT COUNT(*) FROM images WHERE created_at >= ?) AS images_24h,
              (SELECT COUNT(*) FROM images WHERE created_at >= ?) AS images_1h,
              (SELECT COALESCE(SUM(size),0) FROM images) AS bytes_total,
              (SELECT COUNT(*) FROM audit_logs WHERE created_at >= ?) AS audit_24h,
              (SELECT COUNT(*) FROM ip_blocks) AS ip_block_count
        `).bind(since24h, sinceHour, since24h).first<{
            users_total: number; users_disabled: number; images_total: number; images_24h: number; images_1h: number; bytes_total: number; audit_24h: number; ip_block_count: number;
        }>();
        const topIpsPromise = env.DB.prepare("SELECT ip, score FROM ip_blocks ORDER BY score DESC LIMIT 5").all<{ ip: string; score: number }>();
        const [agg, topIps] = await Promise.all([aggPromise, topIpsPromise]);
        const recentImages = await env.DB.prepare(`
        SELECT i.id, i.ext, i.size, i.owner_id, i.created_at, i.last_access_at, i.original_name,
               u.username as owner_username, u.role as owner_role
                FROM images i
                LEFT JOIN users u ON u.id = i.owner_id
                ORDER BY i.created_at DESC
                LIMIT 10
        `).all<{ id: string; ext: string; size: number; owner_id: string | null; created_at: number; last_access_at: number | null; original_name: string | null; owner_username: string | null; owner_role: string | null }>();

        const usersTotal = agg?.users_total || 0;
        const usersDisabled = agg?.users_disabled || 0;
        const imagesTotal = agg?.images_total || 0;
        const images24h = agg?.images_24h || 0;
        const images1h = agg?.images_1h || 0;
        const bytesTotal = agg?.bytes_total || 0;
        const audit24h = agg?.audit_24h || 0;
        const ipBlockCount = agg?.ip_block_count || 0;
        const recentList = (recentImages.results || []) as Array<{ id: string; ext: string; size: number; owner_id: string | null; created_at: number; last_access_at: number | null; original_name: string | null; owner_username: string | null; owner_role: string | null }>;
        let viaMap: Record<string, boolean> = {};
        if (recentList.length) {
            const idsCond = recentList.map(r => r.id).filter(Boolean);
            try {
                for (const rid of idsCond) {
                    const pattern = `%"id":"${rid}"%`;
                    const row = await env.DB.prepare("SELECT meta FROM audit_logs WHERE type='upload' AND meta LIKE ? ORDER BY id DESC LIMIT 1").bind(pattern).first<{ meta: string }>();
                    if (row?.meta) {
                        try { const m = JSON.parse(row.meta); if (m && typeof m.via_api === 'boolean') viaMap[rid] = !!m.via_api; } catch { }
                    }
                }
            } catch { /* ignore */ }
        }
        const payloadObj = {
            users: { total: usersTotal, disabled: usersDisabled, active: usersTotal - usersDisabled },
            images: { total: imagesTotal, last24h: images24h, last1h: images1h, bytes_total: bytesTotal },
            audit: { last24h: audit24h },
            ip_blocks: { total: ipBlockCount, top: topIps.results || [] },
            recent_images: recentList.map(r => ({ id: r.id, url: `/i/${r.id}${r.ext}`, ext: r.ext, size: r.size, owner_id: r.owner_id, owner_username: r.owner_username, owner_role: r.owner_role, created_at: r.created_at, last_access_at: (r as any).last_access_at ?? null, original_name: (r as any).original_name || null, via_api: viaMap[r.id] || false })),
            generated_at: now
        };
        const body = JSON.stringify(payloadObj);
        let etag = 'W/"unknown"';
        try {
            const hashBuf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(body));
            const hashArr = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
            etag = `W/"${hashArr}"`;
        } catch { /* ignore */ }
        if (ifNoneMatch && etag === ifNoneMatch) {
            return new Response(null, { status: 304, headers: { 'etag': etag, 'cache-control': 'no-cache', 'vary': 'accept-encoding, if-none-match' } });
        }
        return new Response(body, { status: 200, headers: { 'content-type': 'application/json; charset=utf-8', 'etag': etag, 'cache-control': 'no-cache', 'vary': 'if-none-match' } });
    }

    // Scheduled tasks (static list for admin visibility)
    if (req.method === 'GET' && path === '/api/admin/scheduled') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const tasks = [
            { name: 'cleanup', cron: '0 * * * *', desc: 'Nettoyage périodique (sessions / tokens / auto delete images)', intervalMin: 60 },
            { name: 'decay_ip_scores', cron: '*/15 * * * *', desc: 'Décroissance scores IP', intervalMin: 15 },
            { name: 'purge_old_logs', cron: '30 3 * * *', desc: 'Purge des logs anciens', intervalMin: 1440 },
        ];
        const nowMs = Date.now();
        function nextRun(ts: number, intervalMin: number): number { return ts + intervalMin * 60000; }
        const list = tasks.map(t => ({ ...t, next_run_ts: Math.floor(nextRun(nowMs, t.intervalMin) / 1000) }));
        return json({ tasks: list, generated_at: Math.floor(nowMs / 1000) });
    }

    if (req.method === "POST" && path === "/api/admin/user/disable") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const { user_id, disabled }: any = await req.json();
        await setUserDisabled(env, user_id, !!disabled);
        await createAudit(env, { type: "disable_user", user_id: s.user_id, ip: clientIp, meta: auditMeta({ target: user_id, disabled }) });
        const targetUsername = await getUsernameCached(user_id);
        await logDiscordUser("Admin toggled user", s.user_id, { target: user_id, target_username: targetUsername, disabled, requestId });
        return json({ ok: true });
    }

    if (req.method === "POST" && path === "/api/admin/user/role") {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const { user_id, role }: any = await req.json();
        if (typeof role !== 'string' || !role.trim()) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        const roleRow = await env.DB.prepare('SELECT role FROM role_policies WHERE role=?').bind(role).first<{ role: string }>();
        if (!roleRow) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        await env.DB.prepare("UPDATE users SET role=? WHERE id=?").bind(role, user_id).run();
        const changedUsername = await getUsernameCached(user_id);
        await logDiscordUser("Admin changed role", s.user_id, { user_id, username_target: changedUsername, role, requestId });
        await createAudit(env, { type: "admin_changed_role", user_id: s.user_id, ip: clientIp, meta: auditMeta({ target: user_id, role }) });
        return json({ ok: true });
    }

    if (req.method === "GET" && path === "/api/admin/images") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const u = new URL(req.url);
        const owner = u.searchParams.get("owner") || undefined;
        const idLike = u.searchParams.get("id") || undefined;
        const ownerUsername = u.searchParams.get("username") || undefined;
        const limit = Math.min(parseInt(u.searchParams.get("limit") || "50", 10) || 50, 200);
        const page = Math.max(parseInt(u.searchParams.get("page") || "1", 10) || 1, 1);
        const offset = (page - 1) * limit;
        const rows = await env.DB.prepare(
            `SELECT i.id, i.owner_id, u.username as owner_username, u.role as owner_role, i.ext, i.content_type, i.size, i.created_at, i.last_access_at, i.auto_delete_at, i.original_name
                         FROM images i
                         LEFT JOIN users u ON u.id = i.owner_id
                         WHERE 1=1
                             AND (? IS NULL OR i.owner_id = ?)
                             AND (? IS NULL OR i.id LIKE ?)
                             AND (? IS NULL OR (u.username IS NOT NULL AND u.username LIKE ?))
                         ORDER BY i.created_at DESC
                         LIMIT ? OFFSET ?`
        ).bind(
            owner ?? null, owner ?? null,
            idLike ? `%${idLike}%` : null, idLike ? `%${idLike}%` : null,
            ownerUsername ? `%${ownerUsername}%` : null, ownerUsername ? `%${ownerUsername}%` : null,
            limit, offset
        ).all();
        const total = (await env.DB.prepare(
            `SELECT COUNT(*) as c FROM images i LEFT JOIN users u ON u.id = i.owner_id WHERE 1=1
               AND (? IS NULL OR i.owner_id = ?)
               AND (? IS NULL OR i.id LIKE ?)
               AND (? IS NULL OR (u.username IS NOT NULL AND u.username LIKE ?))`
        ).bind(
            owner ?? null, owner ?? null,
            idLike ? `%${idLike}%` : null, idLike ? `%${idLike}%` : null,
            ownerUsername ? `%${ownerUsername}%` : null, ownerUsername ? `%${ownerUsername}%` : null
        ).first<{ c: number }>())?.c || 0;
        const list = rows.results || [];
        const viaMap: Record<string, boolean> = {};
        for (const r of list) {
            try {
                const rid = String((r as any).id);
                const pattern = `%"id":"${rid}"%`;
                const row = await env.DB.prepare("SELECT meta FROM audit_logs WHERE type='upload' AND meta LIKE ? ORDER BY id DESC LIMIT 1").bind(pattern).first<{ meta: string }>();
                if (row?.meta) { try { const m = JSON.parse(row.meta); if (typeof m.via_api === 'boolean') viaMap[rid] = !!m.via_api; } catch { } }
            } catch { }
        }
        const out = list.map(r => { const rid = String((r as any).id); return { ...r, via_api: viaMap[rid] || false }; });
        return json({ images: out, total, page, limit, pages: Math.ceil(total / limit) });
    }

    // Source (via_api) pour une image (admin uniquement)
    if (req.method === 'GET' && path === '/api/admin/image/source') {
        const s = await requireAdminGlobal(env, req); if (!s) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const urlObj = new URL(req.url);
        const id = urlObj.searchParams.get('id');
        if (!id) return apiError(ErrorCode.INVALID_DATA, 400, translate('admin.missing_id'));
        try {
            const pattern = `%"id":"${id}"%`;
            const row = await env.DB.prepare("SELECT meta FROM audit_logs WHERE type='upload' AND meta LIKE ? ORDER BY id DESC LIMIT 1").bind(pattern).first<{ meta: string }>();
            if (!row?.meta) return json({ ok: true, via_api: false });
            try { const m = JSON.parse(row.meta); return json({ ok: true, via_api: !!m.via_api }); } catch { return json({ ok: true, via_api: false }); }
        } catch { return json({ ok: true, via_api: false }); }
    }

    if (req.method === "GET" && path === "/api/admin/ipblocks") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const u = new URL(req.url);
        const limit = Math.min(parseInt(u.searchParams.get("limit") || "50", 10) || 50, 200);
        const page = Math.max(parseInt(u.searchParams.get("page") || "1", 10) || 1, 1);
        const offset = (page - 1) * limit;
        const rows = await env.DB.prepare("SELECT ip, score, updated_at FROM ip_blocks ORDER BY score DESC LIMIT ? OFFSET ?").bind(limit, offset).all();
        const total = (await env.DB.prepare("SELECT COUNT(*) as c FROM ip_blocks").first<{ c: number }>())?.c || 0;
        return json({ ips: rows.results || [], total, page, limit, pages: Math.ceil(total / limit) });
    }
    if (req.method === "POST" && path === "/api/admin/ipblocks/set") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const { ip: ipAddr, score }: any = await req.json();
        await env.DB.prepare(
            "INSERT INTO ip_blocks (ip,score,updated_at) VALUES (?,?,strftime('%s','now')) ON CONFLICT(ip) DO UPDATE SET score=?, updated_at=strftime('%s','now')"
        ).bind(ipAddr, score, score).run();
        await logDiscordUser("Admin set IP score", s.user_id, { ip: ipAddr, score, requestId });
        await createAudit(env, { type: "admin_set_ip_score", user_id: s.user_id, ip: clientIp, meta: auditMeta({ target_ip: ipAddr, score }) });
        return json({ ok: true });
    }

    if (req.method === "GET" && path === "/api/admin/logs") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const u = new URL(req.url);
        const q = u.searchParams.get("q") || "";
        const limit = Math.min(parseInt(u.searchParams.get("limit") || "20", 10) || 20, 200);
        const page = Math.max(parseInt(u.searchParams.get("page") || "1", 10) || 1, 1);
        const offset = (page - 1) * limit;
        const rows = await env.DB.prepare(
            `SELECT a.id, a.type, a.user_id, u.username as user_username, a.ip, a.meta, a.created_at
             FROM audit_logs a
             LEFT JOIN users u ON u.id = a.user_id
             WHERE a.type LIKE ? OR a.user_id LIKE ? OR (u.username IS NOT NULL AND u.username LIKE ?)
             ORDER BY a.id DESC
             LIMIT ? OFFSET ?`
        ).bind(`%${q}%`, `%${q}%`, `%${q}%`, limit, offset).all();
        const total = (await env.DB.prepare(
            `SELECT COUNT(*) as c
             FROM audit_logs a
             LEFT JOIN users u ON u.id = a.user_id
             WHERE a.type LIKE ? OR a.user_id LIKE ? OR (u.username IS NOT NULL AND u.username LIKE ?)`
        ).bind(`%${q}%`, `%${q}%`, `%${q}%`).first<{ c: number }>())?.c || 0;
        return json({ logs: rows.results || [], total, page, limit, pages: Math.ceil(total / limit) });
    }

    if (req.method === "POST" && path === "/api/admin/cleanup") {
        const s = await requireAdminGlobal(env, req); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const before = await env.DB.prepare("SELECT COUNT(*) as c FROM maintenance_runs WHERE task='cleanup'").first<{ c: number }>();
        await runCleanup(env);
        const last = await env.DB.prepare("SELECT id, items, meta FROM maintenance_runs WHERE task='cleanup' ORDER BY id DESC LIMIT 1").first<{ id: number; items: number; meta: string }>();
        let meta: any = {}; try { meta = last?.meta ? JSON.parse(last.meta) : {}; } catch { }
        await maintAudit('cleanup_manual', { run_id: last?.id, items: last?.items, meta, before_runs: before?.c ?? 0 }, s.user_id);
        return json({ ok: true, run_id: last?.id, items: last?.items });
    }

    // Advanced maintenance
    async function requireAdmin() { return await requireAdminGlobal(env, req); }
    async function recordRun(task: string, fn: () => Promise<{ items?: number; meta?: any } | void>) {
        const started = Math.floor(Date.now() / 1000);
        const ins = await env.DB.prepare("INSERT INTO maintenance_runs (task,started_at,status) VALUES (?,?,?)").bind(task, started, "running").run();
        let id: number | null = (ins as any)?.meta?.last_row_id ?? null;
        if (!id) {
            const row = await env.DB.prepare("SELECT id FROM maintenance_runs WHERE task=? AND started_at=? ORDER BY id DESC LIMIT 1").bind(task, started).first<{ id: number }>();
            id = row?.id ?? null;
        }
        try {
            const r = await fn() || {};
            const finished = Math.floor(Date.now() / 1000);
            if (id !== null) {
                const metaObj = r.meta ? { ...r.meta, request_id: requestId } : { request_id: requestId };
                await env.DB.prepare("UPDATE maintenance_runs SET finished_at=?, status='ok', items=?, meta=? WHERE id=?")
                    .bind(finished, r.items ?? null, JSON.stringify(metaObj), id).run();
            }
            return { ok: true, id, duration: finished - started, ...r };
        } catch (e: any) {
            const finished = Math.floor(Date.now() / 1000);
            if (id !== null) {
                // Support d'un objet Error enrichi avec e.meta pour debug temporaire
                let meta: any = { error: String(e) };
                if (e && typeof e === 'object' && 'meta' in e) {
                    try {
                        meta = { error: String(e.message || e), debug: (e as any).meta, request_id: requestId };
                    } catch { }
                } else {
                    meta.request_id = requestId;
                }
                await env.DB.prepare("UPDATE maintenance_runs SET finished_at=?, status='error', meta=? WHERE id=?")
                    .bind(finished, JSON.stringify(meta), id).run();
                return { ok: false, id, error: String(e), meta };
            }
            return { ok: false, id, error: String(e) };
        }
    }

    if (req.method === 'POST' && path === '/api/admin/maint/purge-sessions') {
        const admin = await requireAdmin(); if (!admin) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const r = await recordRun('purge_sessions', async () => {
            const now2 = Math.floor(Date.now() / 1000);
            const delSess = await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ? RETURNING id").bind(now2).all();
            const sessCount = (delSess.results || []).length;
            const ninety = now2 - 90 * 86400;
            const delTok = await env.DB.prepare("DELETE FROM api_tokens WHERE (last_used_at IS NULL AND created_at < ?) OR (last_used_at IS NOT NULL AND last_used_at < ?) RETURNING id").bind(ninety, ninety).all();
            const tokCount = (delTok.results || []).length;
            return { items: sessCount + tokCount, meta: { sessions: sessCount, api_tokens: tokCount } };
        });
        if (r.ok) await maintAudit('purge_sessions', { run_id: r.id, sessions: (r as any).meta?.sessions, api_tokens: (r as any).meta?.api_tokens, items: (r as any).items ?? (r as any).meta?.items }, admin.user_id);
        return json(r);
    }
    if (req.method === 'POST' && path === '/api/admin/maint/purge-logs') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const body: any = await req.json().catch(() => ({}));
        const days = Math.min(Math.max(parseInt(body.days) || 60, 7), 365);
        const r = await recordRun('purge_logs', async () => {
            const cutoff = Math.floor(Date.now() / 1000) - days * 86400;
            const del = await env.DB.prepare("DELETE FROM audit_logs WHERE created_at < ? RETURNING id").bind(cutoff).all();
            const n = (del.results || []).length;
            return { items: n, meta: { days, cutoff } };
        });
        if (r.ok) await maintAudit('purge_logs', { run_id: r.id, days, items: (r as any).items ?? (r as any).meta?.items }, admin.user_id);
        return json(r);
    }
    if (req.method === 'POST' && path === '/api/admin/maint/recalc-stats') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const r = await recordRun('recalc_stats', async () => {
            await env.DB.prepare("DELETE FROM users_stats").run();
            const agg2 = await env.DB.prepare(`SELECT owner_id as user_id, COUNT(*) as images_total, COALESCE(SUM(size),0) as bytes_total FROM images WHERE owner_id IS NOT NULL GROUP BY owner_id`).all<{ user_id: string; images_total: number; bytes_total: number }>();
            const now3 = Math.floor(Date.now() / 1000);
            for (const rr of agg2.results || []) {
                await env.DB.prepare("INSERT INTO users_stats (user_id, images_total, images_today, last_upload_at, bytes_total, last_updated_at) VALUES (?,?,?,?,?,?)")
                    .bind(rr.user_id, rr.images_total, 0, null, rr.bytes_total, now3).run();
            }
            return { items: (agg2.results || []).length };
        });
        if (r.ok) await maintAudit('recalc_stats', { run_id: r.id, items: (r as any).items ?? 0 }, admin.user_id);
        return json(r);
    }
    if (req.method === 'GET' && path === '/api/admin/maint/scan-orphans') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const url2 = new URL(req.url);
        const cursor = url2.searchParams.get('cursor') || undefined;
        const limit = Math.min(parseInt(url2.searchParams.get('limit') || '100', 10) || 100, 500);
        const list: any = await env.R2.list({ prefix: 'images/', cursor, limit });
        const out: any[] = [];
        for (const obj of list.objects) {
            const file = obj.key.split('/').pop() || '';
            const m = /^([A-Za-z0-9]+)/.exec(file);
            if (!m) continue;
            const id = m[1];
            const row = await env.DB.prepare("SELECT id FROM images WHERE id=?").bind(id).first();
            if (!row) out.push({ key: obj.key, size: obj.size, uploaded: obj.uploaded });
        }
        const nextCursor = list.cursor || list.nextCursor || undefined;
        await maintAudit('scan_orphans', { found: out.length, truncated: !!list.truncated, limit, had_cursor: !!cursor }, admin.user_id);
        return json({ orphans: out, truncated: list.truncated, cursor: nextCursor });
    }
    if (req.method === 'POST' && path === '/api/admin/maint/delete-orphans') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const body: any = await req.json().catch(() => ({}));
        const keys: string[] = Array.isArray(body.keys) ? body.keys.slice(0, 500) : [];
        const r = await recordRun('delete_orphans', async () => {
            let c = 0; for (const k of keys) { await env.R2.delete(k); c++; }
            return { items: c };
        });
        if (r.ok) await maintAudit('delete_orphans', { run_id: r.id, items: (r as any).items ?? 0, requested: keys.length }, admin.user_id);
        return json(r);
    }
    if (req.method === 'POST' && path === '/api/admin/maint/decay-ip') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const r = await recordRun('decay_ip_scores', async () => {
            const before = await env.DB.prepare('SELECT SUM(score) as s FROM ip_blocks').first<{ s: number }>();
            await env.DB.prepare("UPDATE ip_blocks SET score = MAX(score - 10,0), updated_at=strftime('%s','now')").run();
            const after = await env.DB.prepare('SELECT SUM(score) as s FROM ip_blocks').first<{ s: number }>();
            return { meta: { before: before?.s || 0, after: after?.s || 0 } };
        });
        if (r.ok) await maintAudit('decay_ip_scores', { run_id: r.id, before: r.meta?.before, after: r.meta?.after }, admin.user_id);
        return json(r);
    }
    if (req.method === 'GET' && path === '/api/admin/maint/r2-stats') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        async function sumPrefix(prefix: string) {
            let cursor: string | undefined = undefined; let total = 0; let count = 0; let loops = 0;
            do {
                const l = await env.R2.list({ prefix, cursor, limit: 1000 });
                for (const o of l.objects) { total += o.size; count++; }
                cursor = l.truncated ? l.cursor : undefined; loops++;
            } while (cursor && loops < 50);
            return { total, count };
        }
        const images = await sumPrefix('images/');
        const avatars = await sumPrefix('avatars/');
        await maintAudit('r2_stats', { images_count: images.count, images_bytes: images.total, avatars_count: avatars.count, avatars_bytes: avatars.total }, admin.user_id);
        return json({ images, avatars });
    }

    if (req.method === 'GET' && path === '/api/admin/maint/backup/download') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const u = new URL(req.url);
        const key = u.searchParams.get('key') || '';
        if (!key || !/^backups\//.test(key)) return apiError(ErrorCode.INVALID_DATA, 400, 'Invalid key');
        const obj = await env.R2.get(key);
        if (!obj) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const filename = key.split('/').pop() || 'backup.json.gz';
        const h = new Headers();
        h.set('content-type', obj.httpMetadata?.contentType || 'application/gzip');
        h.set('content-disposition', `attachment; filename="${filename}"`);
        return new Response(obj.body, { status: 200, headers: h });
    }

    // DB Backups
    if (req.method === 'GET' && path === '/api/admin/maint/backups') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const list = await listBackups(env);
        return json({ backups: list });
    }
    if (req.method === 'POST' && path === '/api/admin/maint/db-backup') {
        const admin = await requireAdmin(); if (!admin) return json({ error: translate('auth.unauthorized') }, 403);
        const r = await recordRun('db_backup', async () => {
            const res = await performDbBackup(env);
            return { items: 1, meta: res };
        });
        return json(r);
    }

    if (req.method === 'POST' && path === '/api/admin/maint/test-mail') {
        const s = await requireAdmin(); if (!s) return json({ error: translate('auth.unauthorized') }, 403);
        const body: any = await req.json().catch(() => ({}));
        const toOverride = body.to && typeof body.to === 'string' ? body.to.trim() : null;
        // Resolve target email (override or admin email)
        let targetEmail: string | null = toOverride;
        if (!targetEmail) {
            const row = await env.DB.prepare("SELECT email FROM users WHERE id=?").bind(s.user_id).first<{ email: string }>();
            targetEmail = row?.email || null;
        }
        if (!targetEmail) return apiError(ErrorCode.INVALID_DATA, 400, translate('email.target_missing'));
        if (!(await requireAdmin())) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const apiKey = env.SENDINBLUE_API_KEY || '';
        const r = await recordRun('test_mail', async () => {
            if (!apiKey) throw new Error(translate('email.api_key_missing'));
            const res = await sendEmail(env, {
                to: targetEmail,
                subject: 'Test email maintenance',
                html: `<p>Ceci est un test d'envoi depuis la maintenance (${new Date().toISOString()}).</p>`
            });
            if (!res.ok) {
                const ex: any = new Error(translate('email.send_failed'));
                ex.meta = { to: targetEmail, status: res.status, code: res.code, message: res.remoteMessage, error: res.error };
                throw ex;
            }
            await createAudit(env, { type: 'email_sent', user_id: s.user_id, ip: clientIp, meta: JSON.stringify({ to: targetEmail, purpose: 'test_mail', status: res.status, message_id: res.messageId }) });
            return { items: 1, meta: { to: targetEmail, status: res.status, message_id: res.messageId } };
        });
        if (r.ok) await maintAudit('test_mail', { run_id: r.id, to: targetEmail, status: r.meta?.status }, s.user_id);
        return json(r);
    }
    if (req.method === 'GET' && path === '/api/admin/maint/test-mail/last') {
        if (!(await requireAdmin())) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const row = await env.DB.prepare("SELECT id, started_at, finished_at, status, items, meta FROM maintenance_runs WHERE task='test_mail' ORDER BY id DESC LIMIT 1").first<any>();
        if (!row) return apiError(ErrorCode.NOT_FOUND, 404, 'No run');
        let meta: any = null; try { meta = row.meta ? JSON.parse(row.meta) : null; } catch { meta = row.meta; }
        return json({ run: { id: row.id, started_at: row.started_at, finished_at: row.finished_at, status: row.status, items: row.items, meta } });
    }
    if (req.method === 'GET' && path === '/api/admin/db/tables') {
        if (!(await requireAdmin())) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const rows = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all<{ name: string }>();
        return json({ tables: (rows.results || []).map(r => r.name) });
    }
    if (req.method === 'GET' && path === '/api/admin/db/select') {
        if (!(await requireAdmin())) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const u = new URL(req.url);
        const table = u.searchParams.get('table');
        const limit = Math.min(parseInt(u.searchParams.get('limit') || '50', 10) || 50, 200);
        if (!table || /[^A-Za-z0-9_]/.test(table)) return apiError(ErrorCode.INVALID_DATA, 400, translate('table.invalid'));
        const sql = `SELECT * FROM ${table} LIMIT ?`;
        try {
            const rows = await env.DB.prepare(sql).bind(limit).all();
            return json({ rows: rows.results || [] });
        } catch (e: any) {
            return apiError(ErrorCode.INVALID_DATA, 400, translate('query.failed'), { detail: String(e) });
        }
    }

    if (req.method === 'GET' && path === '/api/admin/maint/history') {
        if (!(await requireAdmin())) return apiError(ErrorCode.FORBIDDEN, 403, translate('auth.forbidden'));
        const u = new URL(req.url); const limit = Math.min(parseInt(u.searchParams.get('limit') || '20', 10) || 20, 100);
        try {
            const rows = await env.DB.prepare("SELECT id,task,started_at,finished_at,status,items,meta FROM maintenance_runs ORDER BY id DESC LIMIT ?").bind(limit).all<any>();
            return json({ runs: rows.results || [] });
        } catch {
            return json({ runs: [] });
        }
    }

    // USER SETTINGS
    if (req.method === "GET" && path === "/api/me") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const info = await userInfo(env, session.user_id);
        const stats = await userStats(env, session.user_id);
        const avatarUrl = (info as any)?.avatar_key ? `/a/${(info as any).avatar_key.split("/").pop()}` : null;
        let role_label: string | null = null;
        try {
            const r = await env.DB.prepare('SELECT label FROM role_policies WHERE role=?').bind((info as any).role).first<{ label: string | null }>();
            role_label = r?.label || null;
        } catch { }
        let avatar_bytes = 0;
        try {
            if ((info as any)?.avatar_key) {
                const obj = await env.R2.get((info as any).avatar_key);
                if (obj && typeof (obj as any).size === 'number') avatar_bytes = (obj as any).size;
            }
        } catch { }
        const images_bytes_total = stats.bytes_total || 0;
        const bytes_total = images_bytes_total + avatar_bytes; // nouveau total incluant avatar
        const statsOut = { ...stats, images_bytes_total, avatar_bytes, bytes_total };
        return json({ info: { ...info, avatar_url: avatarUrl, role_label }, stats: statsOut });
    }

    if (req.method === "POST" && path === "/api/me/avatar") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const row = await env.DB.prepare("SELECT last_avatar_change_at FROM users WHERE id=?").bind(session.user_id).first<{ last_avatar_change_at: number | null }>();
        if (row?.last_avatar_change_at) {
            const now = Math.floor(Date.now() / 1000);
            const diff = now - row.last_avatar_change_at;
            if (diff < AVATAR_COOLDOWN_SEC) {
                return apiError(ErrorCode.AVATAR_COOLDOWN, 429, translate('avatar.cooldown'), { wait: AVATAR_COOLDOWN_SEC - diff });
            }
        } else {
            const cd = await checkAvatarCooldown(env, session.user_id, AVATAR_COOLDOWN_SEC);
            if (!cd.ok) return apiError(ErrorCode.AVATAR_COOLDOWN, 429, translate('avatar.cooldown'), { wait: (cd as any).wait });
        }
        const ct = req.headers.get("content-type") || "";
        if (!ct.startsWith("multipart/form-data")) return apiError(ErrorCode.INVALID_DATA, 400, translate('invalid.form'));
        const fd = await req.formData();
        const f = fd.get("file");
        if (!(f instanceof File)) return apiError(ErrorCode.UPLOAD_MISSING_FILE, 400, translate('missing.file'));
        if (!/^image\/(png|webp|avif|jpeg|jpg)$/.test(f.type)) return apiError(ErrorCode.UPLOAD_UNSUPPORTED_TYPE, 415, translate('upload.unsupported'));
        const ext = f.type === "image/png" ? ".png" : f.type === "image/webp" ? ".webp" : f.type === "image/avif" ? ".avif" : ".jpg";
        const key = `avatars/${randomId(10)}${ext}`;
        await putImage(env, key, await f.arrayBuffer(), f.type);
        await setUserAvatar(env, session.user_id, key);
        await env.DB.prepare("UPDATE users SET last_avatar_change_at=strftime('%s','now') WHERE id=?").bind(session.user_id).run();
        await logDiscordUser("User avatar updated", session.user_id, { requestId });
        await createAudit(env, { type: "User avatar updated", user_id: session.user_id, ip: clientIp, meta: JSON.stringify({ key }) });
        return json({ ok: true, url: `/a/${key.split("/").pop()}` });
    }
    if (req.method === "DELETE" && path === "/api/me/avatar") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const row2 = await env.DB.prepare("SELECT last_avatar_change_at FROM users WHERE id=?").bind(session.user_id).first<{ last_avatar_change_at: number | null }>();
        if (row2?.last_avatar_change_at) {
            const now = Math.floor(Date.now() / 1000);
            const diff = now - row2.last_avatar_change_at;
            if (diff < AVATAR_COOLDOWN_SEC) {
                return apiError(ErrorCode.AVATAR_COOLDOWN, 429, translate('avatar.cooldown'), { wait: AVATAR_COOLDOWN_SEC - diff });
            }
        } else {
            const cd2 = await checkAvatarCooldown(env, session.user_id, AVATAR_COOLDOWN_SEC);
            if (!cd2.ok) return apiError(ErrorCode.AVATAR_COOLDOWN, 429, translate('avatar.cooldown'), { wait: (cd2 as any).wait });
        }
        await env.DB.prepare("UPDATE users SET avatar_key=NULL WHERE id=?").bind(session.user_id).run();
        await env.DB.prepare("UPDATE users SET last_avatar_change_at=strftime('%s','now') WHERE id=?").bind(session.user_id).run();
        await logDiscordUser("User avatar removed", session.user_id, { requestId });
        await createAudit(env, { type: "User avatar removed", user_id: session.user_id, ip: clientIp });
        return json({ ok: true });
    }

    if (req.method === "POST" && path === "/api/me/email/request") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const { new_email }: any = await req.json();
        if (!validateEmail(new_email)) return apiError(ErrorCode.INVALID_DATA, 400, translate('email.invalid'));
        const token = randomId(48);
        const exp = Math.floor(Date.now() / 1000) + 15 * 60;
        await setUserEmailRequest(env, session.user_id, new_email, token, exp);
        const link = `${env.BASE_URL}/confirm-email?token=${token}`;
        if (env.SENDINBLUE_API_KEY) {
            const mailRes = await sendEmail(env, {
                to: new_email,
                subject: 'Confirmez votre nouvelle adresse email',
                html: `<p>Confirmez: <a href="${link}">${link}</a></p>`
            });
            if (mailRes.ok) {
                await createAudit(env, { type: 'email_sent', user_id: session.user_id, ip: clientIp, meta: JSON.stringify({ to: new_email, purpose: 'email_change_confirm', status: mailRes.status, message_id: mailRes.messageId }) });
            } else {
                await createAudit(env, { type: 'email_sent_failed', user_id: session.user_id, ip: clientIp, meta: JSON.stringify({ to: new_email, purpose: 'email_change_confirm', error: mailRes.error, status: mailRes.status, code: mailRes.code }) });
            }
        }
        await logDiscordUser("User email change requested", session.user_id, { new_email, requestId });
        await createAudit(env, { type: "email_change_requested", user_id: session.user_id, ip: clientIp, meta: JSON.stringify({ new_email }) });
        return json({ ok: true });
    }

    if (req.method === "POST" && path === "/api/me/email/confirm") {
        const { token }: any = await req.json();
        const uid = await consumeEmailChange(env, token);
        if (!uid) return apiError(ErrorCode.INVALID_DATA, 400, translate('token.invalid'));
        await logDiscordUser("User email changed", uid, { requestId });
        await createAudit(env, { type: "email_changed", user_id: uid, ip: clientIp });
        return json({ ok: true });
    }

    if (req.method === "POST" && path === "/api/me/password") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const { current, next }: any = await req.json();
        if (!validatePassword(next)) return apiError(ErrorCode.INVALID_DATA, 400, translate('password.too_short'));
        const user = await env.DB.prepare("SELECT password_hash FROM users WHERE id=?").bind(session.user_id).first<{ password_hash: string }>();
        if (!user) return apiError(ErrorCode.INVALID_DATA, 400, translate('common.not_found'));

        const raw = Uint8Array.from(atob(user.password_hash), c => c.charCodeAt(0));
        const salt = raw.slice(0, 16); const hash = raw.slice(16);
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", enc.encode(current), { name: "PBKDF2" }, false, ["deriveBits"]);
        const derived = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
        const d = new Uint8Array(derived);
        let equal = 0;
        for (let i = 0; i < d.length; i++) equal |= d[i] ^ hash[i];
        if (equal !== 0) return apiError(ErrorCode.PASSWORD_INVALID_CURRENT, 401, translate('password.current_invalid'));

        const salt2 = crypto.getRandomValues(new Uint8Array(16));
        const key2 = await crypto.subtle.importKey("raw", enc.encode(next), { name: "PBKDF2" }, false, ["deriveBits"]);
        const derived2 = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: salt2, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key2, 256);
        const buf2 = new Uint8Array(derived2);
        const out2 = new Uint8Array(16 + buf2.length);
        out2.set(salt2, 0); out2.set(buf2, 16);
        const newHash = btoa(String.fromCharCode(...out2));

        await changePassword(env, session.user_id, newHash);
        await logDiscordUser("User password changed", session.user_id, { requestId });
        await createAudit(env, { type: "User password changed", user_id: session.user_id, ip: clientIp });
        return json({ ok: true });
    }

    if (path === "/api/me/token/refresh" && req.method === "POST") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const urlObj = new URL(req.url);
        const rotate = urlObj.searchParams.get("rotate") === "1";
        const exists = await hasApiToken(env, session.user_id);
        if (rotate) {
            const meta = await getApiTokenMeta(env, session.user_id);
            if (meta && Date.now() / 1000 - meta.created_at < 60) {
                return json({ ok: false, error: translate('rotation.too_frequent') }, 429);
            }
        }
        if (exists && !rotate) {
            return json({ ok: true, already: true });
        }
        const token = await refreshApiToken(env, session.user_id);
        await logDiscordUser(rotate ? "API token rotated" : "API token created", session.user_id, { requestId });
        await createAudit(env, { type: rotate ? "API token rotated" : "API token created", user_id: session.user_id, ip: clientIp });
        return json({ ok: true, token, rotated: rotate });
    }

    if (path === "/api/me/token/revoke" && req.method === "POST") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        await revokeApiToken(env, session.user_id);
        await logDiscordUser("API token revoked", session.user_id, { requestId });
        await createAudit(env, { type: "API token revoked", user_id: session.user_id, ip: clientIp });
        return json({ ok: true });
    }

    if (path === "/api/me/token/meta" && req.method === "GET") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const meta = await getApiTokenMeta(env, session.user_id);
        return json({ ok: true, meta });
    }

    if (req.method === "GET" && path === "/api/me/sharex-config") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        return json({
            template: {
                Version: "13.7.0",
                Name: "mduck-cdn",
                DestinationType: "ImageUploader",
                RequestMethod: "POST",
                RequestURL: `${base}/api/upload`,
                Headers: { Authorization: "Bearer VOTRE_TOKEN_ICI" },
                Body: "MultipartFormData",
                FileFormName: "file",
                URL: "$json:url$"
            }
        });
    }

    if (req.method === "GET" && path.startsWith("/a/")) {
        const name = path.slice(3);
        if (!name) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const row = await env.DB.prepare("SELECT avatar_key FROM users WHERE avatar_key LIKE ? LIMIT 1")
            .bind(`avatars/%${name}`).first<{ avatar_key: string }>();
        if (!row?.avatar_key) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const obj = await env.R2.get(row.avatar_key);
        if (!obj) return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
        const h = new Headers();
        h.set("content-type", obj.httpMetadata?.contentType || "image/png");
        // Long immutable cache (unique names)
        h.set("cache-control", "public, max-age=31536000, immutable");
        return new Response(obj.body, { status: 200, headers: h });
    }

    if (req.method === "POST" && path === "/tasks/cleanup") {
        if (env.CLEANUP_ENABLED === "true") {
            await runCleanup(env);
            return json({ ok: true });
        }
        return json({ ok: false, error: translate('cleanup.disabled') }, 403);
    }
    if (req.method === 'GET' && path === '/api/health') {
        return json({ ok: true, time: Date.now() });
    }

    if (req.method === "GET" && path === "/api/me/token/current") {
        const session = await requireSessionUser();
        if (!session) return apiError(ErrorCode.AUTH_REQUIRED, 401, translate('auth.unauthorized'));
        const token = await getApiTokenPlain(env, session.user_id);
        return json({ ok: true, token });
    }

    return apiError(ErrorCode.NOT_FOUND, 404, translate('common.not_found'));
}