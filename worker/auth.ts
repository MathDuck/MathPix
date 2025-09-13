import { Env } from "./env.d";
import { createUser, getUserByEmail, getUserByUsername, getUserByEmailOrUsername } from "./db";
import { sendEmail } from "./email";
import { createSession, sessionCookie, destroySession, getSession } from "./sessions";
import { randomId, getClientIp, getUA, validateEmail, validatePassword, validateUsername, PBKDF2_ITERATIONS, bumpIpScore, verifyCaptcha, LOGIN_WINDOW_SEC, LOGIN_FAIL_THRESHOLD, responseHelpers } from "./utils";
import { logDiscord } from "./discord";
import { createAudit } from "./db";

async function hash(pw: string) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey("raw", enc.encode(pw), { name: "PBKDF2" }, false, ["deriveBits"]);
    const derived = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
    const buf = new Uint8Array(derived);
    const out = new Uint8Array(16 + buf.length);
    out.set(salt, 0); out.set(buf, 16);
    return btoa(String.fromCharCode(...out));
}

async function verify(pw: string, stored: string) {
    const raw = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
    const salt = raw.slice(0, 16); const hash = raw.slice(16);
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(pw), { name: "PBKDF2" }, false, ["deriveBits"]);
    const derived = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
    const derivedArray = new Uint8Array(derived);
    if (derivedArray.length !== hash.length) return false;
    let equal = 0;
    for (let i = 0; i < derivedArray.length; i++) equal |= derivedArray[i] ^ hash[i];
    return equal === 0;
}

export async function handleRegister(req: Request, env: Env, captchaToken: string) {
    const { requestId, json: jsonResponse, auditMeta } = responseHelpers();
    const ip = getClientIp(req);
    try {
        const body: any = await req.json().catch(() => ({}));
        const email: string = body.email || "";
        const password: string = body.password || "";
        const username: string | undefined = body.username || undefined;
        const captcha: string = body.captcha || "";
        const captchaAnswer: string | undefined = body.captchaAnswer;
        if (!validateEmail(email) || !validatePassword(password) || (username && !validateUsername(username))) {
            await bumpIpScore(env, ip, 10);
            return jsonResponse({ error: "Email / mot de passe / username invalide" }, 400);
        }
        const userAnswer = captchaAnswer || captcha; // compat rétro
        const captchaOk = await verifyCaptcha(env, captchaToken, String(userAnswer || ""));
        if (!captchaOk) {
            await bumpIpScore(env, ip, 10);
            return jsonResponse({ error: "Captcha invalide" }, 400);
        }
        const exists: any = await getUserByEmail(env, email);
        if (exists) return jsonResponse({ error: "Compte déjà existant" }, 409);
        if (username) {
            const uTaken: any = await getUserByUsername(env, username);
            if (uTaken) return jsonResponse({ error: "Username déjà pris" }, 409);
        }
        const password_hash = await hash(password);
        const id = "u_" + randomId(16);
        await createUser(env, { id, email, username, role: "user", password_hash });
        const sess = await createSession(env, { id });
        const cookie = await sessionCookie(env, sess.id);
        await logDiscord(env, "User registered", { email, username, id, ip, requestId });
        await createAudit(env, { type: "user_registered", user_id: id, ip, meta: auditMeta({ email, username }) });
        return new Response(JSON.stringify({ ok: true }), {
            status: 201,
            headers: { "content-type": "application/json", "set-cookie": cookie }
        });
    } catch {
        return jsonResponse({ error: "Bad request" }, 400);
    }
}

type ThrottleRow = { fail_count: number; first_fail_at: number; locked_until: number | null };

async function getThrottle(env: Env, key: string): Promise<ThrottleRow | null> {
    return await env.DB.prepare("SELECT fail_count, first_fail_at, locked_until FROM auth_throttle WHERE key=?")
        .bind(key).first<ThrottleRow>();
}
async function clearThrottle(env: Env, key: string) {
    await env.DB.prepare("DELETE FROM auth_throttle WHERE key=?").bind(key).run();
}
async function incrementFail(env: Env, key: string, now: number) {
    const rec = await getThrottle(env, key);
    if (!rec) {
        await env.DB.prepare("INSERT INTO auth_throttle (key, fail_count, first_fail_at, locked_until) VALUES (?,?,?,NULL)")
            .bind(key, 1, now).run();
        return { fail_count: 1, first_fail_at: now, locked_until: null as number | null };
    }
    let failCount = rec.fail_count + 1;
    let first = rec.first_fail_at;
    if (now - first > LOGIN_WINDOW_SEC) {
        failCount = 1; first = now;
    }
    let locked_until = rec.locked_until;
    if (failCount >= LOGIN_FAIL_THRESHOLD) {
        const step = failCount - LOGIN_FAIL_THRESHOLD;
        const lockSec = Math.min(600, Math.pow(2, step) * 5);
        locked_until = now + lockSec;
    }
    await env.DB.prepare("UPDATE auth_throttle SET fail_count=?, first_fail_at=?, locked_until=? WHERE key=?")
        .bind(failCount, first, locked_until ?? null, key).run();
    return { fail_count: failCount, first_fail_at: first, locked_until };
}

async function isLocked(env: Env, key: string, now: number) {
    const rec = await getThrottle(env, key);
    if (rec?.locked_until && rec.locked_until > now) {
        return rec.locked_until - now; // secondes restantes
    }
    return 0;
}

export async function handleLogin(req: Request, env: Env) {
    const { requestId, json: jsonResponse, auditMeta } = responseHelpers();
    const ip = getClientIp(req);
    const userAgent = getUA(req);
    try {
        const body: any = await req.json().catch(() => ({}));
        const identifier: string = body.email || body.username || body.identifier || "";
        const password: string = body.password || "";
        const now = Math.floor(Date.now() / 1000);

        const ipKey = `ip:${ip}`;
        const idKey = identifier ? `id:${identifier.toLowerCase()}` : null;
        for (const k of [ipKey, idKey].filter(Boolean) as string[]) {
            const wait = await isLocked(env, k, now);
            if (wait > 0) return jsonResponse({ error: "Trop de tentatives. Réessayez plus tard", retry_after: wait }, 429);
        }
        const user: any = await getUserByEmailOrUsername(env, identifier);
        if (!user || user.disabled) {
            await bumpIpScore(env, ip, 10);
            await incrementFail(env, ipKey, now);
            if (idKey) await incrementFail(env, idKey, now);
            await createAudit(env, { type: "login_failed", ip, meta: auditMeta({ identifier }) });
            return jsonResponse({ error: "Identifiants invalides" }, 401);
        }
        const ok = await verify(password, user.password_hash as string);
        if (!ok) {
            await bumpIpScore(env, ip, 10);
            await incrementFail(env, ipKey, now);
            await incrementFail(env, idKey!, now);
            await createAudit(env, { type: "login_failed", ip, meta: auditMeta({ identifier, user_id: user.id }) });
            return jsonResponse({ error: "Identifiants invalides" }, 401);
        }
        await clearThrottle(env, ipKey);
        if (idKey) await clearThrottle(env, idKey);
        const sess = await createSession(env, { id: user.id as string });
        const cookie = await sessionCookie(env, sess.id);
        await logDiscord(env, "User login", { identifier, id: user.id, role: user.role, ip, ua: userAgent, requestId });
        await createAudit(env, { type: "login_success", user_id: user.id, ip, meta: auditMeta({ ua: userAgent }) });
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "content-type": "application/json", "set-cookie": cookie }
        });
    } catch {
        return jsonResponse({ error: "Bad request" }, 400);
    }
}

export async function handleLogout(req: Request, env: Env) {
    const session = await getSession(env, req);
    if (session) {
        await destroySession(env, session.id);
        let role: string | undefined;
        if (session.user_id) {
            const roleRow = await env.DB.prepare("SELECT role FROM users WHERE id=?").bind(session.user_id).first<{ role: string }>();
            role = roleRow?.role;
        }
        const requestId = randomId(12);
        await logDiscord(env, "User logout", { user_id: session.user_id, role, requestId });
        await createAudit(env, { type: "logout", user_id: session.user_id, ip: getClientIp(req), meta: JSON.stringify({ request_id: requestId }) });
    }
    return new Response(null, {
        status: 204,
        headers: { "set-cookie": "sessionId=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" }
    });
}

export async function handlePasswordResetRequest(req: Request, env: Env) {
    const { requestId, json: jsonResponse, auditMeta } = responseHelpers();
    const body: any = await req.json().catch(() => ({}));
    const email: string = body.email || "";
    const user: any = await getUserByEmail(env, email);
    if (user) {
        const token = randomId(32);
        const exp = Math.floor(Date.now() / 1000) + 15 * 60;
        await env.DB.prepare(
            "INSERT INTO password_resets (user_id, token, expires_at, used) VALUES (?,?,?,0)"
        ).bind(user.id, token, exp).run();
        const link = `${env.BASE_URL}/reset?token=${token}`;
        if (env.SENDINBLUE_API_KEY) {
            const mailRes = await sendEmail(env, {
                to: email,
                subject: 'Réinitialisation du mot de passe',
                html: `<p>Bonjour,</p><p>Cliquez pour réinitialiser votre mot de passe : <a href="${link}">${link}</a></p>`
            });
            await createAudit(env, { type: "email_sent", user_id: user.id, ip: getClientIp(req), meta: auditMeta({ kind: 'password_reset', status: mailRes.status, ok: mailRes.ok }) });
        }
        await logDiscord(env, "Password reset requested", { user_id: user.id, email, requestId });
        await createAudit(env, { type: "password_reset_requested", user_id: user.id, ip: getClientIp(req), meta: auditMeta({ email }) });
    }
    return jsonResponse({ ok: true });
}

export async function handlePasswordResetConfirm(req: Request, env: Env) {
    const { requestId, json: jsonResponse, auditMeta } = responseHelpers();
    const body: any = await req.json().catch(() => ({}));
    const token: string = body.token || "";
    const password: string = body.password || "";
    if (!validatePassword(password)) return jsonResponse({ error: "Mot de passe invalide" }, 400);
    const rec = await env.DB.prepare(
        "SELECT user_id,expires_at,used FROM password_resets WHERE token=?"
    ).bind(token).first<{ user_id: string; expires_at: number; used: number }>();
    if (!rec || rec.used || rec.expires_at < Math.floor(Date.now() / 1000)) {
        return jsonResponse({ error: "Token invalide" }, 400);
    }
    const password_hash = await hash(password);
    await env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(password_hash, rec.user_id).run();
    await env.DB.prepare("UPDATE password_resets SET used=1 WHERE token=?").bind(token).run();
    await logDiscord(env, "Password reset success", { user_id: rec.user_id, requestId });
    await createAudit(env, { type: "password_reset_success", user_id: rec.user_id, ip: getClientIp(req), meta: auditMeta() });
    return jsonResponse({ ok: true });
}