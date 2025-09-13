import { Env } from "./env.d";

export async function setUserAvatar(env: Env, user_id: string, key: string) {
    return env.DB.prepare("UPDATE users SET avatar_key=? WHERE id=?").bind(key, user_id).run();
}

export async function setUserEmailRequest(env: Env, user_id: string, new_email: string, token: string, exp: number) {
    return env.DB.prepare(
        "INSERT INTO email_change_requests (token,user_id,new_email,expires_at,used) VALUES (?,?,?,?,0)"
    ).bind(token, user_id, new_email, exp).run();
}

export async function consumeEmailChange(env: Env, token: string) {
    const rec = await env.DB.prepare(
        "SELECT user_id,new_email,expires_at,used FROM email_change_requests WHERE token=?"
    ).bind(token).first<{ user_id: string; new_email: string; expires_at: number; used: number }>();
    if (!rec || rec.used || rec.expires_at < Math.floor(Date.now() / 1000)) return null;
    await env.DB.prepare("UPDATE users SET email=?, email_verified=1 WHERE id=?").bind(rec.new_email, rec.user_id).run();
    await env.DB.prepare("UPDATE email_change_requests SET used=1 WHERE token=?").bind(token).run();
    return rec.user_id;
}

export async function changePassword(env: Env, user_id: string, password_hash: string) {
    return env.DB.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(password_hash, user_id).run();
}

export async function userInfo(env: Env, user_id: string) {
    return env.DB.prepare(
        "SELECT id,email,username,role,disabled,created_at,avatar_key,email_verified FROM users WHERE id=?"
    ).bind(user_id).first();
}

export async function userStats(env: Env, user_id: string) {
    const statsRow = await env.DB.prepare("SELECT images_total, images_today, last_upload_at, bytes_total FROM users_stats WHERE user_id=?")
        .bind(user_id).first<{ images_total: number; images_today: number; last_upload_at: number; bytes_total: number }>();
    const recent = await env.DB.prepare(
        "SELECT id,ext,created_at FROM images WHERE owner_id=? ORDER BY created_at DESC LIMIT 12"
    ).bind(user_id).all();

    if (statsRow) {
        const agg = await env.DB.prepare(`
            SELECT
                (SELECT MIN(created_at) FROM images WHERE owner_id=?) AS first_upload_at,
                (SELECT SUM(CASE WHEN type='upload' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS uploads,
                (SELECT SUM(CASE WHEN type='delete_image' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS deletions,
                (SELECT SUM(CASE WHEN type='User avatar updated' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS avatar_changes,
                (SELECT SUM(CASE WHEN type='User password changed' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS password_changes,
                (SELECT SUM(CASE WHEN type='API token refreshed' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS api_token_refreshes
        `).bind(user_id, user_id, user_id, user_id, user_id, user_id).first<{
            first_upload_at: number | null; uploads: number; deletions: number; avatar_changes: number; password_changes: number; api_token_refreshes: number;
        }>();
        return {
            total: statsRow.images_total,
            today: statsRow.images_today,
            bytes_total: statsRow.bytes_total,
            last_upload_at: statsRow.last_upload_at,
            first_upload_at: agg?.first_upload_at ?? null,
            recent: (recent.results || []).map((r: any) => ({ id: r.id, ext: r.ext, created_at: r.created_at })),
            audit: agg ? {
                uploads: agg.uploads || 0,
                deletions: agg.deletions || 0,
                avatar_changes: agg.avatar_changes || 0,
                password_changes: agg.password_changes || 0,
                api_token_refreshes: agg.api_token_refreshes || 0
            } : null
        };
    }
    const fallback = await env.DB.prepare(`
        SELECT
            (SELECT COUNT(*) FROM images WHERE owner_id=?) AS total,
            (SELECT COUNT(*) FROM images WHERE owner_id=? AND date(created_at,'unixepoch','localtime')=date('now','localtime')) AS today,
            (SELECT MIN(created_at) FROM images WHERE owner_id=?) AS first_upload_at,
            (SELECT MAX(created_at) FROM images WHERE owner_id=?) AS last_upload_at,
            (SELECT COALESCE(SUM(size),0) FROM images WHERE owner_id=?) AS bytes_total,
            (SELECT SUM(CASE WHEN type='upload' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS uploads,
            (SELECT SUM(CASE WHEN type='delete_image' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS deletions,
            (SELECT SUM(CASE WHEN type='User avatar updated' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS avatar_changes,
            (SELECT SUM(CASE WHEN type='User password changed' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS password_changes,
            (SELECT SUM(CASE WHEN type='API token refreshed' THEN 1 ELSE 0 END) FROM audit_logs WHERE user_id=?) AS api_token_refreshes
    `).bind(user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id).first<{
        total: number; today: number; first_upload_at: number | null; last_upload_at: number | null; bytes_total: number;
        uploads: number; deletions: number; avatar_changes: number; password_changes: number; api_token_refreshes: number;
    }>();
    return {
        total: fallback?.total || 0,
        today: fallback?.today || 0,
        bytes_total: fallback?.bytes_total || 0,
        last_upload_at: fallback?.last_upload_at || null,
        first_upload_at: fallback?.first_upload_at || null,
        recent: (recent.results || []).map((r: any) => ({ id: r.id, ext: r.ext, created_at: r.created_at })),
        audit: fallback ? {
            uploads: fallback.uploads || 0,
            deletions: fallback.deletions || 0,
            avatar_changes: fallback.avatar_changes || 0,
            password_changes: fallback.password_changes || 0,
            api_token_refreshes: fallback.api_token_refreshes || 0
        } : null
    };
}