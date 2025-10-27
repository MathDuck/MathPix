import { Env } from "./env.d";

function fmtDateStamp(d = new Date()) {
    const pad = (n: number, l = 2) => String(n).padStart(l, '0');
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
}

export async function listBackups(env: Env, prefix = 'backups/') {
    const out: Array<{ key: string; size: number; uploaded: number }> = [];
    let cursor: string | undefined = undefined;
    let loops = 0;
    do {
        const l = await env.R2.list({ prefix, cursor, limit: 1000 });
        for (const o of l.objects) {
            out.push({ key: o.key, size: o.size, uploaded: Math.floor((o.uploaded as any)?.getTime?.() / 1000) || Math.floor(Date.now() / 1000) });
        }
        cursor = l.truncated ? l.cursor : undefined;
        loops++;
    } while (cursor && loops < 50);
    out.sort((a, b) => a.uploaded - b.uploaded);
    return out;
}

export async function performDbBackup(env: Env) {
    const now = Math.floor(Date.now() / 1000);
    // Collect table names
    const tablesRes = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all<{ name: string }>();
    const tables = (tablesRes.results || []).map(r => r.name);
    const dump: Record<string, any[]> = {};
    let totalRows = 0;
    for (const t of tables) {
        try {
            const rows = await env.DB.prepare(`SELECT * FROM ${t}`).all<any>();
            const arr = rows.results || [];
            totalRows += arr.length;
            dump[t] = arr;
        } catch {
            // skip table on error
        }
    }
    const payload = {
        database: env.D1_DATABASE || 'd1',
        created_at: now,
        tables: dump,
    };
    const json = JSON.stringify(payload);
    // gzip using Web CompressionStream (available in Workers)
    const gzStream = new Blob([new TextEncoder().encode(json)]).stream().pipeThrough(new CompressionStream('gzip'));
    const gzBuf = await new Response(gzStream).arrayBuffer();
    const gz = new Uint8Array(gzBuf);
    const stamp = fmtDateStamp(new Date());
    const key = `backups/db-${env.D1_DATABASE || 'd1'}-${stamp}.json.gz`;
    await env.R2.put(key, gz, {
        httpMetadata: { contentType: 'application/gzip', contentDisposition: `attachment; filename="${key.split('/').pop()}"` },
        customMetadata: { kind: 'd1-backup', created_at: String(now), tables: String(tables.length), rows: String(totalRows) }
    });

    // Rotation: keep last 5
    const lst = await listBackups(env);
    let deleted = 0;
    if (lst.length > 5) {
        const toDelete = lst.slice(0, Math.max(0, lst.length - 5));
        for (const f of toDelete) { await env.R2.delete(f.key); deleted++; }
    }
    return { key, bytes: gz.byteLength, tables: tables.length, rows: totalRows, rotated_deleted: deleted };
}

export async function maybeAutoBackup(env: Env, olderThanSec = 4 * 24 * 3600) {
    if (env.BACKUP_ENABLED && env.BACKUP_ENABLED !== 'true') {
        return { ok: false, reason: 'disabled' };
    }
    try {
        const lst = await listBackups(env);
        const last = lst[lst.length - 1];
        const now = Math.floor(Date.now() / 1000);
        if (!last || (now - last.uploaded) >= olderThanSec) {
            const r = await performDbBackup(env);
            return { ok: true, created: true, meta: r };
        }
        return { ok: true, created: false, last_uploaded: last.uploaded };
    } catch (e: any) {
        return { ok: false, error: String(e) };
    }
}
