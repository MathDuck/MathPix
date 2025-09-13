import { Env } from "./env.d";

type FieldMap = Record<string, string | number | boolean | undefined | null>;

function colorFor(title: string): number {
    const t = title.toLowerCase();
    if (/(error|fail|blocked|denied)/.test(t)) return 0xE11D48;
    if (/upload/.test(t)) return 0x3B82F6;
    if (/(delete|removed)/.test(t)) return 0xF59E0B;
    if (/(password|token)/.test(t)) return 0x6366F1;
    if (/(avatar|email)/.test(t)) return 0x10B981;
    if (/(admin)/.test(t)) return 0x9333EA;
    return 0x7289DA;
}

function formatValue(v: unknown): string {
    if (v === null || v === undefined || v === "") return "`—`";
    if (typeof v === "string") {
        if (v.length > 180) return v.slice(0, 177) + "…";
        return v;
    }
    return String(v);
}

export async function logDiscord(env: Env, title: string, fields: FieldMap = {}, opts?: { description?: string }) {
    const url = env.DISCORD_WEBHOOK_URL;
    if (!url) return;
    if (env.DISCORD_WEBHOOK_ENABLED === 'false') return;
    if (!/https:\/\/discord\.com\/api\/webhooks\//.test(url)) return;
    const entries = Object.entries(fields).filter(([, v]) => v !== undefined);
    const embed: any = {
        title,
        color: colorFor(title),
        timestamp: new Date().toISOString(),
        fields: entries.slice(0, 24).map(([name, value]) => ({
            name: name.length > 32 ? name.slice(0, 29) + '…' : name,
            value: formatValue(value),
            inline: true
        }))
    };
    if (opts?.description) embed.description = opts.description.slice(0, 1800);
    if (!embed.fields.length) delete embed.fields;
    await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ embeds: [embed] }) }).catch(() => { });
}