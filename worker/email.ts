import { Env } from "./env.d";

export interface SendEmailInput {
    to: string;
    subject: string;
    html: string;
    senderEmail?: string;
    senderName?: string;
    timeoutMs?: number;
}

export interface SendEmailResult {
    ok: boolean;
    status?: number;
    messageId?: string | null;
    error?: string;
    code?: string | null;
    remoteMessage?: string | null;
    latency_ms?: number;
    retryable?: boolean;
}

export async function sendEmail(env: Env, input: SendEmailInput): Promise<SendEmailResult> {
    const apiKey = env.SENDINBLUE_API_KEY;
    if (!apiKey) return { ok: false, error: "API key absente", retryable: false };
    const endpoint = (env.SENDINBLUE_API_URL || 'https://api.brevo.com/v3/smtp/email').trim();
    const senderEmail = input.senderEmail || env.MAIL_SENDER || 'no-reply@mduck.fr';
    const senderName = input.senderName || env.MAIL_SENDER_NAME || 'MathPix';

    const controller = new AbortController();
    const timeoutMs = input.timeoutMs || 10000;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    let status = 0; let msgId: string | null = null; let code: string | null = null; let remoteMessage: string | null = null;
    const started = Date.now();
    try {
        const resp = await fetch(endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'api-key': apiKey },
            body: JSON.stringify({
                sender: { name: senderName, email: senderEmail },
                to: [{ email: input.to }],
                subject: input.subject,
                htmlContent: input.html
            }),
            signal: controller.signal
        });
        status = resp.status; msgId = resp.headers.get('x-mailin-message-id');
        if (!resp.ok) {
            const txt = await resp.text().catch(() => null);
            if (txt) {
                try {
                    const j = JSON.parse(txt);
                    code = j.code || null;
                    remoteMessage = j.message || null;
                } catch { /* ignore parse error */ }
            }
            const latency = Date.now() - started;
            const retryable = status >= 500 || status === 429;
            return { ok: false, status, messageId: msgId, code, remoteMessage, error: 'HTTP ' + status, latency_ms: latency, retryable };
        }
        return { ok: true, status, messageId: msgId, latency_ms: Date.now() - started, retryable: false };
    } catch (e: any) {
        const latency = Date.now() - started;
        const msg = String(e || 'error');
        const retryable = /AbortError|network|timeout/i.test(msg);
        return { ok: false, status, messageId: msgId, error: msg, code, remoteMessage, latency_ms: latency, retryable };
    } finally { clearTimeout(timeout); }
}
