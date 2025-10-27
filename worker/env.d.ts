export interface Env {
    R2: R2Bucket;
    DB: D1Database;

    R2_ACCOUNT_ID: string;
    R2_ACCESS_KEY_ID: string;
    R2_SECRET_ACCESS_KEY: string;
    R2_BUCKET: string;

    D1_DATABASE: string;

    SENDINBLUE_API_URL?: string;
    SENDINBLUE_API_KEY: string;
    MAIL_SENDER?: string;
    MAIL_SENDER_NAME?: string;

    DISCORD_WEBHOOK_URL: string;
    DISCORD_WEBHOOK_ENABLED?: string;

    CLEANUP_ENABLED?: string;
    BACKUP_ENABLED: string;
    COOKIE_SECRET: string;
    BASE_URL: string;
}