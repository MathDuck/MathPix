// Simple i18n message catalog (API uses English; French kept for UI/toasts potential use)
// Extend by adding keys here; backend calls t(key) so future lang switch is trivial.
export type MessageKey =
    | 'auth.unauthorized'
    | 'auth.forbidden'
    | 'access.blocked'
    | 'quota.daily'
    | 'quota.cooldown'
    | 'quota.limit'
    | 'upload.unsupported'
    | 'upload.unsupported_full'
    | 'upload.unknown_ext'
    | 'upload.failed'
    | 'common.not_found'
    | 'admin.missing_id'
    | 'email.invalid'
    | 'token.invalid'
    | 'password.too_short'
    | 'password.current_invalid'
    | 'avatar.cooldown'
    | 'invalid.form'
    | 'missing.file'
    | 'rotation.too_frequent'
    | 'cleanup.disabled'
    | 'email.target_missing'
    | 'email.api_key_missing'
    | 'email.send_failed'
    | 'table.invalid'
    | 'query.failed'
    | 'maintenance.no_run';

const CATALOG: Record<string, Record<MessageKey, string>> = {
    en: {
        'auth.unauthorized': 'Unauthorized',
        'auth.forbidden': 'Forbidden',
        'access.blocked': 'Forbidden',
        'quota.daily': 'Daily quota reached',
        'quota.cooldown': 'Active cooldown',
        'quota.limit': 'Quota limit',
        'upload.unsupported': 'Unsupported format',
        'upload.unsupported_full': 'Unsupported format (PNG, WebP, AVIF, JPEG)',
        'upload.unknown_ext': 'Unknown extension',
        'upload.failed': 'Upload failed',
        'common.not_found': 'Not found',
        'admin.missing_id': 'Missing id',
        'email.invalid': 'Invalid email',
        'token.invalid': 'Invalid token',
        'password.too_short': 'Password too short',
        'password.current_invalid': 'Current password invalid',
        'avatar.cooldown': 'Avatar cooldown active',
        'invalid.form': 'Invalid form data',
        'missing.file': 'Missing file',
        'rotation.too_frequent': 'Rotation too frequent (wait 60s)',
        'cleanup.disabled': 'Cleanup disabled',
        'email.target_missing': 'Target email missing',
        'email.api_key_missing': 'Email API key missing',
        'email.send_failed': 'Email send failed',
        'table.invalid': 'Invalid table',
        'query.failed': 'Query failed',
        'maintenance.no_run': 'No run'
    },
    fr: {
        'auth.unauthorized': 'Non autorisé',
        'auth.forbidden': 'Interdit',
        'access.blocked': 'Accès bloqué',
        'quota.daily': 'Quota quotidien atteint',
        'quota.cooldown': 'Cooldown actif',
        'quota.limit': 'Limite de quota',
        'upload.unsupported': 'Format non supporté',
        'upload.unsupported_full': 'Format non supporté (PNG, WebP, AVIF, JPEG)',
        'upload.unknown_ext': 'Extension inconnue',
        'upload.failed': "Échec de l'upload",
        'common.not_found': 'Introuvable',
        'admin.missing_id': 'ID manquant',
        'email.invalid': 'Email invalide',
        'token.invalid': 'Token invalide',
        'password.too_short': 'Mot de passe trop court',
        'password.current_invalid': 'Mot de passe actuel invalide',
        'avatar.cooldown': 'Cooldown avatar actif',
        'invalid.form': 'Formulaire invalide',
        'missing.file': 'Fichier manquant',
        'rotation.too_frequent': 'Rotation trop fréquente (attendez 60s)',
        'cleanup.disabled': 'Nettoyage désactivé',
        'email.target_missing': 'Email cible manquant',
        'email.api_key_missing': 'Clé API email absente',
        'email.send_failed': "Échec envoi email",
        'table.invalid': 'Table invalide',
        'query.failed': 'Requête impossible',
        'maintenance.no_run': 'Aucune exécution'
    }
};

export function translate(key: MessageKey, lang: 'en' | 'fr' = 'fr'): string {
    const k = CATALOG[lang]?.[key];
    if (k) return k;
    return CATALOG.en[key] || Object.values(CATALOG.en)[0] || key;
}
