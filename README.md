# MathPix CDN / Image Service

Service d'hébergement et de distribution d'images (Cloudflare Workers + R2 + D1) avec :
- Upload via site ou token API (Bearer)
- Optimisation PNG (>6 Mo, lossless)
- Stockage R2 et diffusion cache longue durée
- Système de rôles + quotas dynamiques
- Captcha simple math pour inscription
- Panneau admin (utilisateurs, images, logs, maintenance, rôles)
- Webhooks Discord (audits, événements)
- Emails transactionnels (Brevo / SendInBlue)

## Sommaire
1. [Architecture](#architecture)
2. [Prérequis](#prérequis)
3. [Configuration](#configuration)
4. [Installation & Dev](#installation--dev)
5. [Base de données D1](#base-de-données-d1)
6. [Rôles & Quotas](#rôles--quotas)
7. [Upload & Optimisation](#upload--optimisation)
8. [Endpoints Principaux](#endpoints-principaux)
9. [Panneau Admin](#panneau-admin)
10. [Sécurité](#sécurité)
11. [Tâches planifiées & Maintenance](#tâches-planifiées--maintenance)
12. [Gestion des Secrets](#gestion-des-secrets)
13. [Roadmap / Idées](#roadmap--idées)
14. [Licence](#licence)

## Architecture
- **Cloudflare Worker** (`worker/index.ts`) : routeur + assets statiques.
- **R2** : stockage des images (`images/{id}{ext}`).
- **D1** : utilisateurs, sessions, images, stats, rôles, audit, captchas.
- **Front** : HTML/CSS/JS dans `public/` (login, register, settings, admin, upload simple).
- **Optimisation** : Module `image_opt.ts` (PNG >6MB only, compression lossless).
- **Audit** : Table `audit_logs` (upload, delete, quota_block, maintenance...).
- **Discord** : Webhook enrichi du username si existant.

## Prérequis
- Node.js (>=18) pour outils (Wrangler / TypeScript).
- `wrangler` (géré via devDependencies).
- Accès Cloudflare avec R2 + D1 activés.

## Configuration
Copier l'exemple :
```bash
cp wrangler.example.toml wrangler.toml
```
Remplir bucket R2, DB D1, route, name, etc.

Secrets (ne pas mettre en clair dans `wrangler.toml`) à injecter :
```
wrangler secret put DISCORD_WEBHOOK_URL
wrangler secret put SENDINBLUE_API_KEY
wrangler secret put COOKIE_SECRET
wrangler secret put SESSION_SIGNING_KEY
wrangler secret put API_TOKEN_PEPPER
```

Variables côté `[vars]` (non sensibles) :
- `BASE_URL` : URL publique (sans slash final)
- `CLEANUP_ENABLED` : "true" / "false"
- `DISCORD_WEBHOOK_ENABLED` : active l'envoi
- `MAIL_SENDER`, `MAIL_SENDER_NAME`

## Installation & Dev
```bash
npm install
npm run dev          # Worker + assets
# Dans un autre terminal (si besoin d'init DB locale):
npm run local:d1:database   # applique schema.sql
npm run local:d1:migrate    # applique migrations (si présentes)
```
Déploiement :
```bash
npm run deploy
```
Logs temps réel :
```bash
npm run remote:tail
```

## Base de données D1
- `db/schema.sql` : structure initiale.
- `db/seed.sql` (si existant) : données de départ.
- Migrations : dossier `db/migrations` (configuré dans `wrangler.example.toml`).

Tables clés (résumé) :
- `users` (roles, avatar_key, created_at, disabled)
- `sessions` (session_id, user_id, expires)
- `api_tokens`
- `images` (id, owner_id nullable, size initiale, ext, original_name, auto_delete_at)
- `users_stats` (bytes cumulés images, counts)
- `audit_logs` (type, meta JSON)
- `captchas`
- `role_policies` (label, quotas)

## Rôles & Quotas
`role_policies` définit : limites, cooldowns, autoDeleteSec possible.
Route admin pour gérer : `/api/admin/role-policies` (CRUD). Changement rôle : `/api/admin/user/role`.

## Upload & Optimisation
POST `/api/upload` :
- Accepté : png, webp, avif, jpeg.
- PNG > 6MB : tentative lossless, si taille réduite on remplace.
- Réponse : `{ id, url, original_bytes, final_bytes, saved_bytes, saved_pct, via_api }`.
- `via_api` = vrai si Authorization Bearer + pas de Referer.
- Image servie via `/i/{id}.{ext}` avec `cache-control: public, max-age=31536000, immutable`.

## Endpoints Principaux (extraits)
- Auth: `/api/register`, `/api/login`, `/api/logout`, `/api/password/reset/*`.
- Session & profil: `/api/session`, `/api/me`, `/api/me/avatar` (POST pour changer avatar).
- Images: `/api/upload`, `/api/images` (list utilisateur), `/api/image/{id}` (DELETE propriétaire/admin).
- Captcha: `/api/captcha`.
- Admin summary: `/api/admin/summary` (ETag + immutable assets côté CDN).
- Admin images: `/api/admin/images` (+ via_api enrichi).
- Admin logs: `/api/admin/logs`.
- Maintenance actions: `/api/admin/cleanup`, purge sessions, logs, orphans, recalcul stats...

## Panneau Admin
`/admin.html` :
- Dashboard (stats, images récentes, IPs)
- Utilisateurs (activation/désactivation, changement rôle)
- Images (suppression, badge API)
- Logs (audit)
- Maintenance (cleanup, recalcul, webhooks test, orphans scan)
- Rôles (CRUD label, quotas)
- Lightbox image : compression (original vs final), pourcentage, badge API.

## Sécurité
- Sessions signées (cookie + store D1). 
- API Tokens (Bearer) avec audit (`via_api`).
- Captcha simple sur inscription pour limiter bots.
- Quotas/cooldowns par rôle (`checkQuota`).
- IP blocking (table `ip_blocks` + decay + manual set).
- Aucun accès anonyme aux endpoints admin (vérification rôle admin).
- Pas de suppression image via token public (rollback réalisé).

## Tâches planifiées & Maintenance
Cron (hourly) : `runCleanup` (sessions expirées, auto-delete images, captchas expirés, IP decay si implémenté). 
Maintenance manuelle : endpoints admin dédiés.

## Gestion des Secrets
Utiliser toujours `wrangler secret put` (pas dans TOML). Rotation conseillée à chaque fuite potentielle.
Discord webhook → régénérer si exposé. Clé email idem.

## Roadmap / Idées
- Stocker `final_size` dans `images`.
- Batch audit lookups (réduire N requêtes par page images admin).
- Suivre téléchargements (compteur, popularité).
- Thumbnails / variants WebP/AVIF automatiques.
- URL signées / hotlink protection optionnelle.
- UI pour régénérer token API, stats de consommation.

## Licence
Projet interne / privé (ajuster selon politique). Ajouter une licence si distribution prévue.

---
**Questions / Ajouts** : ouvrir une issue interne ou proposer une MR.
