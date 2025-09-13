-- Migration 007: ajoute colonne token_plain pour stocker le token API en clair (optionnel)
-- Sécurité: accessible uniquement via endpoints authentifiés de l'utilisateur.
-- Idempotent: ignore l'erreur si la colonne existe déjà.

-- 1. Ajouter colonne token_plain si absente
ALTER TABLE api_tokens ADD COLUMN token_plain TEXT;

-- 2. (Optionnel) Aucune rétro-population possible car les tokens sont hashés.
-- Les nouveaux tokens créés après cette migration auront token_plain rempli.

-- 3. Index facultatif si requêtes fréquentes sur created_at
CREATE INDEX IF NOT EXISTS idx_api_tokens_created ON api_tokens(created_at);
