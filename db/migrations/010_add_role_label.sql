-- Colonne label déjà dans schema.sql -> neutralisée.
-- Pour ancienne base sans la colonne, dé-commentez:
-- ALTER TABLE role_policies ADD COLUMN label TEXT;

-- Backfill des labels initiaux pour les rôles existants (exécuté une seule fois)
UPDATE role_policies
SET label = CASE role
	WHEN 'anon' THEN 'Invité'
	WHEN 'user' THEN 'Utilisateur'
	WHEN 'vip' THEN 'VIP'
	WHEN 'admin' THEN 'Administrateur'
	ELSE COALESCE(label, role)
END
WHERE label IS NULL;