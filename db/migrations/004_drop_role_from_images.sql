-- 004: Retrait colonne role de images + recréation index
PRAGMA foreign_keys=OFF;
-- BEGIN TRANSACTION; -- transactions SQL non supportées, laisser Wrangler gérer
CREATE TABLE images_new (
  id TEXT PRIMARY KEY,
  owner_id TEXT,
  key TEXT NOT NULL,
  ext TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  ip TEXT NOT NULL,
  auto_delete_at INTEGER,
  FOREIGN KEY (owner_id) REFERENCES users(id)
);
INSERT INTO images_new (id,owner_id,key,ext,content_type,size,created_at,ip,auto_delete_at)
  SELECT id,owner_id,key,ext,content_type,size,created_at,ip,auto_delete_at FROM images;
DROP TABLE images;
ALTER TABLE images_new RENAME TO images;
CREATE INDEX IF NOT EXISTS idx_images_owner ON images(owner_id);
CREATE INDEX IF NOT EXISTS idx_images_ip ON images(ip);
CREATE INDEX IF NOT EXISTS idx_images_autodel ON images(auto_delete_at);
-- COMMIT; -- non supporté
PRAGMA foreign_keys=ON;