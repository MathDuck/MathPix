-- 003: Retrait colonne role de sessions
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE sessions_new (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
INSERT INTO sessions_new (id,user_id,expires_at,created_at)
  SELECT id,user_id,expires_at,created_at FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
COMMIT;
PRAGMA foreign_keys=ON;