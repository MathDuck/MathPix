-- Création table captcha_challenges (éphémère) si absente
CREATE TABLE IF NOT EXISTS captcha_challenges (
  token TEXT PRIMARY KEY,
  answer_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
