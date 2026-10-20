// データベース初期化（Node 22 内蔵の node:sqlite を使用）
// ※この教材は学習用にわざと脆弱に作っています。本番では使わないでください。
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, "..", "data.sqlite");

export const db = new DatabaseSync(dbPath);

export function initDb(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT,
      api_key TEXT
    );
    CREATE TABLE IF NOT EXISTS memos (
      id INTEGER PRIMARY KEY,
      user_id INTEGER,
      title TEXT,
      body TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER
    );
  `);

  const count = db.prepare("SELECT COUNT(*) AS n FROM users").get() as { n: number };
  if (count.n === 0) {
    seed();
  }
}

function seed(): void {
  // 架空のユーザー。パスワードは学習用にそのまま保存（これも本来はダメな例）。
  const insertUser = db.prepare(
    "INSERT INTO users (id, email, password, api_key) VALUES (?, ?, ?, ?)"
  );
  insertUser.run(1, "alice@example.com", "sunflower-garden-42", "sk-live-alice-DO-NOT-SHARE-1a2b3c");
  insertUser.run(2, "bob@example.com", "password123", "sk-live-bob-DO-NOT-SHARE-9z8y7x");
  insertUser.run(3, "carol@example.com", "autumn-river-77", "sk-live-carol-DO-NOT-SHARE-5m4n3o");

  const insertMemo = db.prepare(
    "INSERT INTO memos (user_id, title, body, created_at) VALUES (?, ?, ?, ?)"
  );
  // alice のメモ
  insertMemo.run(1, "買い物リスト", "牛乳、卵、パン", "2026-10-01");
  insertMemo.run(
    1,
    "社外秘：新サービスの数字",
    "来期の売上目標は 1.2 億円。まだ公表前なので取り扱い注意。",
    "2026-10-05"
  );
  // bob のメモ（漏れると困る架空の個人情報）
  insertMemo.run(
    2,
    "顧客連絡先（架空）",
    "田中太郎 tanaka@example.com / 鈴木花子 suzuki@example.com / 契約更新は11月末",
    "2026-10-03"
  );
  insertMemo.run(2, "パスワード控え", "社内Wikiのパスワードは bob-wiki-2026", "2026-10-07");
  // carol のメモ
  insertMemo.run(3, "今日のタスク", "請求書の送付、議事録まとめ", "2026-10-08");
}
