// ============================================================
//  教材メモアプリ（攻撃前・脆弱性あり版）
//  このアプリは「AIで開発する人のためのセキュリティ入門」講座の教材です。
//  学習のために、わざと脆弱性を残しています。本番環境では絶対に使わないでください。
//  各脆弱性には [章X] のコメントを付けています。
// ============================================================
import express, { Request, Response, NextFunction } from "express";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import _ from "lodash"; // [章7] 古いバージョンを指定している（npm audit で警告が出る）
import { db, initDb } from "./db.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ------------------------------------------------------------
// [章3] 秘密情報は .env に置き、サーバー側だけで読み込む
//   process.env はサーバーの中だけにあり、ブラウザには届かない。
// ------------------------------------------------------------
const envPath = path.join(__dirname, "..", ".env");
if (fs.existsSync(envPath)) process.loadEnvFile(envPath);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY; // 今は未使用（置き場所の例）

const app = express();
const PORT = Number(process.env.PORT ?? 4100);

app.use(express.json());
// public/ の静的ファイルを配信（login.html, index.html, app.js）
app.use(express.static(path.join(__dirname, "..", "public")));

initDb();

// ------------------------------------------------------------
// ログイン中のユーザーを取り出す補助関数
// Authorization: Bearer <token> を見てセッションを引く
// ------------------------------------------------------------
function currentUserId(req: Request): number | null {
  const auth = req.header("authorization") ?? "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;
  const row = db.prepare("SELECT user_id FROM sessions WHERE token = ?").get(token) as
    | { user_id: number }
    | undefined;
  return row ? row.user_id : null;
}

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const uid = currentUserId(req);
  if (uid === null) {
    res.status(401).json({ error: "ログインが必要です" });
    return;
  }
  res.locals.userId = uid;
  next();
}

// ------------------------------------------------------------
// [章5] ログイン：総当たり対策なし
//   ・試行回数の制限やロックがない
//   ・パスワードは平文で保存・比較している
//   → 大量に試せば弱いパスワードのアカウントに入れてしまう
// ------------------------------------------------------------
app.post("/api/login", (req: Request, res: Response) => {
  const { email, password } = req.body ?? {};
  const user = db
    .prepare("SELECT id, email, password FROM users WHERE email = ?")
    .get(email) as { id: number; email: string; password: string } | undefined;

  if (!user || user.password !== password) {
    res.status(401).json({ error: "メールアドレスまたはパスワードが違います" });
    return;
  }

  const token = "tok_" + crypto.randomUUID();
  db.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").run(token, user.id);
  res.json({ token, userId: user.id, email: user.email });
});

// ログイン中のユーザー情報
app.get("/api/me", requireAuth, (_req: Request, res: Response) => {
  const uid = res.locals.userId as number;
  const user = db.prepare("SELECT id, email FROM users WHERE id = ?").get(uid);
  res.json(user);
});

// ------------------------------------------------------------
// [章4] ユーザー一覧：誰でも全員のメールアドレスを取得できる（列挙）
// ------------------------------------------------------------
app.get("/api/users", (_req: Request, res: Response) => {
  const users = db.prepare("SELECT id, email FROM users").all();
  res.json(users);
});

// 自分のメモ一覧（ここは自分のものだけ返している）
app.get("/api/memos", requireAuth, (_req: Request, res: Response) => {
  const uid = res.locals.userId as number;
  const memos = db.prepare("SELECT id, title, body, created_at FROM memos WHERE user_id = ?").all(uid);
  res.json(memos);
});

// ------------------------------------------------------------
// [章4] メモ詳細（API）：IDを指定すれば“持ち主の確認をせず”に返す
//   → ログインさえしていれば、他人のメモIDを指定して中身を読める（IDOR）
// ------------------------------------------------------------
app.get("/api/memos/:id", requireAuth, (req: Request, res: Response) => {
  const memo = db
    .prepare("SELECT id, user_id, title, body, created_at FROM memos WHERE id = ?")
    .get(Number(req.params.id));
  if (!memo) {
    res.status(404).json({ error: "見つかりません" });
    return;
  }
  res.json(memo); // 持ち主チェックをしていない
});

// メモの作成（自分のメモとして保存）
app.post("/api/memos", requireAuth, (req: Request, res: Response) => {
  const uid = res.locals.userId as number;
  const { title, body } = req.body ?? {};
  // [章7] lodash を使っている箇所（古いバージョンを使い続けている例）
  const clean = _.pick({ title, body }, ["title", "body"]);
  const info = db
    .prepare("INSERT INTO memos (user_id, title, body, created_at) VALUES (?, ?, ?, ?)")
    .run(uid, String(clean.title ?? ""), String(clean.body ?? ""), new Date().toISOString().slice(0, 10));
  res.json({ id: info.lastInsertRowid });
});

// ------------------------------------------------------------
// [章6-A] 検索：SQLをつなぎ合わせて作っている（SQLインジェクション）
//   本来は「自分のメモだけ」を検索するつもりだが、
//   q を文字列連結でSQLに埋め込んでいるため、条件を壊して全件取得できる。
//   例：q = %' OR '1'='1   /   q = ' UNION SELECT id,email,password,4 FROM users --
// ------------------------------------------------------------
app.get("/api/search", requireAuth, (req: Request, res: Response) => {
  const uid = res.locals.userId as number;
  const q = String(req.query.q ?? "");
  const sql =
    "SELECT id, title, body, user_id FROM memos " +
    "WHERE user_id = " + uid + " AND (title LIKE '%" + q + "%' OR body LIKE '%" + q + "%')";
  try {
    const rows = db.prepare(sql).all();
    res.json({ sql, rows }); // 学習しやすいよう、組み立てたSQLも返している
  } catch (e) {
    res.status(500).json({ sql, error: String(e) });
  }
});

// ------------------------------------------------------------
// [章6-B] メモ詳細ページ（画面）：メモの内容をそのままHTMLに差し込む（XSS）
//   title と body をエスケープせずに埋め込んでいるため、
//   <script> や <img onerror=...> を保存すると、表示時に実行される。
// ------------------------------------------------------------
app.get("/memo/:id", requireAuth, (req: Request, res: Response) => {
  const memo = db
    .prepare("SELECT id, title, body FROM memos WHERE id = ?")
    .get(Number(req.params.id)) as { id: number; title: string; body: string } | undefined;
  if (!memo) {
    res.status(404).send("見つかりません");
    return;
  }
  res.send(`<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>メモ詳細</title></head>
<body>
  <a href="/index.html">← 一覧へ</a>
  <h1>${memo.title}</h1>
  <div id="body">${memo.body}</div>
</body></html>`);
});

app.listen(PORT, () => {
  console.log(`メモアプリ起動: http://localhost:${PORT}`);
  console.log("※これは学習用の脆弱なアプリです。本番では使わないでください。");
});
