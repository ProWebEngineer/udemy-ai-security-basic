# 教材メモアプリ（攻撃前・脆弱性あり版）

「AIで開発する人のためのセキュリティ入門」講座の教材です。
2人のユーザーがメモを管理する小さなWebアプリに、学習用の脆弱性をわざと仕込んでいます。

> **警告**
> このアプリは学習のために、わざと安全でない作りにしています。
> 本番環境では絶対に使わないでください。攻撃の練習は、自分のPCの中（このアプリ）だけで行ってください。
> 他人のサイトやサービスに同じことを試すのは、法律違反になります。

技術構成: TypeScript + Express + SQLite（Node 22 内蔵の `node:sqlite`。ネイティブビルド不要）

---

## 起動方法

### Docker で起動（おすすめ）

```bash
docker compose up
```

起動したら、ブラウザで http://localhost:4100/login.html を開きます。

### Docker を使わない場合

Node.js 22 以上が必要です。

```bash
npm install
npm start
```

### テスト用アカウント

| メールアドレス | パスワード | 備考 |
|---|---|---|
| alice@example.com | sunflower-garden-42 | メモ2件 |
| bob@example.com | password123 | 弱いパスワード（章5の標的） |
| carol@example.com | autumn-river-77 | メモ1件 |

### 初期状態に戻す

実演でデータを壊したら、次のコマンドで初期データに戻せます。

```bash
npm run seed
```

---

## このアプリに仕込んだ脆弱性（章ごと）

各章は「攻撃して漏れるのを見せる → なぜ起きるか → 直す → もう一度攻撃して防げるのを見せる」の順で進めます。
以下は、攻撃が成立することを確認するためのコマンド例です（`BASE=http://localhost:4100`）。

### 章3　秘密情報の漏れ

APIキーなどの秘密情報を、ブラウザに配信されるファイルに書いてしまっている例。

```bash
# フロントのJSを開くだけでAPIキーが読める
curl -s http://localhost:4100/app.js | grep sk-live
```

さらに、秘密情報を書いた `.env` を `.gitignore` から外しているため、git にそのまま含まれてしまう。

- 原因: `public/app.js` にAPIキーを直書き。`.env` を git 管理下に置いている。
- 対策: 秘密情報はサーバー側だけで持つ。`.env` は `.gitignore` に入れる。漏れたキーは失効させる。

### 章4　認可の抜け（他人のデータが見える）

ログインさえしていれば、IDを変えるだけで他人のメモを読めてしまう（IDOR）。

```bash
# aliceでログインしてトークンを取得
TOKEN=$(curl -s -X POST http://localhost:4100/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"sunflower-garden-42"}' \
  | sed -E 's/.*"token":"([^"]+)".*/\1/')

# aliceのトークンで、bob のメモ（#3, #4）を読む
curl -s http://localhost:4100/api/memos/4 -H "Authorization: Bearer $TOKEN"

# ついでに全ユーザーのメールアドレスも取れる
curl -s http://localhost:4100/api/users
```

- 原因: `/api/memos/:id` が「持ち主かどうか」を確認していない。`/api/users` が誰でも叩ける。
- 対策: メモを返す前に「そのメモの `user_id` がログイン中のユーザーと一致するか」を確認する。

### 章5　ログインの総当たり

ログインに試行回数の制限がないので、よくあるパスワードを機械的に試せば入れてしまう。

```bash
# bob に対してよくあるパスワードを順に試す（制限なくいくらでも試せる）
for pw in 123456 qwerty admin password password123 letmein; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:4100/api/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"bob@example.com\",\"password\":\"$pw\"}")
  echo "$pw -> $code"   # password123 で 200（ログイン成功）になる
done
```

- 原因: 試行回数の制限・アカウントのロックがない。パスワードが弱い＆平文保存。
- 対策: 一定回数失敗したら待たせる／ロックする。パスワードはハッシュ化して保存する。

### 章6　入力と出力の扱い

#### 6-A　SQLインジェクション

検索キーワードを文字列連結でSQLに埋め込んでいるため、条件を壊して全件を取り出せる。
（学習しやすいよう、組み立てたSQLをレスポンスに表示しています）

```bash
# 自分のメモだけ検索するつもりが、全ユーザーのメモを取り出せる
curl -s -G http://localhost:4100/api/search -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=%') OR 1=1 -- "

# UNION で全ユーザーのメール＋パスワードを抜き取る
curl -s -G http://localhost:4100/api/search -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=%') UNION SELECT id,email,password,0 FROM users -- "
```

- 原因: 入力値をそのままSQL文に連結している。
- 対策: プレースホルダ（パラメータ化クエリ）を使い、値をSQLの一部にしない。

#### 6-B　XSS（保存した内容がそのまま実行される）

メモの内容をエスケープせずHTMLに差し込んでいるため、保存したスクリプトが表示時に動く。

```bash
# スクリプト入りのメモを保存
curl -s -X POST http://localhost:4100/api/memos -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"test","body":"<img src=x onerror=alert(document.cookie)>"}'

# 保存したメモの詳細ページを開くと、エスケープされず埋め込まれているのが分かる
curl -s http://localhost:4100/memo/6 -H "Authorization: Bearer $TOKEN"
```

- 原因: 保存された内容を `innerHTML` 相当でそのままページに差し込んでいる。
- 対策: 表示するときにエスケープする（`<` を `&lt;` にするなど）。

### 章7　脆弱な依存パッケージ

古いバージョンのライブラリを使い続けている。

```bash
npm audit   # lodash が critical で報告される
```

- 原因: `package.json` で古い `lodash`（4.17.11）を指定している。
- 対策: `npm audit` で確認し、更新する。使っていないパッケージは外す。

---

## ディレクトリ構成

```
app/
├── docker-compose.yml   … docker compose up の設定
├── Dockerfile
├── package.json
├── .env                 … [章3] わざと git に含めている秘密情報
├── src/
│   ├── server.ts        … ルート定義。各脆弱性に [章X] のコメント
│   ├── db.ts            … DB初期化とテストデータ
│   └── seed.ts          … 初期状態に戻すスクリプト
└── public/
    ├── login.html
    ├── index.html
    └── app.js           … [章3] APIキーを直書きしている
```
