// ------------------------------------------------------------
// [章5] パスワードのハッシュ化（Node 内蔵の scrypt を使用）
//   ・ユーザーごとにランダムなソルトを付けてハッシュ化する
//     → 同じパスワードでも保存される値が変わり、事前計算表（レインボーテーブル）が効かない
//   ・scrypt はわざと計算を重くしてあり、漏れたハッシュから総当たりで戻すのが難しい
//   保存形式: scrypt$N$r$p$<ソルト(base64)>$<ハッシュ(base64)>
// ------------------------------------------------------------
import crypto from "node:crypto";

const PREFIX = "scrypt";
const N = 16384; // 計算コスト
const r = 8;
const p = 1;
const KEY_LEN = 64;
const SALT_LEN = 16;

function scrypt(password: string, salt: Buffer, n: number, rr: number, pp: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LEN, { N: n, r: rr, p: pp }, (err, key) =>
      err ? reject(err) : resolve(key)
    );
  });
}

function format(salt: Buffer, key: Buffer): string {
  return [PREFIX, N, r, p, salt.toString("base64"), key.toString("base64")].join("$");
}

// 保存用：ソルトを生成してハッシュ化する
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_LEN);
  return format(salt, await scrypt(password, salt, N, r, p));
}

// 初期データ・移行用（起動時に一度だけ使う同期版）
export function hashPasswordSync(password: string): string {
  const salt = crypto.randomBytes(SALT_LEN);
  return format(salt, crypto.scryptSync(password, salt, KEY_LEN, { N, r, p }));
}

export function isHashed(stored: string): boolean {
  return stored.startsWith(PREFIX + "$");
}

// 照合：保存されているソルトとパラメータで同じ計算をして、一定時間比較で比べる
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== PREFIX) return false;
  const [, n, rr, pp, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, "base64");
  const actual = await scrypt(password, Buffer.from(saltB64, "base64"), Number(n), Number(rr), Number(pp));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

// 存在しないメールのときも同じだけ時間をかけるためのダミー（応答時間でアカウントの有無を悟らせない）
export const DUMMY_HASH = hashPasswordSync(crypto.randomUUID());
