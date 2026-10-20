// データを初期状態に戻すスクリプト（実演のあとにやり直すとき用）
//   使い方: npm run seed
import { db, initDb } from "./db.js";

db.exec(`
  DROP TABLE IF EXISTS sessions;
  DROP TABLE IF EXISTS memos;
  DROP TABLE IF EXISTS users;
`);
initDb();
console.log("初期データに戻しました。");
