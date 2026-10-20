// フロントエンドのスクリプト
// ------------------------------------------------------------
// [章3] 秘密情報をフロントに書いてしまっている悪い例
//   APIキーはブラウザに配信されるファイルに書くと、誰でも見られてしまう。
//   （開発者ツールやソース表示、/app.js を直接開くだけで読める）
// ------------------------------------------------------------
const OPENAI_API_KEY = "sk-live-frontend-DO-NOT-SHARE-aaa111bbb222";

function getToken() {
  return localStorage.getItem("token");
}

async function login(email, password) {
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error("ログインに失敗しました");
  const data = await res.json();
  localStorage.setItem("token", data.token);
  localStorage.setItem("email", data.email);
  return data;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + getToken(),
      ...(options.headers || {}),
    },
  });
  return res.json();
}

async function loadMemos() {
  const memos = await api("/api/memos");
  const ul = document.getElementById("memos");
  ul.innerHTML = "";
  for (const m of memos) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = "/memo/" + m.id;
    a.textContent = m.title + "（#" + m.id + "）";
    li.appendChild(a);
    ul.appendChild(li);
  }
}

async function createMemo(title, body) {
  await api("/api/memos", { method: "POST", body: JSON.stringify({ title, body }) });
  await loadMemos();
}

async function search(q) {
  const data = await api("/api/search?q=" + encodeURIComponent(q));
  const pre = document.getElementById("search-result");
  pre.textContent = JSON.stringify(data, null, 2);
}
