FROM node:22-slim

WORKDIR /app

# 依存だけ先に入れてキャッシュを効かせる
COPY package.json ./
RUN npm install

# アプリ本体をコピー
COPY . .

EXPOSE 4100
CMD ["npm", "start"]
