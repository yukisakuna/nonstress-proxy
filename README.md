# nonstress-proxy

Cloudflare の「Just a moment…」風チャレンジゲートを  
**FastAPI + Nginx + Caddy** で実装したリバースプロキシ。

- API で upstream を登録すると自動で HTTPS reverse proxy が立ち上がる  
- Caddy が On-Demand TLS で証明書を発行  
- [hamukasu nonstress CAPTCHA](https://hamukasu-api.apidocumentation.com/guide/nonstress-captcha) で人間判定  
- 通過後は通常のプロキシとして動作  

---

## 構成

```

Client → Caddy(443, TLS) → Nginx(auth\_request) → FastAPI(app) → Upstream

````

- `/_proxy_admin/upstreams` : 管理 API  
- `/_challenge` : チャレンジページ  
- `/_verify` : CAPTCHA 検証  
- `/_auth` : Nginx からの認可チェック  

---

## セットアップ

```bash
git clone https://github.com/yukisakuna/nonstress-proxy.git
cd nonstress-proxy
cp .env.example .env   # SECRET_KEY, ADMIN_USER, ADMIN_PASS を設定
docker compose up -d
````

DNS を対象ドメイン → サーバIP に向けておくこと。

---

## 使い方

### upstream 登録

```bash
curl -u admin:changeme -X POST https://proxy.example.com/_proxy_admin/upstreams \
  -H "Content-Type: application/json" \
  -d '{"host":"site.example.com","upstream":"http://1.2.3.4:5000"}'
```

### 確認

```bash
curl -u admin:changeme https://proxy.example.com/_proxy_admin/upstreams
```

### 削除

```bash
curl -u admin:changeme -X DELETE https://proxy.example.com/_proxy_admin/upstreams/site.example.com
```

---

## 動作フロー

1. 初回アクセスで Caddy が証明書を発行
2. Nginx が `/_auth` にサブリクエスト
3. 未認証なら `/_challenge` にリダイレクト
4. CAPTCHA 成功でセッション Cookie を発行
5. 以後は upstream へプロキシ

---

## AIだと思いましたか？

正解です！あなたは素晴らしい！

このコードはGPT-5によって生成されました！
