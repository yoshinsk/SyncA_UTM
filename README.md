# SyncA UTM

SyncA UTM は AlmaLinux 9 系を基盤にした UTM / ルーターアプライアンスです。ローカル管理 GUI からネットワーク、ファイアウォール、VPN、DNS/DHCP、DDNS、証明書、バックアップ、fail2ban、Nginx リバースプロキシを管理します。

このリポジトリは、既存 SyncA UTM の公開アップデート元であり、オフラインインストール ISO を作成するためのソースツリーでもあります。

## 検証済み基準

- AlmaLinux 9.x、現時点では AlmaLinux 9.8 で検証
- `AlmaLinux-9-latest-x86_64-dvd.iso` を基にしたオフラインインストール ISO
- 初回起動時のコンソールセットアップ
- WAN / LAN からの管理 GUI 初期アクセス
- SyncA UTM 集中管理エージェントの 9.8 系 / 8.10 系対応

## 主な機能

### ネットワーク

- WAN の DHCP / 固定 IP / PPPoE
- LAN アドレスと DHCP 範囲の設定
- 静的ルート
- WAN / LAN のセカンダリ IP
- VLAN タグ付きインターフェース
- 複数 NIC のブリッジ構成
- PPPoE MTU / MSS 調整

### ファイアウォール

- firewalld によるルーティングとフィルタリング
- LAN から WAN への NAT / masquerade
- 初期WAN公開は管理GUIの `4444/tcp` のみ
- ポート転送追加時の該当zoneポート許可の自動追加
- PPTP / IPsec passthrough 向けの GRE / ESP / AH 転送補助
- UPnP / NAT-PMP の明示的な ON/OFF 管理 (既定は OFF)
- ISO インストール用 firewalld プロファイル
- GUI からのルール管理と手動ルール維持
- VPN トンネル作成時の必要許可追加

### VPN

- WireGuard サーバー / クライアント管理
- strongSwan site-to-site IPsec 管理
- peer ネットワーク向けファイアウォール許可の自動追加

### DNS / DHCP

- dnsmasq ベースの LAN DNS / DHCP
- DHCP オプションのインポートとプレビュー
- GUI からのローカル DHCP スコープ管理

### DDNS / 証明書

- `ddnsft.com` の DDNS ホスト名管理
- 既存ホスト検出
- 4 桁 PIN による既存 DDNS ホスト上書き承認
- SMTP 設定による PIN メール送信
- Let's Encrypt 証明書発行と更新
- `certbot-renew.timer` / `certbot.timer` / `snap.certbot.renew.timer` のうち利用可能な自動更新 timer をインストーラと GUI 起動時に補完
- ACME HTTP-01 実行中だけ firewalld の `80/tcp` を一時開放し、終了後に元の状態へ戻す renewal hook
- 証明書更新成功時に Nginx を reload する deploy hook
- GUI からの手動更新は certbot のランダム待機を無効化し、管理画面のタイムアウトによる中断を避ける
- 9 系 / 8 系とも、証明書検証に必要な時刻同期は `chronyd` を有効化する

### Nginx リバースプロキシ / WAF

- Nginx SSL 終端 / リバースプロキシ管理
- Let's Encrypt challenge パス処理
- ModSecurity / WAF 管理
- Sophos インポートプレビュー用の大きな XML アップロード対応

### fail2ban

- 公開サービス検出と jail 同期
- Ban IP 一覧表示
- Unban 操作
- Ban IP の ignore IP への移動

### バックアップ

- GUI からのアプライアンスバックアップ
- 既定保持: 10 世代または合計 2 GiB
- SyncA UTM 集中管理へのバックアップアップロード

### Sophos SG UTM インポート

- Sophos SG UTM XML インポートプレビュー
- インターフェース、静的ルート、DHCP、DHCP オプション、IPsec、Nginx リバースプロキシ、DDNS 候補、証明書情報の変換
- WebAdmin 証明書とローカルユーザー X509 証明書は自動復元対象外

## リポジトリ構成

- `payload/server-gui/`: SyncA UTM 管理 GUI と補助スクリプト
- `payload/firewalld-profiles/`: ISO インストール用 firewalld プロファイル
- `iso/`: Kickstart とインストーラ payload
- `scripts/`: bootstrap、検証、ISO ビルド用スクリプト
- `docs/`: 設計メモと ISO 要件

調査成果物、取得したサーバー状態、認証情報、秘密鍵、ログ、スクリーンショット、生成物、テスト出力は Git から除外します。

## SyncA UTM 集中管理

新規出荷環境では、private firstboot 環境ファイルに次の値を含めます。

```bash
SYNCA_CENTRAL_ENABLED=1
SYNCA_CENTRAL_URL=https://nsksys.com/syncautm/admin
SYNCA_CENTRAL_ENROLLMENT_TOKEN=<中央管理 .env の ENROLLMENT_TOKEN>
```

通常は `SYNCA_CENTRAL_ENABLED=1` です。公開 GitHub リポジトリには実トークンを入れません。初回起動後にインターネットへ接続されると、`central-agent` が集中管理の自動登録 API に接続し、端末別の `device_id`、`api_secret`、`sso_secret` を取得して `/etc/server-gui/central.json` に保存します。

既存 SyncA UTM は通常アップデートで `server_gui` と `bin` が更新されます。更新後の GUI 起動時に `central_sso` が集中管理用 systemd タイマーと `central.json` を補完します。出荷時環境変数または手動インストーラで登録トークンが入っていれば、状態レポートとバックアップアップロードが開始されます。

## ISO ビルド

公開ビルド経路には SMTP、DDNS、証明書、VPN、集中管理登録トークンなどの秘密情報を含めません。

内部 ISO ビルドでは、ビルドホスト上の private firstboot 環境ファイルを `SYNCA_PRIVATE_FIRSTBOOT_ENV` で渡します。このファイルに `SYNCA_CENTRAL_URL` と `SYNCA_CENTRAL_ENROLLMENT_TOKEN` を含めます。

```bash
SYNCA_PRIVATE_FIRSTBOOT_ENV=/root/synca-internal/firstboot.env \
SYNCA_PRIVATE_SMTP_DROPIN=/root/synca-internal-smtp/server-gui-ddns-smtp.conf \
RPM_DIR_SRC=/root/synca-install-repos \
SYNC_PRUNE_DVD_REPOS=1 \
SYNC_BUILD_WHEELHOUSE=1 \
ALMA_ISO=/root/SyncA_UTM_build/output/iso-build/AlmaLinux-9-latest-x86_64-dvd.iso \
OUTPUT_ISO=/root/SyncA-UTM-AlmaLinux-9-internal.iso \
./scripts/build-synca-utm-iso.sh
```

## 公開アップデート元

既存 SyncA UTM は既定で次の GitHub リポジトリをアップデート元にします。

```text
https://github.com/yoshinsk/SyncA_UTM
```

管理 GUI は設定されたブランチを確認し、GitHub アーカイブを取得して `payload/server-gui/` 配下の `server_gui` と `bin` を更新します。

## セキュリティ

アプライアンスバックアップ、`evidence/`、`/etc/server-gui`、WireGuard 鍵、IPsec PSK、DDNS 認証情報、SMTP 認証情報、Let's Encrypt 秘密鍵、NetworkManager 接続秘密情報、サーバーログはコミットしません。

`.gitignore` は生成 ISO と一般的な秘密情報ファイルを除外します。内部 ISO 専用ファイルはリポジトリ外、または ignore 済みローカルパスで管理します。

## ライセンス

別途ライセンスファイルが追加されない限り、ライセンスは proprietary です。
