# docs/iso-requirements.md
# AlmaLinux 9.x ベース SyncA UTM インストールISO要件

## 目的

AlmaLinux 9.x の最小構成から、SyncA UTM として起動できる完全オフラインISOを作成する。ISOはインストール時にWAN/LAN/管理/DDNS/VPNの初期値を受け取り、初回起動後にSSH、管理GUI、LANからのインターネット接続、DDNS、証明書更新、VPN、Nginxリバースプロキシ、WAF、fail2ban、Firewalldプロファイルをローカルだけで構成できる状態にする。

## オフライン要件

- ISO作成時点のAlmaLinux 9.x最新安定版を基準にする。2026-05-30時点の実機検証はAlmaLinux 9.8。
- インストール中と初回起動中に外部リポジトリへ依存しない。
- ISO内にBaseOS、AppStream、CRB、Extras、EPELのRPMスナップショットを同梱する。
- `server-gui` のPython依存はwheelhouseまたはビルド済みvenvとして同梱する。
- Bootstrap、Bootstrap Icons、JavaScript/CSS、画像などGUI静的資産はローカル配布に固定する。
- `wireguard-ui` はバイナリまたは再現可能なローカルパッケージとして同梱する。
- 証明書取得、DDNS更新、日本IPセット取得、GitHub更新はインターネット接続後に実行する。ISOインストール自体の成否はこれらの外部通信に依存させない。

## インストール時入力

### 管理者

- Linuxログインユーザー名。
- Linuxログインパスワード。
- 管理GUIユーザー名。
- 管理GUIパスワード。
- sudo可能な管理ユーザーを作成する。
- 初期仕様ではSSH用sudoユーザーと管理GUIユーザーは同一ID、同一初期パスワードにできる。
- 初回ログイン後のパスワード変更強制は未決定。

### 管理アクセス許可元

- 管理許可CIDRを入力する。
- 初回起動時は次の両方から管理GUIへ到達できること。
  - WAN側グローバルIP経由。
  - LAN側IP経由。
- 初期許可ポートは次を基準にする。
  - `22/tcp`: SSH。
  - `4444/tcp`: SyncA UTM管理GUI。
  - `5011/tcp`: WireGuard UI。必要な場合のみ。

### DDNS

- DDNSサービスは `ddnsft.com` を前提にする。
- 入力させる値はホスト名の左辺だけにする。例: `example.ddnsft.com` の場合は `example`。
- ドメインは既定で `ddnsft.com`。
- インストール時にはDDNSプロバイダ登録を自動作成しない。初回起動後、管理GUIで運用者が登録する。
- DDNS登録前に `dig @ns1.ddnsft.com <host>.ddnsft.com A +short` で既存登録を確認する。
- 既に登録されているホスト名は通常登録を拒否する。
- 自身で運用中のホスト名を上書きする場合のみ、4桁数字PINを入力すると登録を許可する。
- 4桁PINは `syncautm@nsksys.com` にメール送信する。保存時に既存ホスト名を検出した場合はPINを自動発行する。
- ISOには `bind-utils` と `/usr/sbin/sendmail` 互換MTAを同梱する。
- 25/tcpで外部MXへ直接配送できない環境があるため、PINメールはSMTP submission設定も利用可能にする。
  - `SYNCA_DDNS_PIN_SMTP_HOST`
  - `SYNCA_DDNS_PIN_SMTP_PORT`
  - `SYNCA_DDNS_PIN_SMTP_USER`
  - `SYNCA_DDNS_PIN_SMTP_PASS`
  - `SYNCA_DDNS_PIN_SMTP_FROM`
  - `SYNCA_DDNS_PIN_SMTP_SSL`
- DDNS認証ユーザーとパスワードは必要なサービスの場合のみ保存する。`ddnsft.com` の既定プリセットには認証情報を埋め込まない。
- WAN IP確定後、登録済みDDNSプロバイダがある場合だけDDNS更新を行い、FQDN到達確認後にLet's Encrypt取得へ進む。

### WAN

いずれか1方式を選択する。

- DHCP。
  - WAN NIC。
  - DNSの取得方針。
- Static。
  - WAN NIC。
  - IPアドレス/プレフィックス。
  - デフォルトゲートウェイ。
  - DNSサーバー。
- PPPoE。
  - 物理WAN NIC。
  - PPPoEユーザー名。
  - PPPoEパスワード。
  - MTU/MRU。既定は1492。
  - TCP MSS clamp。MTUブラックホール対策として有効化する。

### LAN

- LAN NIC。
- LAN IPアドレス/プレフィックス。
- DHCP配布開始アドレス。
- DHCP配布終了アドレス。
- DHCPリース時間。
- DHCPで配布するDNS。
- DHCPで配布するゲートウェイ。
- LAN NICが複数ある場合、ブリッジ化の有無を選択する。
- ブリッジ化する場合、参加NICとSTP有効/無効を指定する。

### WireGuard

- WireGuardインターフェース名。既定は `wg0`。
- SyncA UTMが持つWireGuard仮想NICのIP。例: `10.252.1.1/24`。
- クライアント割当範囲。例: `10.252.1.2-10.252.1.254`。
- Listen port。既定は `51820/udp`。
- Endpoint FQDN。DDNS FQDNを既定にする。
- AllowedIPs方針。
  - スプリットトンネル: LAN CIDRとWireGuard CIDR。
  - フルトンネル: `0.0.0.0/0` と `::/0`。

### IPsec strongSwan

- 初期ISOでは接続テンプレートを同梱し、対向ごとの設定はGUIから追加する。
- トンネル追加時、対向ローカルCIDRからの通信をFirewalldで自動許可する。
- ISOビルド前の検証条件として、既存のstrongSwan SAを切断しないこと。

## 初回起動シーケンス

1. 管理ユーザー、GUI認証、基本設定を作成する。
2. NetworkManagerでWAN/LAN/ブリッジ/PPPoEを構成する。
3. LAN IPとDHCP/DNSを構成する。
4. Firewalldの基本プロファイルを適用する。
5. LANからWANへのNATとforwardを有効化する。
6. WireGuard、strongSwan、Nginx、server-gui、fail2banを起動する。
7. WAN疎通確認後、登録済みDDNSプロバイダがあればDDNSを更新する。初期状態ではDDNS登録は空にする。
8. DDNS解決確認後、Let's Encrypt証明書を取得する。DDNS未登録の場合は自己署名証明書のままGUIを継続稼働する。
9. 初回インターネット接続完了時に日本IPセットを取得し、管理対象国として自動登録する。
10. certbot、DDNS、GeoIP、backup、更新確認のtimerを有効化する。

## Firewalldプロファイル

- ISOではFirewalld設定をprofileとしてテンプレート化する。
- 既存環境で検証したカスタムルールは、実機固有値を変数化したFirewalld profileとして同梱対象にする。
- WAN zoneは原則DROP/REJECT寄りにし、必要ポートだけを開ける。
- LAN zoneはDHCP、DNS、管理GUI、LANからWANへのforwardを許可する。
- WireGuard zoneは `wg0` とWireGuard CIDRを許可する。
- IPsec remote subnetはトンネル追加時に自動許可する。
- Nginxリバースプロキシのvhost追加時、listen portをFirewalldへ追加する。既存接続を壊さないようadd-onlyで適用する。
- 日本IPセットが存在する前提のルールがあるため、初回オンライン時のJP ipset取得とzone反映を必須処理にする。

## Nginxリバースプロキシ

- GUI管理vhostは `/etc/nginx/conf.d/vhost-*.conf` に生成する。
- backend定義はGUIのJSON設定から生成する。
- 既定proxy headerは次を含める。
  - `Host`
  - `X-Real-IP`
  - `X-Forwarded-For`
  - `X-Forwarded-Proto`
  - `X-Forwarded-Host`
  - `X-Forwarded-Port`
- ACME webrootは `/var/www/letsencrypt` を標準にする。
- vhostには `/.well-known/acme-challenge/` をwebrootで受けるlocationを入れる。
- HTTP/HTTPS vhostが存在する場合、Let's Encrypt取得はstandaloneよりwebrootを優先する。standaloneはnginx停止を伴い、GUI接続が一時切断されるためフォールバック扱いにする。

## WAF / ModSecurity

実機テスト環境で次の構成を確認済み。

- OS: AlmaLinux 9.8。
- Nginx module path: `/usr/lib64/nginx/modules`。
- Nginxの標準include: `/usr/share/nginx/modules/*.conf`。
- 必須RPM。
  - `nginx-mod-modsecurity`。EPEL。
  - `libmodsecurity`。EPEL。
  - `ssdeep-libs`。EPEL。
  - `mod_security`。AppStream。
  - `mod_security_crs`。AppStream。
- 依存RPMの例。
  - `apr`
  - `apr-util`
  - `httpd`
  - `httpd-core`
  - `httpd-filesystem`
  - `httpd-tools`
  - `libmaxminddb`
  - `yajl`
  - `mod_http2`
  - `mod_lua`
- 配置パス。
  - Nginx動的モジュール: `/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so`。
  - load_module設定: `/usr/share/nginx/modules/mod-modsecurity.conf`。
  - ModSecurity基本設定: `/etc/nginx/modsecurity.conf`。
  - SyncA UTM用ルール入口: `/etc/nginx/modsec/main.conf`。
  - CRS setup: `/etc/httpd/modsecurity.d/crs-setup.conf`。
  - CRS active rules: `/etc/httpd/modsecurity.d/activated_rules/*.conf`。
- `/etc/nginx/modsec/main.conf` はISOインストーラーで作成する。

```nginx
# Managed by SyncA UTM installer.
# Enables the packaged ModSecurity v2 engine and OWASP CRS on AlmaLinux 9.
Include /etc/nginx/modsecurity.conf
SecRuleEngine On
Include /etc/httpd/modsecurity.d/crs-setup.conf
Include /etc/httpd/modsecurity.d/activated_rules/*.conf
```

この状態でGUIのWAF設定欄は `modsecurity_available: true`、`modsecurity_rules_file_exists: true` と判定できる。ISOには上記RPMと設定ファイルを必ず含める。
`IncludeOptional` はModSecurityルールファイル内では使用しない。実機の一時vhostで `modsecurity on;` と `modsecurity_rules_file /etc/nginx/modsec/main.conf;` を指定し、`nginx -t` が成功することを確認済み。

## fail2ban

- SSH、Nginx、管理GUI、公開中vhostを監視対象にする。
- GUIから公開ポートを同期し、安全なfilterがあるものだけjailを自動生成する。
- 安全なfilterがないポートは日本語理由を表示し、自動生成しない。
- ban中IP一覧、ban理由、unban、ignoreipへの移行をGUIから操作できる。
- ignoreip永続化ファイルは `/etc/fail2ban/jail.d/server-gui-ignoreip.local` を標準にする。

## Let's Encrypt

- certbotとrenew timerを同梱する。
- 初回証明書はDDNS更新とFQDN到達確認後に取得する。
- renewal hookでnginx reloadを行う。
- HTTP-01のため、80/tcpの扱いをFirewalld profileで定義する。

## バックアップ

- GUIバックアップは最低限次を含む。
  - `/etc/server-gui`
  - `/etc/nginx`
  - `/etc/letsencrypt`
  - `/etc/firewalld`
  - `/etc/NetworkManager/system-connections`
  - `/etc/wireguard`
  - `/etc/swanctl`
  - `/etc/strongswan`
  - `/etc/fail2ban`
  - `/var/lib/server-gui`
- ISOビルド前に現行バックアップの復元テストを行う。

## アップデート

- インストール後、公開GitHubから更新できる構成にする。
- オフラインISOの初期導入と、オンライン更新経路を分離する。
- 更新時はGUI/SSH/VPNを落とす可能性がある操作を事前に表示し、rollback可能にする。

## ISOビルド前の確認項目

- AlmaLinux 9.8最小構成から、外部リポジトリなしで全RPMが導入できる。
- Python wheelhouseまたはvenvだけでserver-guiが起動する。
- Bootstrap等のGUI資産が外部CDNへ依存していない。
- PPPoE、Static、DHCPのWAN設定が再現できる。
- LAN DHCPとLANからインターネットへのNATが動作する。
- PPPoE環境でMSS clampが有効で、MTUブラックホールを起こさない。
- DDNSFT.COMのホスト左辺だけでDDNS更新できる。
- 既存DDNSホスト名はPINなしで登録できず、4桁PINは `syncautm@nsksys.com` に届く。
- Let's Encrypt証明書取得とrenewalが動作する。
- 日本IPセットが初回オンライン時に取得され、Firewalldに反映される。
- strongSwan VPNが切断されない。
- 各NICのIPアドレスが意図せず変化しない。
- SSHとGUIが接続不可にならない。
- WireGuard接続後、WireGuard CIDRとLAN CIDRへ疎通できる。
- Nginxリバースプロキシで外部FQDNから内部backendへ到達できる。
- ModSecurity導入済み状態でGUIのWAF警告が表示されない。
- fail2banのban/unban/ignoreip移行がGUIから動作する。
