# SyncA UTM

SyncA UTMはAlmaLinux9系を基盤とするUTM・ルーターアプライアンスです。ローカル管理GUIでネットワーク、WAN回線品質診断、ファイアウォール、AI防御、VPN、DNS/DHCP、DDNS、証明書、バックアップ、fail2ban、Nginxリバースプロキシを管理できます。

このリポジトリには、既存のSyncA UTMへ配信する更新と、オフラインインストールISOの作成に必要なソースを収録しています。

## 検証済み基準

- AlmaLinux 9.x、現時点では AlmaLinux 9.8 で検証
- `AlmaLinux-9-latest-x86_64-dvd.iso` を基にしたオフラインインストール ISO
- 初回起動時のコンソールセットアップ
- WAN / LAN からの管理 GUI 初期アクセス
- SyncA UTM 集中管理エージェントの 9.8 系 / 8.10 系対応

## 主な機能

### 管理メニュー

デスクトップの左メニューとハンバーガーメニューには、同じ区分と順序の階層メニューが表示されます。カテゴリ名を選択すると、その区分に属する画面へのリンクを開閉できます。現在表示している画面が属するカテゴリは、初期状態で展開済みです。画面の分類は次のとおりです。

| 区分 | 画面 |
| --- | --- |
| TOP | ダッシュボード |
| Network | ネットワーク、DHCP、DNS、IPv6、UPnP |
| Check | WAN品質 |
| Defense | 国別IP、Firewall、fail2ban、AI防御 |
| VPN | IPsec、WireGuard |
| Publish | DDNS、Nginx、証明書 |
| Manage | 管理、バックアップ、Sophos取込 |

### ネットワーク

- WAN の DHCP / 固定 IP / PPPoE
- PPPoE から DHCP / 固定 IP へ切り替える際の親WAN NICプロファイル自動準備
- LAN アドレスと DHCP 範囲の設定
- 静的ルート
- WAN / LAN のセカンダリ IP
- VLAN タグ付きインターフェース
- 複数 NIC のブリッジ構成
- PPPoE MTU / MSS 調整

### WAN回線品質診断

「WAN品質」画面は、現在の IPv4 既定経路で回線品質を手動測定する画面です。自動測定は行わないため、WAN 通信は管理者が実行したときだけ発生します。結果は直近 20 件をローカルに保存します。

遅延と転送速度は、同じ IPv4 WAN インターフェースで測定します。転送測定の接続待ちは最大 10 秒、DNS 解決から転送完了までの上限は下り・上りそれぞれ 45 秒です。接続できない IPv6 アドレスが先に返される環境でも、IPv4 の測定が長い接続待ちで中断されないようにしました。

遅延測定では各測定先に 4 回の ICMP echo を送ります。`ping` がない既存装置では、GUI サービスの ICMP ソケットで測定できます。この処理はパッケージやネットワーク設定を変更しません。新規 ISO には `ping` を提供する `iputils` を含めます。

転送を最後まで完了できなかった場合は速度を表示せず、DNS、接続、TLS、時間超過などの原因を表示します。遅延や転送の一部が測定できなかった場合、総合状態は「要確認」になります。

| 計測項目 | 内容 | 読み方 |
| --- | --- | --- |
| 下り速度 | Cloudflare の固定測定先から約 20 MB を受信して求める実効速度 | 契約上の最大速度ではありません。宅内利用状況、測定先、経路の混雑で変動します。 |
| 上り速度 | Cloudflare の固定測定先へ約 10 MB を送信して求める実効速度 | バックアップやクラウド送信の目安になります。 |
| 平均 RTT | Cloudflare DNS、Google Public DNS、Quad9 DNS への ping 往復時間 | 小さいほど応答性の目安になります。Web会議や VPN の遅延確認に使えます。 |
| RTT のばらつき | ping の mdev | 値が大きい場合は、応答時間が不安定な可能性があります。 |
| パケット損失 | 送信した ping に対して応答がなかった割合 | 損失が継続する場合は、回線、物理リンク、上位機器を確認してください。 |
| WAN リンク状態 | 既定経路、carrier、MTU、リンク速度、受信・送信エラー、破棄の累計値 | エラーや破棄の増加傾向は、物理リンクや上位機器を調べる材料になります。 |

画面の「大きな異常なし」「要確認」は、固定の参照先に対する一回の測定を整理するための表示です。ISP障害や契約速度を確定する判定ではありません。

### ファイアウォール

- firewalld によるルーティングとフィルタリング
- LAN から WAN への NAT / masquerade
- 初期WAN公開は管理GUIの `4444/tcp` のみ
- ポート転送追加時の該当zoneポート許可の自動追加
- PPTP / IPsec passthrough 向けの GRE / ESP / AH 転送補助
- UPnP / NAT-PMP の明示的な ON/OFF 管理 (既定は OFF)
- ISO インストール用 firewalld プロファイル
- GUI からのルール管理と手動ルール維持
- PublicのIPセット許可制
- VPN トンネル作成時の必要許可追加

#### CVE-2026-98432の暫定緩和

LinuxカーネルのIPv4 TCP処理に関するCVE-2026-98432に対し、[Red Hat RHSB-2026-016](https://access.redhat.com/security/vulnerabilities/RHSB-2026-016)の緩和ルールを専用nftablesテーブルへ登録します。これは攻撃への露出を減らす暫定措置であり、完全な防御や修正済みカーネルへの更新の代替ではありません。

専用テーブルは`inet synca_cve_2026_98432`です。`input`フックの優先度`-310`で、UTM自身へ届くIPv4 TCPのうち、IPヘッダー長が5ワードを超えるパケットを遮断します。ルールは`ip protocol tcp ip hdrlength > 5 counter drop`です。IPv4のIPオプションを対象とし、通常のTCPオプションとは区別します。IPオプションを必要とするTCP通信には影響するため、適用前に利用状況を確認してください。IPv6、UDP、UTMを通過する転送通信は対象外です。背後のサーバーには、そのサーバー自身の対策が必要です。

更新後のGUI起動時に、専用systemdサービス`synca-cve-2026-98432.service`を導入し、既定で有効化します。旧版の更新処理から今回の版へ更新した場合も、再起動後のGUI起動処理で導入します。今回の版以降の更新処理では、導入に失敗した場合は更新失敗として記録します。新規ISOのインストール処理にも導入を組み込みました。`nftables.service`の有効化や`flush ruleset`は行わず、専用テーブルだけを操作します。

ルールは`nft --check`で検査してから単一バッチで適用します。専用テーブルが正常なら再作成せず、遮断カウンターを維持します。構造が不一致の場合は、専用テーブルの削除と再作成を同じバッチで行います。起動時適用はGUIとは独立したサービスで行い、GUI起動時にも状態を確認して修復します。他のツールによる全ルール消去を継続監視する機能はありません。

「Defense」→「Firewall」→「CVE-2026-98432 暫定緩和」では、ルールの有効状態、起動時適用、サービス状態、解除指定、遮断カウンターを確認できます。有効化と解除も同じ画面から操作できます。状態判定ではテーブルの存在だけでなく、フック、優先度、条件、遮断動作を照合します。「有効」は暫定ルールの適用状態であり、カーネル修正済みという意味ではありません。

CLIでは次のコマンドを使用します。`enable`は現在のルールと起動時適用を有効にし、`disable`はサービスを無効化して専用テーブルを削除します。解除指定は`/etc/server-gui/cve-2026-98432.disabled`に保存され、GUI更新・再起動後も保持されます。再有効化する場合はGUIまたは`enable`を使ってください。

```bash
cd /opt/server-gui
sudo /opt/server-gui/venv/bin/python -m server_gui.cve_2026_98432 status
sudo /opt/server-gui/venv/bin/python -m server_gui.cve_2026_98432 enable
sudo nft list table inet synca_cve_2026_98432
sudo systemctl status synca-cve-2026-98432.service
# 修正済みカーネルで稼働していることを確認した後の解除
sudo /opt/server-gui/venv/bin/python -m server_gui.cve_2026_98432 disable
```

修正済みカーネルかどうかは、ディストリビューションの公式アドバイザリーと稼働中の`uname -r`を照合してください。修正パッケージをインストールしただけでは、稼働中カーネルが切り替わったとは判断できません。この機能ではカーネル更新や再起動、修正済み判定、暫定ルールの自動解除は行いません。

回帰テストは`python scripts/test-cve-2026-98432.py`で実行します。Linuxの実パケット検証は`sudo unshare --net python3 scripts/test-cve-2026-98432-network.py`で、隔離ネットワーク名前空間内に限定して実行できます。ホストのネットワーク名前空間では実行を拒否します。

2026年10月31日のAlmaLinux 9.8隔離環境では、通常のIPv4/IPv6 TCPとIPオプション付きUDPの通過、IPオプション付きIPv4 TCPの遮断、カウンター保持、解除後の通常TCP接続、他テーブルの維持を確認しました。

同日のAlmaLinux 8.10（nftables 1.0.4）と9.8（nftables 1.0.9）の実機検証では、自己更新後の導入を確認しました。更新履歴の成功状態とインストール済みSHAを確認し、GUI/APIの表示をカーネル上の専用テーブル・ルールと照合しています。両系統で暫定ルールが有効、起動時適用がenabled、専用サービスがactiveかつResult=success、解除指定なしの状態でした。systemdユニットの構文検査も通過しています。

実機上のローカル試験用TCPソケットでは、通常のTCP接続が成功し、IPオプション付きTCPが遮断され、遮断カウンターが増加することを両系統で確認しました。未認証のAPI呼出しとCSRFトークンのない設定変更要求を拒否すること、検証後もSSH・GUI・firewalldが利用できることも確認しています。実機の検証では通信ルールの変更、OS再起動、firewalld reloadは実施していません。起動時適用の登録は確認済みですが、再起動後の自動適用とreload前後のルール保持は今回の実機検証に含みません。

#### 同一LAN内の全IP通信許可

「Defense」→「Firewall」→「LAN内の通信許可」で、表示されたインターフェースとIPv4サブネットを確認し、「全IP通信を許可」を選択します。例えば`br-lan / 192.168.1.0/24`では、送信元・宛先がともに`192.168.1.0/24`である全IPプロトコル・全ポートの転送を許可します。対象は、IPv4アドレスが設定され、`trusted`ゾーンに所属し、IPv4のデフォルト経路に使用されていないインターフェースです。`/0`と`/31`・`/32`は対象外です。

転送専用のfirewalld policy `synca-lan-internal`は、入口・出口をともに`trusted`、targetを`CONTINUE`、priorityを`-109`に設定します。許可ルールは送信元・宛先の両方を対象サブネットに限定します。ゾーンのrich ruleだけでは端末間転送の許可にならないため、policyへ登録します。同名policyの入口・出口・target・priorityが異なる場合は、適用を中止します。

初回は空の専用policyを永続設定に作成し、既存の管理アクセス保護付きfirewalld reloadとfail2banの再反映を実行します。その後の有効・無効切替では、専用ルールの実行時設定と永続設定だけを変更します。途中で失敗した場合は、その操作で変更したルールを元に戻し、復元に失敗した場合もエラーを表示します。policyの実行時・永続設定が不一致の場合は適用を中止するため、管理者が設定を確認してください。

「専用ルールを削除」は、この機能の許可ルールだけを削除します。既存の`trusted`全許可設定を無効にする操作ではありません。WAN側の受信ポート、IPv6、IP以外のL2プロトコル、端末側のファイアウォールは変更しません。同じスイッチ内で直接通信する端末同士のパケットは、UTMを通らない場合があります。LANアドレスやゾーンを変更する前に専用ルールを削除し、変更後のサブネットで設定し直してください。

2026年10月29日のAlmaLinux 9.8実機検証では、認証後のGUI/APIで有効化・削除・再有効化・同じ設定の再適用を確認しました。実行時・永続設定とカーネルの転送用ルールを照合し、未認証、CSRFトークン欠落、WAN指定、対象外CIDR、不正な有効値を拒否することも確認しました。SSHとGUIの再接続、WANデフォルト経路、関連サービスの稼働を確認しています。8.10系の実機動作、再起動後の動作、端末間の全プロトコルを用いた実通信は未検証です。永続設定の保存は確認しています。

TCP 1433の障害では、UTMの許可設定とデータベースの接続復旧を分けて確認してください。サーバーの待受ポート、SQL ServerのTCP/IP設定、サーバー側ファイアウォール、クライアントの接続先・サブネットマスクを確認し、実際の接続元から再試験します。UTMからの接続確認だけでは、クライアント固有の制限やアプリケーション認証の成否は確定できません。

回帰テストは`python scripts/test-firewall-lan-access.py`で実行します。許可範囲、WAN・他ゾーンの除外、専用policyの範囲、実行時・永続設定の不一致、再適用、途中失敗時の復元を確認します。

##### TCP 1433に接続できない場合の切り分け

UTMでLAN内通信を許可していても、データベースサーバー側のfirewalldが接続を拒否・破棄する場合があります。サーバー側の設定変更後にクライアントから接続できた場合は、その変更内容と再試験結果を復旧の根拠として記録してください。UTM側の設定変更だけで復旧したとは判断しません。

1. 接続元端末とサーバーのIPアドレス、サブネットマスク、接続先名、実際の待受ポート、エラー内容を確認します。同一サブネットでは端末間で直接通信する場合があるため、UTMを通過する経路かも確認してください。SQL Serverの名前付きインスタンスでは、TCP 1433以外で待ち受けている場合があります。
2. 問題のクライアントから対象ポートへのTCP接続を試します。WindowsではPowerShellの`Test-NetConnection -ComputerName DB_SERVER_IP -Port 1433`を使えます。`DB_SERVER_IP`は実際のサーバーIPに置き換えてください。pingや別ポートへの接続成功は、TCP 1433の許可を証明するものではありません。
3. UTMからも同じサーバー・ポートへ接続し、結果を比較します。UTMからの接続はUTM自身が送信元になるため、クライアントからの転送経路や接続元ごとの制限は検証できません。UTMから成功してもクライアントから失敗する場合は、クライアント側の経路と、サーバー側の接続元制限を確認します。
4. サーバー側でサービスの起動状態、TCP/IPの有効化、待受アドレスとポートを確認します。Linuxでは以下の読み取り専用コマンドで、TCP 1433の待受とfirewalldの実行時・永続設定を確認できます。待受がない場合は、先にデータベースのサービス設定を確認してください。

   ```bash
   sudo ss -lntp '( sport = :1433 )'
   sudo firewall-cmd --state
   sudo firewall-cmd --get-active-zones
   sudo firewall-cmd --list-all-zones
   sudo firewall-cmd --permanent --list-all-zones
   ```

5. サーバーへ到着するインターフェースや送信元に適用されるゾーンを確認し、対象ポート、サービス定義、rich rule、拒否・破棄ルール、実行時と永続設定の差を調べます。許可が必要な場合は、必要な接続元と待受ポートに範囲を限定してください。切り分けのためにサーバーのfirewalld全体を停止する必要はありません。
6. 必要に応じてサーバー側とUTM側でパケットを取得し、同じ時刻・接続元・宛先・ポートの通信を照合します。SYNが送出されているのに応答がない場合、送出地点より先の経路、サーバー側の制限、待受状態を確認します。SYNだけでサーバー側firewalldが原因とは断定できません。同じスイッチ内で完結する通信では、UTM側にパケットが現れないこともあります。
7. サーバー側の設定変更後、最初に失敗したクライアントからTCP接続とアプリケーションの接続を再試験します。TCP接続だけ成功し、アプリケーションが失敗する場合は、認証情報、接続先インスタンス、TLS設定などを確認してください。変更した許可ルールの実行時・永続設定も照合します。

この手順は、サーバー側firewalldの設定変更後にクライアントからの通信が復旧した事例を一般化したものです。顧客のIPアドレス、接続情報、調査ログは掲載していません。今回の追記は文書のみで、実機設定の変更や追加試験は行っていません。

#### PublicのIPセット許可制

「Firewalld」の「PublicをIPセット許可制に切替」で、WANから接続を受け付ける送信元をIPセットで指定できます。選択したIPセットは許可ゾーンへ移します。許可ゾーンの既定値は`japan`です。

「public zoneの公開サービス/ポートを閉じる」を選んで適用すると、公開サービスとポートを許可ゾーンへ引き継ぎます。公開サービスとポートは、許可ゾーンに登録された送信元から受け付ける構成です。`public`ゾーンの対象は`DROP`に設定され、適用状態とゾーン設定はGUIで確認できます。

適用時は各ゾーンの送信元一覧を一度だけ取得します。取得済みの一覧を再利用するため、IPセットを移すたびにゾーンの詳細を照会する処理は不要です。一覧の取得に失敗した場合は、既存ゾーンの公開設定を変更する前に処理を中止します。

LANの経路制御に使うIPセットは、既存のLAN用設定を維持してください。外部向けの許可ゾーンへ移すと、LAN端末のゾーン分類も変わり、DNSなどの通信に影響します。

2026年10月8日のAlmaLinux 9.8実機検証では、外部向け9個のIPセットを指定したGUIの適用処理が約56秒で完了しました。9.8系の`main`と8.10系の`codex/almalinux8-iso`には、同じ修正と回帰テストを反映しています。8.10系の実機検証は未実施です。

開発環境では、リポジトリのルートから次のコマンドで回帰テストを実行できます。複数IPセットでも送信元一覧をゾーンごとに一度だけ取得すること、一覧の取得失敗時に既存設定を変更しないこと、移動失敗時に取得済みの一覧を維持することを確認します。

```bash
python scripts/test-firewall-allowlist.py
```

### VPN

- WireGuard サーバー / クライアント管理
- strongSwan site-to-site IPsec 管理
- peer ネットワーク向けファイアウォール許可の自動追加

### DNS / DHCP

- dnsmasq ベースの LAN DNS / DHCP
- DHCP オプションのインポートとプレビュー
- GUI からのローカル DHCP スコープ管理

#### 上流DNSの選択

DNS画面でドメインを空欄にした上流DNSを登録すると、dnsmasqはその設定を通常の問い合わせ先として使います。生成設定に`no-resolv`を追加し、OSの`/etc/resolv.conf`にあるDNSを併用しないようにしました。LAN内の別ルーターから自動取得したDNSが、GUIで指定した上流DNSに混ざることを防ぎます。ドメインを指定した上流DNSへの振り分けも維持します。

上流DNSをすべて削除した場合や、ドメインを指定した上流DNSだけを登録した場合は、通常の問い合わせにOSのDNSを使います。上流DNSが未設定の初期状態では、既定の`1.1.1.1`と`1.0.0.1`を使います。OS自身の名前解決に使うDNSは、この設定では変更しません。[dnsmasq公式マニュアル](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)の`--server`と`--no-resolv`に基づく動作です。

既存装置では更新後にDNS画面から設定を適用してください。生成設定の変更時は`dnsmasq --test`で検査してからdnsmasqを再起動します。WAN、NetworkManager、firewalldの再起動は不要です。

LAN端末が名前解決できない場合は、UTMのDNS応答に加え、端末が実際に使っているDNSとDHCPの配布元を確認してください。同じLAN内の別機器が配布するDHCPやIPv6 DNSは、その機器の設定や接続構成でも調整が必要です。端末と別DHCPサーバーが同じスイッチに接続されている場合、その間の通信はUTMを通らないことがあります。

回帰テストは、リポジトリのルートから次のコマンドで実行できます。

```bash
python scripts/test-dnsmasq-upstream.py
```

2026年10月16日の検証では、既定上流DNSとドメイン指定の有無に応じた生成内容を確認しました。9.8系の実機では、構文検査、dnsmasqの上流DNS一覧、LAN端末とのDNS要求・応答、外部HTTPS通信を確認しています。8.10系は同じ回帰テストとPython構文検査を実施し、実機での適用とISOの再作成・起動は未検証です。別機器が配布する設定を使っている全端末の復旧は、この検証には含みません。

#### 初回起動時のDNS/DHCPはGUI管理設定として生成する

初回起動で入力したLANアドレス、DHCP範囲、上流DNSは、`/etc/server-gui/dnsmasq.json` に保存し、GUIと同じ生成処理で `/etc/dnsmasq.d/server-gui.conf` へ反映します。初回起動専用の `synca-lan.conf` を新規作成しないため、初期設定だけがGUIの管理外に残ることはありません。

DHCP開始・終了アドレスは、LAN CIDR内の有効なIPv4アドレスで、開始アドレスが終了アドレス以下でなければなりません。たとえば `192.168.11.100` から `192.168.11.235` は有効ですが、`192.168.11.2235` のような不正なIPv4アドレスは初回起動を中止して保存しません。

初回起動後は、次の3点を確認します。`dnsmasq` が `active`、`dnsmasq --test` が成功、LAN IPの53番DNSと67番DHCPが待受状態であれば、DNS/DHCPサービスは起動済みです。

```bash
systemctl is-active dnsmasq
dnsmasq --test
ss -lunp | grep -E ':(53|67)\b'
```

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
- GitHub 更新で既存機の `certbot` runtime を自己修復し、hook 更新、timer 有効化、期限到来済み証明書の即時 renew を実行する
- 9 系 / 8 系とも、証明書検証に必要な時刻同期は `chronyd` を導入または有効化する

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

### AI防御（Jev）

「AI防御」画面は、WAN の既定インターフェースに対応する firewalld ゾーンに加え、実行時に有効で外部送信元へ適用される送信元 IP アドレス・IP セットのゾーンから、公開サービス、明示ポート、ポート範囲、ポート転送を取得します。送信元専用で対象が `DROP` または `REJECT` のゾーンは対象外です。直近ログの認証失敗、探索的な HTTP 要求、または繰り返しの記録を持つ送信元だけを候補にします。direct ルールや任意の nftables ルールは自動列挙の対象外です。

サービスの公開ポートは、ゾーンの実行時設定とサービス定義を分けて確認する構成です。対応する firewalld ではサービス定義のポート取得が永続設定専用のため、`--permanent --service=<サービス名> --get-ports` を優先します。GUI には判定に含めたゾーン、その適用範囲、サービス、ポートを表示し、WAN インターフェースのゾーンが空でも送信元 IP セットで許可しているゾーンを確認できます。

Jev の判定データに含めるのは、`source-001` のような匿名候補 ID、イベント種別の件数、対象ポートです。IP アドレス、元のログ行、利用者名、要求パス、アクセス元の認証情報は含めません。API キーは Jev API の認証ヘッダーにのみ使用し、画面やログには表示しません。

[System One v1 API](https://docs.typesafe.ai/api) に合わせ、質問は匿名候補 ID をキーにしたオブジェクトで送ります。各質問には `type: choice`、`instructions`、`criteria` を指定し、判定する候補の位置を指示文に明記します。質問 ID 自体はモデルに渡らないため、複数の候補を同時に判定する場合も、その候補のイベント件数だけを評価する構成です。

Jev の確認に失敗した場合は、認証、要求形式、利用制限、DNS、TLS、時間超過、応答形式のどこで失敗したかを表示します。「今すぐ確認」が HTTP 503 になった場合も、保存された前回の結果を再読み込みします。ログにはエラー分類と Jev 側の HTTP 状態だけを記録し、API キー、要求本文、Jev のエラー本文は記録しません。

初期状態は無効です。Jev API キーが未設定の場合、確認も遮断も行いません。有効化するときは、次の手順で API キーを設定します。

1. [Typesafe AI Console](https://console.typesafe.ai/) にサインインします。
2. ダッシュボードで API キーを発行し、作成直後に安全な場所へ控えます。
3. 「AI防御」画面に API キーを貼り付け、有効化して設定を保存します。

API キーは `/etc/server-gui/ai_defense.json` に権限 `0600` で保存し、画面には再表示しません。既定の実行間隔は 8 時間ごとで、1 日 3 回です。画面から 1 ～ 168 時間ごとに変更できます。systemd の `server-gui-ai-defense.timer` は 1 時間ごとに起動し、設定した間隔に達した場合だけ `server-gui-ai-defense.service` を実行します。

遮断は安全側で判断します。公開ポートに対する不審候補について、Jev が `benign` と判定し、確信度が `0.85` 以上かつ悪性確率が `0` の場合だけ遮断しません。`malicious`、`insufficient`、低い確信度、または悪性確率が 0 より大きい結果は、専用の `synca-ai-defense-v4` または `synca-ai-defense-v6` IP セットに追加して遮断します。Jev API の通信失敗や応答形式の不正時は、判定結果を検証できないため自動遮断しません。

遮断前には `drop` ゾーンの実行時設定と永続設定の対象が `DROP` であることを確認し、firewalld の再読込は行いません。一部の firewalld では対象値の取得が永続設定専用のため、両方の `--list-all` 出力から対象値を検証します。

[firewalld の IP セット作成](https://firewalld.org/documentation/man-pages/firewall-cmd.html)は永続設定専用です。専用セットが実行時にまだ読み込まれていない場合は、永続設定に遮断 IP を保存したうえで、`synca-ai-defense` コメントを付けた INPUT・FORWARD の direct DROP ルールを追加して即時遮断します。direct ルールは、firewalld の登録状態だけでなく、`iptables` または `ip6tables` でカーネル側の配置も確認します。nftables 構成の INPUT・FORWARD と、iptables 構成の `*_direct` チェーンを区別して検査します。後の通常の再読込・再起動では、永続 IP セットによる遮断が読み込まれます。

遮断に失敗した場合は、失敗件数を表示し、「確認完了」とは扱いません。失敗時に取り消すのは、その処理で新たに追加した設定だけです。遮断した IP アドレスは「AI防御」の一覧から手動で解除できます。解除時は、永続 IP セット、読み込まれた実行時 IP セット、専用コメント付きの direct ルールを削除します。管理者が別途設定したルールは削除しません。

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

## WAN 接続方式の切替

ネットワーク画面の WAN 設定で PPPoE 接続中に DHCP クライアントまたは Static IP を選択すると、GUI は PPPoE プロファイルではなく、PPPoE 親NICの Ethernet WAN プロファイルを作成または再利用して編集します。

切替を適用すると、新WAN IF向けに firewalld の public zone、`4444/tcp`、LAN から WAN への FORWARD、戻り通信の RELATED/ESTABLISHED、LAN CIDR から新WAN IFへの MASQUERADE を同期してから、旧PPPoEの自動接続をOFFにして新WAN接続を up します。新WANがIPv4 default routeにならない場合、GUIは旧PPPoE接続へ戻すロールバックを試みます。

DHCPへ切り替える場合は、上位側でDHCP OFFER、デフォルトゲートウェイ、DNSが提供されている必要があります。DHCP提供がない回線で実切替を行うと、ロールバックまでは一時的にWANが途切れる可能性があります。

## セキュリティ

アプライアンスバックアップ、`evidence/`、`/etc/server-gui`、WireGuard 鍵、IPsec PSK、DDNS 認証情報、SMTP 認証情報、Let's Encrypt 秘密鍵、NetworkManager 接続秘密情報、サーバーログはコミットしません。

`.gitignore` は生成 ISO と一般的な秘密情報ファイルを除外します。内部 ISO 専用ファイルはリポジトリ外、または ignore 済みローカルパスで管理します。

## 今回の検証

開発環境では、次の確認を実行しました。

```bash
python scripts/test-wan-quality-ai-defense.py
node scripts/test-ai-defense-ui.js
python scripts/test-navigation-groups.py
python -m py_compile \
  payload/server-gui/server_gui/modules/wan_quality.py \
  payload/server-gui/server_gui/modules/ai_defense.py \
  payload/server-gui/server_gui/app.py \
  payload/server-gui/bin/ai-defense-check
bash -n iso/payload/synca-install.sh
bash -n iso/payload/synca-firstboot.sh
bash -n scripts/bootstrap-synca-testhost.sh
```

回帰テストでは、ping 結果の解析、ICMP 応答の照合、`ping` がない場合の代替測定、IPv4 WAN に固定した転送、転送未完了時の扱い、WAN品質の状態整理、Jev に IP アドレスを含めない要求生成、Jev 応答形式の検証、安全側の遮断条件、GUI の試行制限ログ、送信元 IP セットを使う公開ゾーン、サービス定義の永続設定からのポート取得、公開ポート範囲、アプリケーション登録、ISO インストーラと初回起動時の timer 有効化、firewalld を再読込しない遮断経路を確認します。テンプレートの JavaScript 構文と差分の空白エラーも確認しました。

AI 防御の追加テストでは、System One v1 の要求形式、複数候補と質問の対応、利用制限・過負荷時だけの再試行、秘密情報を含めないエラー表示、遮断失敗時の結果、実行時セットがない場合の direct ルール、カーネル側にルールがない場合の失敗、既存の遮断を保持した失敗処理、両経路の手動解除を確認しました。GUI の JavaScript テストでは、HTTP エラー・通信失敗・成功の各場合で結果を再読み込みし、実行ボタンを操作可能に戻すことを確認しました。

2026-10-13 に AlmaLinux 9.8 と 8.10 の実機で、認証付き GUI API から WAN品質を測定しました。両機とも約 10 秒で HTTP 200 を返し、下り 20 MB、上り 10 MB、3 測定先それぞれ 4 回の応答、損失 0%、履歴への保存を確認しています。8.10 の実機は `ping` がない状態で ICMP ソケットによる測定を確認しました。新しいパッケージ構成での ISO 再作成・起動試験と、実機の通信障害を発生させる試験は未実施です。

ナビゲーションの回帰テストは、デスクトップの左メニューとハンバーガーメニューに、同じ区分、リンク順、カテゴリの開閉構造、現在の画面が属するカテゴリだけが初期状態で開くこと、アクティブページの `aria-current` が表示されることを確認します。Flask のテンプレートレンダリングとローカルの実ブラウザで、デスクトップとハンバーガーメニューの開閉を確認しました。アプライアンス実機のブラウザで、画面幅ごとに目視する確認は未実施です。

以前の公開ポート検証では、WAN インターフェースのゾーンが空で、送信元 IP セットの許可ゾーンに公開サービス、明示ポート、ポート転送がある構成を読み取り専用で確認しました。修正後は AlmaLinux 9.8 の実機で送信元 IP セットの許可ゾーンから 14 種類のポート・範囲を検出し、候補 0 件の確認処理が `no_candidates` で完了しました。この検証では候補がなく、Jev API 呼出しと遮断は未実施でした。

2026-10-14 の AlmaLinux 9.8 実機検証では、保存済みの API キーで Jev API の判定が成功しました。認証付き GUI の「今すぐ確認」API は約 4.2 秒で HTTP 200 を返し、判定結果と遮断一覧の保存、永続 IP セットへの追加、INPUT・FORWARD の実際の DROP ルールを確認しました。適用時は管理 GUI のワーカーだけを再読み込みし、firewalld とネットワーク設定は再読み込みしていません。定期実行タイマーが有効・稼働中であることも確認しました。

AlmaLinux 8.10 実機での今回の Jev 呼出し・遮断、実機での手動解除、IPv6 遮断、再起動後の遮断維持、9.8・8.10 の ISO 再作成・起動試験は未実施です。手動解除と IPv6 のルール生成は回帰テストで確認しています。実機の通信へ影響する試験は、検証環境で API キーとテスト用送信元を用意して確認してください。

## 開発とコミット

コミット前にREADME.mdを必ず更新してください。変更した機能や設定方法、検証結果、未検証の項目を記載し、コードと説明の内容を一致させます。

文章はyomiyasuスキルで整え、同梱のリンターで検査します。技術的な条件や数値、コマンド、確認できた範囲はそのまま保持してください。認証情報や顧客固有の調査ログは掲載しません。

README.mdの更新が完了してからコミットします。コミットメッセージは日本語で作成してください。この手順は`AGENTS.md`にも記載しています。

## ライセンス

SyncA独自部分には、[LICENSE](LICENSE)に記載した利用条件を適用します。株式会社NSKは著作権を放棄しません。

個人による非商用利用は自由です。個人利用に必要な使用、複製、改変に利用料や事前連絡は不要です。商用利用を始める前に、[株式会社NSKの問い合わせフォーム](https://nsksys.com/)から連絡してください。個人による利用でも、事業や業務で使う場合は商用利用に含まれます。

同梱または利用する第三者製ソフトウェアには、それぞれのライセンスが適用されます。各ソフトウェアの利用条件と著作権表示は変更しません。
