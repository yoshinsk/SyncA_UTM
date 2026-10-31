"""payload/server-gui/server_gui/os_security_update.py

AlmaLinux 8.10/9.8の安定版セキュリティRPMを計画・準備・検査・適用する。
EL8のplatform-python 3.6でも動作する。GUI更新時の自動RPM適用や再起動はしない。
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
import uuid

ROOT = Path('/var/lib/server-gui/os-security-updates')
STABLE_REPOS = {'baseos', 'appstream', 'extras', 'powertools', 'crb'}
SERVICES = ('NetworkManager', 'firewalld', 'sshd', 'nginx', 'server-gui', 'dnsmasq', 'strongswan')
MAX_AGE = 24 * 3600
GIB = 1024 ** 3
# AlmaLinux公式 https://almalinux.org/ja/security/ の主鍵fingerprint。
OFFICIAL_KEYS = {
    '8.10': {'5E9B8F5617B5066CE92057C3488FCF7C3ABB34F8', 'BC5EDDCADF502C077F1582882AE81E8ACED7258B'},
    '9.8': {'BF18AC2876178908D6E71267D36CB86CB86B3716'},
}


def command(argv, check=True, timeout=30, cwd=None):
    """固定引数で実行し、応答しないコマンドには期限を設ける。"""
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, encoding='utf-8', errors='replace', timeout=timeout, cwd=cwd)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'command failed')
    return result


def write_json(path, value):
    """状態ファイルをroot専用・原子的に置換し、途中のJSONを公開しない。"""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def read_json(path):
    with path.open(encoding='utf-8') as stream:
        return json.load(stream)


def file_hash(path):
    """大きなkernel RPMを全量メモリーへ載せずに改変検査する。"""
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def release():
    """対象OSを厳密に確認し、他ディストリビューションやメジャー更新を拒否する。"""
    data = dict(line.strip().split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                if '=' in line and not line.startswith('#'))
    data = {key: value.strip('"') for key, value in data.items()}
    if data.get('ID') != 'almalinux' or data.get('VERSION_ID') not in ('8.10', '9.8'):
        raise RuntimeError('対応OSはAlmaLinux 8.10と9.8です')
    return data['VERSION_ID']


def package_row(pkg):
    return {'name': pkg.name, 'evr': pkg.evr, 'arch': pkg.arch, 'repo': pkg.reponame}


def identity(row):
    return (row['name'], row['evr'], row['arch'])


def rpmdb_hash(base):
    # 署名鍵は独立してfingerprint照合する。公式鍵の登録はRPM構成の変更に数えない。
    rows = sorted(identity(package_row(pkg)) for pkg in base.sack.query().installed() if pkg.name != 'gpg-pubkey')
    return hashlib.sha256(json.dumps(rows).encode('utf-8')).hexdigest()


def keyring(job):
    """公式主鍵を固定fingerprintで照合し、準備・検査用の隔離RPM鍵DBへ登録する。"""
    version = release()
    key = Path('/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux' + ('-9' if version == '9.8' else ''))
    home = job / 'gpg-inspect'; home.mkdir(mode=0o700, exist_ok=True)
    output = command(['gpg', '--batch', '--no-options', '--homedir', str(home),
                      '--with-colons', '--show-keys', str(key)]).stdout
    primary = False
    fingerprints = set()
    for line in output.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub': primary = True
        elif fields[0] == 'sub': primary = False
        elif fields[0] == 'fpr' and primary:
            fingerprints.add(fields[9].upper()); primary = False
    if not fingerprints or not fingerprints.issubset(OFFICIAL_KEYS[version]):
        raise RuntimeError('AlmaLinux公式署名鍵のfingerprintが一致しません')
    database = job / 'keydb'; database.mkdir(mode=0o700, exist_ok=True)
    command(['rpmkeys', '--dbpath', str(database), '--import', str(key)])
    return key, database


def verify_signed_rpm(path, database):
    """公式鍵だけの隔離keyringで署名を検証する。未署名RPMも拒否する。"""
    result = command(['rpmkeys', '--dbpath', str(database), '--checksig', '--verbose', str(path)])
    if not any('Signature' in line and line.rstrip().endswith(': OK') for line in result.stdout.splitlines()):
        raise RuntimeError('RPMの有効な署名を確認できません: ' + path.name)


def base_for(job, offline=False, test=False):
    """公式安定版の有効repoだけを使い、署名必須・削除制限・旧カーネル保持を設定。"""
    import dnf

    base = dnf.Base()
    base.conf.read()
    base.conf.cachedir = str(job / 'cache')
    base.conf.logdir = str(job)
    base.conf.gpgcheck = True
    base.conf.localpkg_gpgcheck = True
    base.conf.best = True
    base.conf.installonly_limit = 0
    base.conf.clean_requirements_on_remove = False
    base.conf.tsflags = ['test'] if test else []
    base.conf.timeout = 15
    base.conf.retries = 1
    base.read_all_repos()
    enabled = []
    for repo in base.repos.all():
        if offline or repo.id not in STABLE_REPOS or not repo.enabled:
            repo.disable()
            continue
        # 異なる提供元の鍵を指定した同名repoは流用しない。
        if not repo.gpgkey or any(not key.startswith('file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux')
                                  for key in repo.gpgkey):
            raise RuntimeError('公式鍵を確認できないrepo: ' + repo.id)
        repo.gpgcheck = True
        repo.sslverify = True
        repo.skip_if_unavailable = False
        enabled.append(repo.id)
    if not offline and not {'baseos', 'appstream'}.issubset(enabled):
        raise RuntimeError('baseosとappstreamの有効な公式安定版repoが必要です')
    base.fill_sack(load_available_repos=not offline)
    return base


def validate_transaction(base, expected=None):
    """依存関係込みの全RPMを固定し、他パッケージの削除・置換を許可しない。"""
    if not base.transaction:
        if expected:
            raise RuntimeError('確認済みの更新対象を解決できません')
        return []
    install = sorted([package_row(pkg) for pkg in base.transaction.install_set], key=identity)
    replacement = {(row['name'], row['arch']) for row in install}
    for pkg in base.transaction.remove_set:
        if (pkg.name, pkg.arch) not in replacement:
            # EL8公式のdbxtool→fwupd統合だけを、RPMのObsoletes宣言も確認して許可する。
            if pkg.name == 'dbxtool' and any(new.name == 'fwupd' and
                    'dbxtool < 9' in [str(value) for value in new.obsoletes]
                    for new in base.transaction.install_set):
                continue
            raise RuntimeError('既存パッケージの削除を伴うため中止: ' + pkg.name)
    if expected is not None and [identity(row) for row in install] != sorted(identity(row) for row in expected):
        raise RuntimeError('確認済み計画と依存関係が変化しました。計画を作成し直してください')
    return install


def impact(rows):
    """scriptletによる再起動も含め、通信・認証・稼働中ライブラリーへの影響を表示。"""
    names = {row['name'] for row in rows}
    groups = {
        'WAN/LAN・DHCP・VPN': ('NetworkManager', 'firewalld', 'python3-firewall', 'dnsmasq', 'strongswan', 'ppp'),
        'SSH・GUI・公開サービス': ('openssh', 'nginx', 'httpd', 'openssl', 'postfix'),
        'OS基盤・認証': ('glibc', 'systemd', 'dbus', 'pam', 'sudo'),
        'カーネル・起動環境': ('kernel', 'dracut', 'microcode_ctl', 'linux-firmware', 'grub2', 'grubby', 'shim', 'fwupd'),
    }
    affected = {group: sorted(name for name in names if any(name == p or name.startswith(p + '-')
                                                         for p in prefixes))
                for group, prefixes in groups.items()}
    return {key: value for key, value in affected.items() if value}


def kernel_state(version):
    """98432の公式修正版下限と稼働カーネルを照合する。testingへの切替はしない。"""
    import rpm

    current = os.uname().release
    value = current.rsplit('.', 1)[0].split('-', 1)
    minimum = ('4.18.0', '553.180.2.el8_10') if version == '8.10' else ('5.14.0', '687.61.2.el9_8')
    vendor_suffix = '.el8_10' if version == '8.10' else '.el9_8'
    fixed = (len(value) == 2 and value[0] == minimum[0] and vendor_suffix in value[1] and
             rpm.labelCompare(('0', value[0], value[1]), ('0',) + minimum) >= 0)
    return {'running_kernel': current, 'cve_2026_98432_running_fixed': bool(fixed),
            'cve_2026_98432_minimum': '-'.join(minimum)}


def health():
    """変更前後の経路・サービス・ローカルGUIを比較する。外部到達性は別途確認する。"""
    import urllib.request

    result = {'services': {}, 'route': command(['ip', '-4', 'route', 'show', 'default']).stdout.strip()}
    direct = command(['firewall-cmd', '--direct', '--get-all-rules'], check=False)
    result['direct_rules'] = sorted(direct.stdout.splitlines()) if direct.returncode == 0 else None
    for service in SERVICES:
        result['services'][service] = command(['systemctl', 'is-active', service], check=False).stdout.strip()
    try:
        with urllib.request.urlopen('http://127.0.0.1:5010/login', timeout=5) as response:
            result['local_gui'] = response.status == 200
    except Exception:
        result['local_gui'] = False
    cve = command(['/opt/server-gui/venv/bin/python', '-m', 'server_gui.cve_2026_98432', 'status'],
                  check=False, cwd='/opt/server-gui')
    try:
        result['mitigation_active'] = bool(json.loads(cve.stdout).get('active'))
    except ValueError:
        result['mitigation_active'] = None
    return result


def boot_id():
    """稼働セッションの識別子で、OS再起動と単なるサービス再起動を区別する。"""
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def compare_health(before, after):
    issues = []
    for name, state in before['services'].items():
        if state == 'active' and after['services'].get(name) != 'active':
            issues.append(name + 'がactiveではありません')
    if before['route'] != after['route']:
        issues.append('WANデフォルト経路が変化しました')
    if before['local_gui'] and not after['local_gui']:
        issues.append('ローカルGUIに接続できません')
    if before['mitigation_active'] is True and after['mitigation_active'] is not True:
        issues.append('CVE-2026-98432暫定緩和の状態を確認できません')
    if before.get('direct_rules') is not None and before.get('direct_rules') != after.get('direct_rules'):
        issues.append('NAT・転送等のfirewalld directルールが変化しました')
    return issues


def preflight(job, rows, download_bytes=0):
    """空き容量と旧カーネルを検査し、復旧に使う稼働版の削除を防ぐ。"""
    if shutil.disk_usage(str(job)).free < max(2 * GIB, download_bytes * 4):
        raise RuntimeError('作業領域に2GiB以上またはダウンロード量の4倍の空きが必要です')
    if any(row['name'] == 'kernel-core' for row in rows):
        if not Path('/boot/vmlinuz-' + os.uname().release).is_file():
            raise RuntimeError('稼働カーネルの起動ファイルを保持できません')
        if shutil.disk_usage('/boot').free < 512 * 1024 ** 2:
            raise RuntimeError('/bootに512MiB以上の空きが必要です')


def save_state(data):
    data['updated_at'] = int(time.time())
    write_json(ROOT / 'state.json', data)
    print('os-security-update phase={0} plan={1}'.format(data.get('phase'), data.get('plan_id', '-')))


def record_apply(job, data):
    """適用結果を計画確認の状態とは別に保存し、次の確認で成功履歴を失わない。"""
    data['updated_at'] = int(time.time())
    write_json(job / 'result.json', data)
    write_json(ROOT / 'last-apply.json', data)
    save_state(data)


def last_apply(data):
    """旧版の適用済み状態と過去の適用後確認記録も区別して表示する。"""
    path = ROOT / 'last-apply.json'
    if path.exists():
        result = read_json(path)
    elif data.get('phase') in ('applied', 'attention', 'reboot_scheduled'):
        result = data
    else:
        candidates = [p for p in ROOT.glob('*/health-after.json')
                      if re.match(r'^[0-9a-f]{32}$', p.parent.name) and (p.parent / 'plan.json').exists()]
        if not candidates:
            return None
        path = max(candidates, key=lambda p: p.stat().st_mtime)
        plan = read_json(path.parent / 'plan.json')
        return {'phase': 'postcheck_recorded', 'plan_id': path.parent.name,
                'package_count': len(plan.get('packages', [])), 'updated_at': int(path.stat().st_mtime),
                'message': '過去の適用後確認記録があります。直近の計画確認とは別の記録です。'}
    result = dict(result)
    if result.get('applied_boot_id') and boot_id() != result['applied_boot_id']:
        result.update(reboot_required=False, reboot_pending=False,
                      message='OS再起動を検出しました。経路・VPN・LAN・GUIの復旧を確認してください。')
        if result['phase'] == 'reboot_scheduled':
            result['phase'] = 'applied'
    keys = ('phase', 'plan_id', 'updated_at', 'message', 'issues', 'reboot_required', 'reboot_pending')
    summary = {key: result.get(key) for key in keys}
    summary['package_count'] = len(result.get('plan', {}).get('packages', []))
    return summary


def checked_plan(plan_id):
    if not re.match(r'^[0-9a-f]{32}$', plan_id or ''):
        raise RuntimeError('計画IDが不正です')
    job = ROOT / plan_id
    plan = read_json(job / 'plan.json')
    if time.time() - plan['created_at'] > MAX_AGE or plan['os'] != release():
        raise RuntimeError('計画の期限切れまたはOSの変更を検出しました')
    return job, plan


def plan_update():
    """依存関係を解決して確認用の計画を作る。この段階ではRPMを適用しない。"""
    version = release()
    # 旧版から更新した装置でも、次の計画作成の前に適用済み記録を保存する。
    if (ROOT / 'state.json').exists():
        previous = read_json(ROOT / 'state.json')
        if previous.get('phase') in ('applied', 'attention', 'reboot_scheduled'):
            write_json(ROOT / 'last-apply.json', previous)
    plan_id = uuid.uuid4().hex
    job = ROOT / plan_id
    job.mkdir(mode=0o700, parents=True)
    save_state({'phase': 'planning', 'plan_id': plan_id})
    with base_for(job) as base:
        fingerprint = rpmdb_hash(base)
        base.add_security_filters('gte', types=['security'])
        base.upgrade_all()
        base.resolve(allow_erasing=False)
        rows = validate_transaction(base)
        if any(row['repo'] not in STABLE_REPOS for row in rows):
            raise RuntimeError('安定版以外のrepoが更新計画に混入しました')
        download = sum(pkg.downloadsize for pkg in base.transaction.install_set) if base.transaction else 0
        preflight(job, rows, download)
        plan = {'plan_id': plan_id, 'os': version, 'created_at': int(time.time()),
                'rpmdb_hash': fingerprint, 'packages': rows, 'download_bytes': download,
                'removed_versions': [package_row(pkg) for pkg in base.transaction.remove_set] if base.transaction else [],
                'impact': impact(rows), 'kernel': kernel_state(version),
                'reboot_expected': bool(impact(rows).get('カーネル・起動環境') or impact(rows).get('OS基盤・認証'))}
        write_json(job / 'plan.json', plan)
    save_state({'phase': 'planned' if rows else 'no_updates', 'plan': plan, 'plan_id': plan_id})


def prepare_update(plan_id):
    """再解決結果を照合後にダウンロードし、全RPMの署名・SHA256を固定する。"""
    job, plan = checked_plan(plan_id)
    if not plan['packages']:
        raise RuntimeError('更新対象のRPMがありません')
    save_state({'phase': 'preparing', 'plan': plan, 'plan_id': plan_id})
    with base_for(job) as base:
        if rpmdb_hash(base) != plan['rpmdb_hash']:
            raise RuntimeError('RPM構成が変化しました。計画を作成し直してください')
        base.add_security_filters('gte', types=['security'])
        base.upgrade_all()
        base.resolve(allow_erasing=False)
        validate_transaction(base, plan['packages'])
        preflight(job, plan['packages'], plan['download_bytes'])
        packages = list(base.transaction.install_set)
        base.download_packages(packages)
        key, database = keyring(job)
        payload = []
        for pkg in packages:
            path = Path(pkg.localPkg()).resolve()
            if job.resolve() not in path.parents:
                raise RuntimeError('計画外のRPMパスを検出しました')
            verify_signed_rpm(path, database)
            payload.append(dict(package_row(pkg), path=str(path), sha256=file_hash(path)))
        plan['payload'] = payload
        write_json(job / 'plan.json', plan)
    save_state({'phase': 'ready', 'plan_id': plan_id, 'plan': plan})


def local_transaction(job, plan, test=False):
    """ネットワークrepoを使わず、署名検証済みの固定RPMだけで再構成する。"""
    base = base_for(job, offline=True, test=test)
    try:
        if rpmdb_hash(base) != plan['rpmdb_hash']:
            raise RuntimeError('RPM構成が変化しました。計画を作成し直してください')
        payload = plan.get('payload', [])
        if sorted(identity(row) for row in payload) != sorted(identity(row) for row in plan['packages']):
            raise RuntimeError('署名検証済みの準備データがありません')
        paths = []
        for row in payload:
            path = Path(row['path']).resolve()
            if job.resolve() not in path.parents or file_hash(path) != row['sha256']:
                raise RuntimeError('ダウンロード済みRPMの変更を検出しました')
            paths.append(str(path))
        packages = base.add_remote_rpms(paths)
        key, database = keyring(job)
        for pkg in packages:
            verify_signed_rpm(Path(pkg.localPkg()), database)
            base.package_install(pkg, strict=True)
        base.resolve(allow_erasing=False)
        validate_transaction(base, plan['packages'])
        return base
    except Exception:
        base.close()
        raise


def test_update(plan_id):
    """RPMのtestトランザクションを実行し、実インストール前の依存・容量検査を行う。"""
    job, plan = checked_plan(plan_id)
    save_state({'phase': 'testing', 'plan_id': plan_id, 'plan': plan})
    with local_transaction(job, plan, test=True) as base:
        base.do_transaction()
    with base_for(job, offline=True) as base:
        if rpmdb_hash(base) != plan['rpmdb_hash']:
            raise RuntimeError('検査後のRPM構成が一致しません')
    plan['transaction_test_ok'] = True
    write_json(job / 'plan.json', plan)
    save_state({'phase': 'ready', 'plan_id': plan_id, 'plan': plan})


def apply_update(plan_id, maintenance=False, recovery=False, reboot_after=False):
    """保守・復旧確認後だけ実適用する。指定された場合も正常完了後だけ再起動を予約。"""
    if not maintenance or not recovery:
        raise RuntimeError('通信中断を伴う保守時間と、外部バックアップ・コンソール復旧手段の確認が必要です')
    job, plan = checked_plan(plan_id)
    if not plan.get('transaction_test_ok'):
        raise RuntimeError('準備とトランザクション検査を先に完了してください')
    save_state({'phase': 'preflight', 'plan_id': plan_id, 'plan': plan})
    preflight(job, plan['packages'], plan['download_bytes'])
    # 計画・RPM構成・署名・依存関係を、設定やシステム鍵を変更する前に再検査する。
    with local_transaction(job, plan, test=True) as base:
        base.do_transaction()
    before = health()
    if any(before['services'].get(name) != 'active' for name in ('NetworkManager', 'firewalld', 'sshd', 'server-gui')) or not before['local_gui'] or before.get('direct_rules') is None:
        raise RuntimeError('管理アクセスまたはネットワークの事前確認に失敗しました')
    write_json(job / 'health-before.json', before)
    # 設定バックアップだけではRPMやファイルシステム全体の復旧にならないため、外部復旧確認も必須。
    with tarfile.open(str(job / 'config-and-boot.tar.gz'), 'w:gz', dereference=False) as archive:
        archive.add('/etc', arcname='etc')
        archive.add('/boot', arcname='boot')
    (job / 'config-and-boot.tar.gz').chmod(0o600)
    command(['/opt/server-gui/venv/bin/python', '-c',
             'from server_gui.firewalld_safety import ensure_before_firewalld_reload; '
             'r=ensure_before_firewalld_reload(); print(r.output); raise SystemExit(0 if r.ok else 1)'],
            cwd='/opt/server-gui')
    # 準備・testではシステム鍵DBを変えず、実適用の承認後だけ公式鍵を登録する。
    key, database = keyring(job)
    command(['rpmkeys', '--import', str(key)])
    save_state({'phase': 'applying', 'plan_id': plan_id, 'plan': plan, 'transaction_started': True})
    with local_transaction(job, plan) as base:
        base.do_transaction()
    after = health()
    issues = compare_health(before, after)
    with base_for(job, offline=True) as base:
        installed = {identity(package_row(pkg)) for pkg in base.sack.query().installed()}
        issues.extend('更新版を確認できません: ' + row['name'] for row in plan['packages']
                      if identity(row) not in installed)
    write_json(job / 'health-after.json', after)
    result = {'phase': 'attention' if issues else 'applied', 'plan_id': plan_id,
                'plan': plan, 'issues': issues, 'reboot_required': plan['reboot_expected'],
                'applied_boot_id': boot_id(),
                'kernel': kernel_state(plan['os']),
                'message': 'OSを再起動してください。再起動後に経路・VPN・LAN・GUIを確認してください。'
                           if plan['reboot_expected'] else '稼働中サービスの旧ライブラリー利用を確認し、必要なサービスを再起動してください。'}
    record_apply(job, result)
    if reboot_after and not issues:
        try:
            # GUI応答と結果保存を完了できるよう30秒後に独立timerで再起動する。
            command(['systemd-run', '--no-block', '--collect', '--unit=synca-os-security-reboot',
                     '--on-active=30s', '--timer-property=AccuracySec=1s', '--', '/usr/libexec/platform-python',
                     '/opt/server-gui/bin/os-security-update', 'reboot', '--plan-id', plan_id, '--state-dir', str(ROOT)])
            result.update(phase='reboot_scheduled', reboot_required=True, reboot_pending=True,
                          message='OS更新が正常に完了しました。30秒後にOSを再起動します。接続が戻るまでお待ちください。')
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            result.update(phase='attention', reboot_required=True,
                          message='OS更新は完了しましたが再起動を予約できませんでした。管理者がOSを再起動してください。',
                          issues=['再起動予約失敗: ' + str(exc)])
        record_apply(job, result)


def reboot_if_ready(plan_id):
    """timer実行時にも成功記録を照合する。記録失敗・別処理・再起動済みなら実行しない。"""
    job, plan = checked_plan(plan_id)
    result = read_json(job / 'result.json')
    current = read_json(ROOT / 'state.json')
    if any(record.get('phase') != 'reboot_scheduled' or record.get('plan_id') != plan_id or
           record.get('issues') or record.get('error') or record.get('applied_boot_id') != boot_id()
           for record in (result, current)):
        raise RuntimeError('再起動予約後の状態が一致しないため、自動再起動を中止しました')
    command(['/usr/bin/systemctl', 'reboot'])


def status():
    """再起動後は稼働カーネルを再照合し、再起動要求だけを解除する。通信復旧は別確認。"""
    data = read_json(ROOT / 'state.json') if (ROOT / 'state.json').exists() else {'phase': 'idle'}
    if data.get('phase') in ('applied', 'attention', 'reboot_scheduled'):
        data['kernel'] = kernel_state(release())
        if data.get('applied_boot_id') and boot_id() != data['applied_boot_id']:
            data['reboot_required'] = False
            data['reboot_pending'] = False
            if data['phase'] == 'reboot_scheduled':
                data['phase'] = 'applied'
            data['message'] = 'OS再起動を検出しました。経路・VPN・LAN・GUIの復旧を確認してください。'
    data['last_apply'] = last_apply(data)
    return data


def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'prepare', 'test', 'apply', 'status', 'reboot'))
    parser.add_argument('--plan-id', default='')
    parser.add_argument('--maintenance-confirmed', action='store_true')
    parser.add_argument('--recovery-confirmed', action='store_true')
    parser.add_argument('--reboot-after-apply', action='store_true')
    parser.add_argument('--state-dir', type=Path, default=ROOT)
    args = parser.parse_args()
    ROOT = args.state_dir
    if args.action == 'status':
        print(json.dumps(status(), ensure_ascii=True))
        return 0
    if os.geteuid() != 0:
        raise SystemExit('root権限が必要です')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    import fcntl
    with (ROOT / 'worker.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('別のセキュリティ更新処理が実行中です')
            return 1
        try:
            if args.action != 'reboot' and status().get('reboot_pending'):
                print('OS再起動を予約済みです。再起動完了まで次の更新処理は開始できません')
                return 1
            if args.action == 'plan': plan_update()
            elif args.action == 'prepare': prepare_update(args.plan_id)
            elif args.action == 'test': test_update(args.plan_id)
            elif args.action == 'reboot': reboot_if_ready(args.plan_id)
            else: apply_update(args.plan_id, args.maintenance_confirmed, args.recovery_confirmed, args.reboot_after_apply)
            return 0
        except Exception as exc:
            state = read_json(ROOT / 'state.json') if (ROOT / 'state.json').exists() else {}
            state.update(phase='failed', error=str(exc))
            if state.get('transaction_started'):
                state['message'] = '一部の更新が適用済みの可能性があります。ログ・経路・サービスを確認し、復旧手段を使用してください。自動undoは実行していません。'
            save_state(state)
            print(str(exc))
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
