"""payload/server-gui/server_gui/modules/geoip.py - Manage firewalld country ipsets.

Workflow:
  1. Download CIDR list for ISO-3166 country code from ipdeny.com
  2. Create / update / adopt a firewalld ipset (default name: `<cc>-ipv4`)
  3. Attach (`--add-source=ipset:<name>`) to a target zone

The ipset name is configurable per entry, so existing handwritten ipsets
(e.g. an admin-created `jp-ipv4`) can be brought under GUI management by
specifying the existing name when adding the country.

Storage (/etc/server-gui/geoip.json):
  {
    "countries": [
      {
        "code": "JP",
        "ipset": "jp-ipv4",
        "last_updated": "2026-05-14T17:45:00",
        "entry_count": 1284,
        "source_url": "...",
        "adopted": false
      }
    ]
  }
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import re
import urllib.error
import urllib.request
from pathlib import Path

from flask import Blueprint, Flask, current_app, jsonify, render_template, request

from ..auth import csrf_protect, login_required
from ..config_store import ConfigStore
from ..shell import run, sudo_run
from ..validators import ValidationError, validate_country_code, validate_identifier

logger = logging.getLogger(__name__)

bp = Blueprint("geoip", __name__, url_prefix="/geoip")

MODULE_NAME = "geoip"
IPDENY_URL = "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone"
DOWNLOAD_TIMEOUT = 30
TMP_DIR = Path("/var/tmp/server-gui")
IPSET_DIR = Path("/etc/firewalld/ipsets")
IPSET_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,32}$")
SIPIS_ID = "acrobits-sipis"
SIPIS_HOSTNAME = "all.sipis.acrobits.cz"
SIPIS_IPSET = "acrobits-sipis-ipv4"


def register(app: Flask) -> None:
    app.register_blueprint(bp)


def _store() -> ConfigStore:
    return ConfigStore(current_app.config["CONFIG_DIR"])


def _default() -> dict:
    return {"countries": [], "dynamic_ipsets": _builtin_dynamic_ipsets()}


def _builtin_dynamic_ipsets() -> list[dict]:
    return [{
        "id": SIPIS_ID,
        "name": "Acrobits SIPIS",
        "ipset": SIPIS_IPSET,
        "hostname": SIPIS_HOSTNAME,
        "resolver": "getent-ahostsv4",
        "last_updated": None,
        "entry_count": 0,
        "source": f"DNS A records for {SIPIS_HOSTNAME}",
    }]


def _normalise_data(data: dict) -> dict:
    """Return config data with built-in dynamic ipsets present."""
    if not isinstance(data, dict):
        data = _default()
    if not isinstance(data.get("countries"), list):
        data["countries"] = []
    if not isinstance(data.get("dynamic_ipsets"), list):
        data["dynamic_ipsets"] = []
    dynamic = data["dynamic_ipsets"]
    known = {str(item.get("id")): item for item in dynamic if isinstance(item, dict)}
    for builtin in _builtin_dynamic_ipsets():
        current = known.get(builtin["id"])
        if current is None:
            dynamic.append(dict(builtin))
            continue
        for key, value in builtin.items():
            if key not in current or current[key] in (None, ""):
                current[key] = value
    return data


def _default_ipset_name(code: str) -> str:
    """Default name matches the convention used by handwritten installs."""
    return f"{code.lower()}-ipv4"


def _write_ipset_xml(ipset_name: str, cidrs: list[str]) -> None:
    # Firewalld can load ipset XML directly. Replacing the file in one step is
    # much faster and less disruptive than removing thousands of entries via
    # firewall-cmd one by one.
    IPSET_DIR.mkdir(parents=True, exist_ok=True)
    content = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<ipset type="hash:net">',
        '  <option name="family" value="inet"/>',
    ]
    content.extend(f"  <entry>{cidr}</entry>" for cidr in cidrs)
    content.append("</ipset>")
    tmp = IPSET_DIR / f".{ipset_name}.xml.new"
    dst = IPSET_DIR / f"{ipset_name}.xml"
    tmp.write_text("\n".join(content) + "\n", encoding="utf-8")
    tmp.chmod(0o640)
    tmp.replace(dst)


# ---- views -------------------------------------------------------------

@bp.route("/")
@login_required
def page():
    return render_template("geoip.html", active_tab="geoip")


@bp.route("/api/countries", methods=["GET"])
@login_required
def list_countries():
    data = _normalise_data(_store().load(MODULE_NAME, _default()))
    return jsonify(data)


@bp.route("/api/ipsets/<name>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_ipset(name: str):
    """Delete an arbitrary firewalld ipset (managed or not).

    Refuses deletion if the ipset is currently referenced as a `source` in
    any firewalld zone — deleting it anyway would break that zone on the
    next reload, which previously caused full firewall outage.
    """
    if not IPSET_NAME_RE.match(name):
        return jsonify({"error": "invalid ipset name"}), 400

    # Pre-flight: scan every zone's sources for `ipset:<name>`
    referencing_zones = _zones_referencing_ipset(name)
    if referencing_zones:
        return jsonify({
            "ok": False,
            "error": (
                f"ipset {name!r} is in use by zone(s): {', '.join(referencing_zones)}."
                " Detach the ipset from each zone first (firewall タブで source を削除)."
            ),
            "in_use_by": referencing_zones,
        }), 409

    res = sudo_run(["firewall-cmd", "--permanent", "--delete-ipset", name])
    if not res.ok:
        return jsonify({"ok": False, "error": (res.stderr or res.stdout).strip()}), 500
    reload_res = sudo_run(["firewall-cmd", "--reload"])
    if not reload_res.ok:
        # Highly unlikely after the pre-flight check, but surface it cleanly.
        return jsonify({"ok": False, "error": "reload failed: " + reload_res.stderr.strip()}), 500
    with _store().transaction(MODULE_NAME, _default()) as data:
        _normalise_data(data)
        data["countries"] = [c for c in data["countries"] if c["ipset"] != name]
    return jsonify({"ok": True, "deleted": name})


def _zones_referencing_ipset(name: str) -> list[str]:
    """Return zones whose `source` list contains `ipset:<name>`."""
    target = f"ipset:{name}"
    zones_res = sudo_run(["firewall-cmd", "--permanent", "--get-zones"])
    if not zones_res.ok:
        return []
    matching: list[str] = []
    for zone in zones_res.stdout.split():
        sr = sudo_run(["firewall-cmd", "--permanent", "--zone", zone, "--list-sources"])
        if sr.ok and target in sr.stdout.split():
            matching.append(zone)
    return matching


@bp.route("/api/ipsets/discover", methods=["GET"])
@login_required
def discover_ipsets():
    """List all firewalld ipsets and mark which are managed by us.

    Helps adopt admin-created ipsets (e.g. existing `jp-ipv4`) into GUI
    management without duplicating them.
    """
    res = sudo_run(["firewall-cmd", "--permanent", "--get-ipsets"])
    if not res.ok:
        return jsonify({"ipsets": [], "error": res.stderr.strip()})
    all_sets = res.stdout.split()
    stored = _normalise_data(_store().load(MODULE_NAME, _default()))
    managed = {c["ipset"]: c["code"] for c in stored["countries"]}
    managed.update({d["ipset"]: d["name"] for d in stored.get("dynamic_ipsets", [])})
    items = []
    for name in sorted(all_sets):
        entries_res = sudo_run(["firewall-cmd", "--permanent", "--ipset", name, "--get-entries"])
        entry_count = len(entries_res.stdout.split()) if entries_res.ok else 0
        items.append({
            "name": name,
            "entry_count": entry_count,
            "managed_by": managed.get(name),
        })
    return jsonify({"ipsets": items})


@bp.route("/api/countries", methods=["POST"])
@login_required
@csrf_protect
def add_country():
    """Add a country entry.

    Body:
      {
        "code":  "JP",            # required, ISO 3166 alpha-2
        "ipset": "jp-ipv4",       # optional, defaults to "<cc>-ipv4"
        "adopt": false            # if true, record without downloading
                                  # (use to adopt an existing ipset)
      }
    """
    payload = request.get_json(force=True, silent=True) or {}
    try:
        code = validate_country_code(str(payload.get("code", "")).upper())
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    ipset_name = str(payload.get("ipset") or _default_ipset_name(code))
    if not IPSET_NAME_RE.match(ipset_name):
        return jsonify({"error": f"invalid ipset name: {ipset_name!r}"}), 400
    adopt = bool(payload.get("adopt", False))

    with _store().transaction(MODULE_NAME, _default()) as data:
        _normalise_data(data)
        if any(c["code"] == code for c in data["countries"]):
            return jsonify({"error": f"country {code} already managed"}), 409
        entry = {
            "code": code,
            "ipset": ipset_name,
            "last_updated": None,
            "entry_count": 0,
            "source_url": IPDENY_URL.format(cc=code.lower()),
            "adopted": adopt,
        }
        data["countries"].append(entry)

    if adopt:
        # Record current entry count without modifying the ipset.
        info_res = sudo_run(["firewall-cmd", "--permanent", "--ipset", ipset_name, "--get-entries"])
        if not info_res.ok:
            # Roll back the record
            with _store().transaction(MODULE_NAME, _default()) as data:
                _normalise_data(data)
                data["countries"] = [c for c in data["countries"] if c["code"] != code]
            return jsonify({"error": f"ipset {ipset_name!r} not found"}), 404
        count = len(info_res.stdout.split())
        adopted_entry = {
            "code": code,
            "ipset": ipset_name,
            "last_updated": _dt.datetime.now().isoformat(timespec="seconds") + " (adopted)",
            "entry_count": count,
            "source_url": IPDENY_URL.format(cc=code.lower()),
            "adopted": True,
        }
        with _store().transaction(MODULE_NAME, _default()) as data:
            _normalise_data(data)
            for i, c in enumerate(data["countries"]):
                if c["code"] == code:
                    data["countries"][i] = adopted_entry
                    break
        return jsonify({"country": adopted_entry}), 201

    try:
        updated = _refresh_country(code)
        return jsonify({"country": updated}), 201
    except RuntimeError as e:
        with _store().transaction(MODULE_NAME, _default()) as data:
            _normalise_data(data)
            data["countries"] = [c for c in data["countries"] if c["code"] != code]
        return jsonify({"error": str(e)}), 500


@bp.route("/api/countries/<code>/refresh", methods=["POST"])
@login_required
@csrf_protect
def refresh_country(code: str):
    try:
        code = validate_country_code(code.upper())
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    try:
        updated = _refresh_country(code)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"country": updated})


@bp.route("/api/countries/<code>", methods=["DELETE"])
@login_required
@csrf_protect
def delete_country(code: str):
    try:
        code = validate_country_code(code.upper())
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    payload = request.get_json(force=True, silent=True) or {}
    delete_ipset_too = bool(payload.get("delete_ipset", False))

    with _store().transaction(MODULE_NAME, _default()) as data:
        _normalise_data(data)
        entry = next((c for c in data["countries"] if c["code"] == code), None)
        if not entry:
            return jsonify({"error": "not found"}), 404
        data["countries"] = [c for c in data["countries"] if c["code"] != code]
    ipset_name = entry["ipset"]

    fw_msg = ""
    if delete_ipset_too:
        res = sudo_run(["firewall-cmd", "--permanent", "--delete-ipset", ipset_name])
        sudo_run(["firewall-cmd", "--reload"])
        fw_msg = res.stdout or res.stderr
    return jsonify({"deleted": code, "ipset_kept": not delete_ipset_too, "firewalld": fw_msg})


@bp.route("/api/dynamic-ipsets/<set_id>/refresh", methods=["POST"])
@login_required
@csrf_protect
def refresh_dynamic_ipset(set_id: str):
    try:
        updated = _refresh_dynamic_ipset(set_id)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"dynamic_ipset": updated})


@bp.route("/api/dynamic-ipsets/<set_id>/attach", methods=["POST"])
@login_required
@csrf_protect
def attach_dynamic_to_zone(set_id: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        zone = validate_identifier(payload.get("zone", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    entry = _dynamic_entry(set_id)
    if not entry:
        return jsonify({"error": "dynamic ipset not managed"}), 404
    source = f"ipset:{entry['ipset']}"
    res = sudo_run(["firewall-cmd", "--zone", zone, "--add-source", source, "--permanent"])
    if not res.ok:
        return jsonify({"ok": False, "error": res.stderr.strip()}), 500
    sudo_run(["firewall-cmd", "--reload"])
    return jsonify({"ok": True, "zone": zone, "source": source})


@bp.route("/api/dynamic-ipsets/<set_id>/detach", methods=["POST"])
@login_required
@csrf_protect
def detach_dynamic_from_zone(set_id: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        zone = validate_identifier(payload.get("zone", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    entry = _dynamic_entry(set_id)
    if not entry:
        return jsonify({"error": "dynamic ipset not managed"}), 404
    source = f"ipset:{entry['ipset']}"
    res = sudo_run(["firewall-cmd", "--zone", zone, "--remove-source", source, "--permanent"])
    if not res.ok:
        return jsonify({"ok": False, "error": res.stderr.strip()}), 500
    sudo_run(["firewall-cmd", "--reload"])
    return jsonify({"ok": True})


@bp.route("/api/countries/<code>/attach", methods=["POST"])
@login_required
@csrf_protect
def attach_to_zone(code: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        code = validate_country_code(code.upper())
        zone = validate_identifier(payload.get("zone", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    data = _normalise_data(_store().load(MODULE_NAME, _default()))
    entry = next((c for c in data["countries"] if c["code"] == code), None)
    if not entry:
        return jsonify({"error": "country not managed"}), 404
    source = f"ipset:{entry['ipset']}"
    res = sudo_run(["firewall-cmd", "--zone", zone, "--add-source", source, "--permanent"])
    if not res.ok:
        return jsonify({"ok": False, "error": res.stderr.strip()}), 500
    sudo_run(["firewall-cmd", "--reload"])
    return jsonify({"ok": True, "zone": zone, "source": source})


@bp.route("/api/countries/<code>/detach", methods=["POST"])
@login_required
@csrf_protect
def detach_from_zone(code: str):
    payload = request.get_json(force=True, silent=True) or {}
    try:
        code = validate_country_code(code.upper())
        zone = validate_identifier(payload.get("zone", ""))
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    data = _store().load(MODULE_NAME, _default())
    entry = next((c for c in data["countries"] if c["code"] == code), None)
    if not entry:
        return jsonify({"error": "country not managed"}), 404
    source = f"ipset:{entry['ipset']}"
    res = sudo_run(["firewall-cmd", "--zone", zone, "--remove-source", source, "--permanent"])
    if not res.ok:
        return jsonify({"ok": False, "error": res.stderr.strip()}), 500
    sudo_run(["firewall-cmd", "--reload"])
    return jsonify({"ok": True})


# ---- core logic --------------------------------------------------------

def _refresh_country(code: str) -> dict:
    """Download → write to file → upsert firewalld ipset → reload → record state."""
    cc_lower = code.lower()
    # Use the ipset name from store if entry exists; otherwise default.
    data = _store().load(MODULE_NAME, _default())
    entry = next((c for c in data["countries"] if c["code"] == code), None)
    ipset_name = (entry or {}).get("ipset") or _default_ipset_name(code)
    if not IPSET_NAME_RE.match(ipset_name):
        raise RuntimeError(f"invalid ipset name: {ipset_name!r}")

    url = IPDENY_URL.format(cc=cc_lower)
    cidrs = _download_cidrs(url)
    if not cidrs:
        raise RuntimeError(f"no CIDRs returned for {code} from {url}")

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    list_file = TMP_DIR / f"{cc_lower}.zone"
    list_file.write_text("\n".join(cidrs) + "\n", encoding="utf-8")

    _write_ipset_xml(ipset_name, cidrs)

    reload_res = sudo_run(["firewall-cmd", "--reload"])
    if not reload_res.ok:
        raise RuntimeError(f"reload failed: {reload_res.stderr.strip()}")

    updated_entry = {
        "code": code,
        "ipset": ipset_name,
        "last_updated": _dt.datetime.now().isoformat(timespec="seconds"),
        "entry_count": len(cidrs),
        "source_url": url,
        "adopted": False,
    }
    with _store().transaction(MODULE_NAME, _default()) as data:
        _normalise_data(data)
        found = False
        for i, c in enumerate(data["countries"]):
            if c["code"] == code:
                data["countries"][i] = updated_entry
                found = True
                break
        if not found:
            data["countries"].append(updated_entry)
    return updated_entry


def _dynamic_entry(set_id: str) -> dict | None:
    data = _normalise_data(_store().load(MODULE_NAME, _default()))
    return next((item for item in data.get("dynamic_ipsets", []) if item.get("id") == set_id), None)


def _refresh_dynamic_ipset(set_id: str) -> dict:
    data = _normalise_data(_store().load(MODULE_NAME, _default()))
    entry = next((item for item in data.get("dynamic_ipsets", []) if item.get("id") == set_id), None)
    if not entry:
        raise RuntimeError(f"dynamic ipset not found: {set_id}")
    ipset_name = entry.get("ipset") or ""
    if not IPSET_NAME_RE.match(ipset_name):
        raise RuntimeError(f"invalid ipset name: {ipset_name!r}")
    hostname = entry.get("hostname") or ""
    addresses = _resolve_ahostsv4(hostname)
    if not addresses:
        raise RuntimeError(f"no IPv4 addresses returned for {hostname}")

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    list_file = TMP_DIR / f"{set_id}.zone"
    list_file.write_text("\n".join(addresses) + "\n", encoding="utf-8")
    _write_ipset_xml(ipset_name, addresses)

    reload_res = sudo_run(["firewall-cmd", "--reload"])
    if not reload_res.ok:
        raise RuntimeError(f"reload failed: {reload_res.stderr.strip()}")

    updated_entry = dict(entry)
    updated_entry.update({
        "last_updated": _dt.datetime.now().isoformat(timespec="seconds"),
        "entry_count": len(addresses),
        "addresses": addresses,
    })
    with _store().transaction(MODULE_NAME, _default()) as stored:
        _normalise_data(stored)
        for idx, item in enumerate(stored["dynamic_ipsets"]):
            if item.get("id") == set_id:
                stored["dynamic_ipsets"][idx] = updated_entry
                break
        else:
            stored["dynamic_ipsets"].append(updated_entry)
    return updated_entry


def _resolve_ahostsv4(hostname: str) -> list[str]:
    if not hostname:
        raise RuntimeError("hostname is empty")
    res = run(["getent", "ahostsv4", hostname], timeout=DOWNLOAD_TIMEOUT)
    if not res.ok:
        raise RuntimeError((res.stderr or res.stdout or "getent failed").strip())
    addresses: list[str] = []
    for line in res.stdout.splitlines():
        first = line.split(None, 1)[0] if line.split() else ""
        if not first:
            continue
        try:
            address = str(ipaddress.IPv4Address(first))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return sorted(addresses, key=ipaddress.IPv4Address)


def _download_cidrs(url: str) -> list[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "server-gui/0.1"})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"download failed: {e}") from e
    cidrs: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "/" not in s:
            continue
        cidrs.append(str(ipaddress.ip_network(s, strict=False)))
    return sorted(set(cidrs), key=lambda item: (
        ipaddress.ip_network(item).version,
        ipaddress.ip_network(item).network_address,
    ))
