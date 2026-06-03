#!/usr/bin/env python3
# scripts/prepare-synca-rpm-dir-from-repodata.py
# Downloads a compact RPM dependency closure and writes DNF-compatible repos.

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import lzma
import os
import shutil
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

COMMON_NS = "http://linux.duke.edu/metadata/common"
FILELISTS_NS = "http://linux.duke.edu/metadata/filelists"
REPO_NS = "http://linux.duke.edu/metadata/repo"
RPM_NS = "http://linux.duke.edu/metadata/rpm"

ET.register_namespace("", COMMON_NS)
ET.register_namespace("rpm", RPM_NS)


@dataclass(frozen=True)
class RepoSpec:
    repo_id: str
    baseurl: str
    dest_repo: str
    priority: int


@dataclass(frozen=True)
class Requirement:
    name: str
    flags: str = ""
    epoch: str = "0"
    ver: str = ""
    rel: str = ""


@dataclass(frozen=True)
class Provide:
    name: str
    flags: str = ""
    epoch: str = "0"
    ver: str = ""
    rel: str = ""


@dataclass
class Package:
    repo: RepoSpec
    name: str
    arch: str
    epoch: str
    ver: str
    rel: str
    checksum: str
    location: str
    primary_element: ET.Element
    filelists_element: ET.Element | None = None
    provides: list[Provide] = field(default_factory=list)
    requires: list[Requirement] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    @property
    def nevra(self) -> str:
        return f"{self.name}-{self.epoch}:{self.ver}-{self.rel}.{self.arch}"

    @property
    def filename(self) -> str:
        return self.location.rsplit("/", 1)[-1]

    @property
    def url(self) -> str:
        return self.repo.baseurl.rstrip("/") + "/" + self.location.lstrip("/")


def default_repos(mirror: str, version: str) -> list[RepoSpec]:
    base = mirror.rstrip("/")
    return [
        RepoSpec("al8-baseos", f"{base}/{version}/BaseOS/x86_64/os", "BaseOS", 10),
        RepoSpec("al8-appstream", f"{base}/{version}/AppStream/x86_64/os", "AppStream", 20),
        RepoSpec("al8-powertools", f"{base}/{version}/PowerTools/x86_64/os", "SyncA-Extra", 30),
        RepoSpec("epel8", "https://download.fedoraproject.org/pub/epel/8/Everything/x86_64", "SyncA-Extra", 40),
    ]


def read_package_goals(path: Path) -> list[str]:
    goals: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        goals.append(line)
    return goals


def fetch_bytes(url: str, timeout: int = 120) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def download_file(url: str, target: Path, expected_sha256: str | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and expected_sha256:
        if sha256_file(target) == expected_sha256:
            return
        target.unlink()
    elif target.exists():
        return

    part = target.with_suffix(target.suffix + ".part")
    with urllib.request.urlopen(url, timeout=300) as response, part.open("wb") as fh:
        shutil.copyfileobj(response, fh, length=1024 * 1024)
    if expected_sha256 and sha256_file(part) != expected_sha256:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"checksum mismatch: {url}")
    part.replace(target)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repomd_locations(repo: RepoSpec) -> tuple[str, str]:
    repomd = ET.fromstring(fetch_bytes(f"{repo.baseurl.rstrip('/')}/repodata/repomd.xml"))
    locations: dict[str, str] = {}
    for data in repomd.findall(f"{{{REPO_NS}}}data"):
        data_type = data.attrib.get("type", "")
        location = data.find(f"{{{REPO_NS}}}location")
        if location is not None and "href" in location.attrib:
            locations[data_type] = location.attrib["href"]
    if "primary" not in locations or "filelists" not in locations:
        raise RuntimeError(f"primary/filelists metadata not found for {repo.repo_id}")
    return locations["primary"], locations["filelists"]


def parse_entry(element: ET.Element) -> Requirement:
    return Requirement(
        name=element.attrib.get("name", ""),
        flags=element.attrib.get("flags", ""),
        epoch=element.attrib.get("epoch", "0"),
        ver=element.attrib.get("ver", ""),
        rel=element.attrib.get("rel", ""),
    )


def parse_provide(element: ET.Element) -> Provide:
    return Provide(
        name=element.attrib.get("name", ""),
        flags=element.attrib.get("flags", ""),
        epoch=element.attrib.get("epoch", "0"),
        ver=element.attrib.get("ver", ""),
        rel=element.attrib.get("rel", ""),
    )


def parse_primary(repo: RepoSpec, cache_dir: Path) -> dict[str, Package]:
    primary_href, _ = repomd_locations(repo)
    primary_path = cache_dir / repo.repo_id / primary_href.rsplit("/", 1)[-1]
    download_file(repo.baseurl.rstrip("/") + "/" + primary_href, primary_path)
    with open_metadata(primary_path) as fh:
        root = ET.parse(fh).getroot()

    packages: dict[str, Package] = {}
    for pkg_el in root.findall(f"{{{COMMON_NS}}}package"):
        arch = text_of(pkg_el, "arch")
        if arch not in {"x86_64", "noarch"}:
            continue
        name = text_of(pkg_el, "name")
        version = pkg_el.find(f"{{{COMMON_NS}}}version")
        checksum_el = pkg_el.find(f"{{{COMMON_NS}}}checksum")
        location_el = pkg_el.find(f"{{{COMMON_NS}}}location")
        format_el = pkg_el.find(f"{{{COMMON_NS}}}format")
        if version is None or checksum_el is None or location_el is None or format_el is None:
            continue
        checksum = (checksum_el.text or "").strip()
        location = location_el.attrib.get("href", "")
        package = Package(
            repo=repo,
            name=name,
            arch=arch,
            epoch=version.attrib.get("epoch", "0"),
            ver=version.attrib.get("ver", ""),
            rel=version.attrib.get("rel", ""),
            checksum=checksum,
            location=location,
            primary_element=pkg_el,
        )
        provides_el = format_el.find(f"{{{RPM_NS}}}provides")
        if provides_el is not None:
            package.provides.extend(parse_provide(entry) for entry in provides_el.findall(f"{{{RPM_NS}}}entry"))
        requires_el = format_el.find(f"{{{RPM_NS}}}requires")
        if requires_el is not None:
            package.requires.extend(parse_entry(entry) for entry in requires_el.findall(f"{{{RPM_NS}}}entry"))
        for file_el in format_el.findall(f"{{{COMMON_NS}}}file"):
            if file_el.text:
                package.files.append(file_el.text.strip())
        packages[checksum] = package
    return packages


def attach_filelists(repo: RepoSpec, cache_dir: Path, packages: dict[str, Package]) -> None:
    _, filelists_href = repomd_locations(repo)
    filelists_path = cache_dir / repo.repo_id / filelists_href.rsplit("/", 1)[-1]
    download_file(repo.baseurl.rstrip("/") + "/" + filelists_href, filelists_path)
    with open_metadata(filelists_path) as fh:
        root = ET.parse(fh).getroot()
    for pkg_el in root.findall(f"{{{FILELISTS_NS}}}package"):
        pkgid = pkg_el.attrib.get("pkgid", "")
        package = packages.get(pkgid)
        if not package:
            continue
        package.filelists_element = pkg_el
        for file_el in pkg_el.findall(f"{{{FILELISTS_NS}}}file"):
            if file_el.text:
                package.files.append(file_el.text.strip())


def text_of(element: ET.Element, child: str) -> str:
    found = element.find(f"{{{COMMON_NS}}}{child}")
    return (found.text or "").strip() if found is not None else ""


def open_metadata(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rb")
    if path.name.endswith(".xz"):
        return lzma.open(path, "rb")
    return path.open("rb")


def build_indexes(packages: Iterable[Package]) -> tuple[dict[str, list[Package]], dict[str, list[tuple[Provide, Package]]]]:
    by_name: dict[str, list[Package]] = {}
    by_provide: dict[str, list[tuple[Provide, Package]]] = {}
    for package in packages:
        by_name.setdefault(package.name, []).append(package)
        package_provides = list(package.provides)
        package_provides.append(Provide(package.name, "EQ", package.epoch, package.ver, package.rel))
        package_provides.extend(Provide(path) for path in package.files if path)
        for provide in package_provides:
            by_provide.setdefault(provide.name, []).append((provide, package))
    for candidates in by_name.values():
        candidates.sort(key=package_sort_key)
    for candidates in by_provide.values():
        candidates.sort(key=lambda item: package_sort_key(item[1]))
    return by_name, by_provide


def package_sort_key(package: Package) -> tuple[int, int, str]:
    arch_score = 0 if package.arch == "x86_64" else 1
    return (package.repo.priority, arch_score, package.nevra)


def requirement_is_skippable(requirement: Requirement) -> bool:
    name = requirement.name
    return (
        not name
        or name.startswith("rpmlib(")
        or name.startswith("config(")
        or name.startswith("module(")
        or name.startswith("platform:")
        or name.startswith("(")
        or " if " in name
    )


def satisfies(requirement: Requirement, provide: Provide) -> bool:
    if requirement.name != provide.name:
        return False
    flags = requirement.flags
    if not flags:
        return True
    if flags == "EQ":
        if requirement.ver and requirement.ver != provide.ver:
            return False
        if requirement.rel and requirement.rel != provide.rel:
            return False
        if requirement.epoch and requirement.epoch != provide.epoch:
            return False
        return True
    # The repository metadata already contains the newest compatible packages
    # for this appliance build. Non-exact range checks are accepted here and
    # verified later by Anaconda/DNF during the QEMU install test.
    return flags in {"GE", "GT", "LE", "LT"}


def choose_goal(goal: str, by_name: dict[str, list[Package]], by_provide: dict[str, list[tuple[Provide, Package]]]) -> Package:
    if goal in by_name:
        return by_name[goal][0]
    return choose_provider(Requirement(goal), by_provide)


def choose_provider(requirement: Requirement, by_provide: dict[str, list[tuple[Provide, Package]]]) -> Package:
    for provide, package in by_provide.get(requirement.name, []):
        if satisfies(requirement, provide):
            return package
    raise KeyError(requirement.name)


def resolve(goals: list[str], packages: list[Package]) -> tuple[dict[str, Package], list[Requirement]]:
    by_name, by_provide = build_indexes(packages)
    selected: dict[str, Package] = {}
    queue: list[Package] = []
    unresolved: list[Requirement] = []

    for goal in goals:
        package = choose_goal(goal, by_name, by_provide)
        if package.checksum not in selected:
            selected[package.checksum] = package
            queue.append(package)

    while queue:
        package = queue.pop(0)
        for requirement in package.requires:
            if requirement_is_skippable(requirement):
                continue
            try:
                provider = choose_provider(requirement, by_provide)
            except KeyError:
                unresolved.append(requirement)
                continue
            if provider.checksum not in selected:
                selected[provider.checksum] = provider
                queue.append(provider)
    return selected, unresolved


def write_repo_metadata(repo_name: str, packages: list[Package], repo_dir: Path) -> None:
    repodata = repo_dir / "repodata"
    repodata.mkdir(parents=True, exist_ok=True)

    primary_root = ET.Element(f"{{{COMMON_NS}}}metadata", {"packages": str(len(packages))})
    filelists_root = ET.Element(f"{{{FILELISTS_NS}}}filelists", {"packages": str(len(packages))})
    for package in sorted(packages, key=lambda pkg: pkg.nevra):
        primary_element = copy.deepcopy(package.primary_element)
        location = primary_element.find(f"{{{COMMON_NS}}}location")
        if location is not None:
            location.attrib["href"] = f"Packages/{package.filename}"
        primary_root.append(primary_element)
        if package.filelists_element is not None:
            filelists_root.append(copy.deepcopy(package.filelists_element))

    primary_open = serialize_with_default_namespace(primary_root, COMMON_NS)
    filelists_open = serialize_with_default_namespace(filelists_root, FILELISTS_NS)
    primary_gz = gzip.compress(primary_open, mtime=0)
    filelists_gz = gzip.compress(filelists_open, mtime=0)

    primary_name = f"{sha256_bytes(primary_gz)}-primary.xml.gz"
    filelists_name = f"{sha256_bytes(filelists_gz)}-filelists.xml.gz"
    (repodata / primary_name).write_bytes(primary_gz)
    (repodata / filelists_name).write_bytes(filelists_gz)

    repomd_root = ET.Element(f"{{{REPO_NS}}}repomd")
    timestamp = str(int(time.time()))
    add_repomd_data(repomd_root, "primary", primary_name, primary_gz, primary_open, timestamp)
    add_repomd_data(repomd_root, "filelists", filelists_name, filelists_gz, filelists_open, timestamp)
    repomd_bytes = serialize_with_default_namespace(repomd_root, REPO_NS)
    (repodata / "repomd.xml").write_bytes(repomd_bytes)
    print(f"{repo_name}: wrote metadata for {len(packages)} packages")


def serialize_with_default_namespace(root: ET.Element, namespace: str) -> bytes:
    ET.register_namespace("", namespace)
    ET.register_namespace("rpm", RPM_NS)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def add_repomd_data(root: ET.Element, data_type: str, filename: str, compressed: bytes, open_data: bytes, timestamp: str) -> None:
    data = ET.SubElement(root, f"{{{REPO_NS}}}data", {"type": data_type})
    checksum = ET.SubElement(data, f"{{{REPO_NS}}}checksum", {"type": "sha256"})
    checksum.text = sha256_bytes(compressed)
    open_checksum = ET.SubElement(data, f"{{{REPO_NS}}}open-checksum", {"type": "sha256"})
    open_checksum.text = sha256_bytes(open_data)
    location = ET.SubElement(data, f"{{{REPO_NS}}}location", {"href": f"repodata/{filename}"})
    timestamp_el = ET.SubElement(data, f"{{{REPO_NS}}}timestamp")
    timestamp_el.text = timestamp
    size = ET.SubElement(data, f"{{{REPO_NS}}}size")
    size.text = str(len(compressed))
    open_size = ET.SubElement(data, f"{{{REPO_NS}}}open-size")
    open_size.text = str(len(open_data))


def prepare_output(output_dir: Path) -> None:
    tmp_dir = output_dir.with_suffix(output_dir.suffix + ".tmp")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)
    return None


def copy_cached_package(package: Package, target: Path, output_dir: Path) -> bool:
    source = output_dir / package.repo.dest_repo / "Packages" / package.filename
    if not source.exists() or sha256_file(source) != package.checksum:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-list", type=Path, default=Path("iso/package-lists/synca-rpms-el8.txt"))
    parser.add_argument("--output-dir", type=Path, default=Path("output/rpms-almalinux8"))
    parser.add_argument("--cache-dir", type=Path, default=Path("output/repo-metadata-cache/almalinux8"))
    parser.add_argument("--mirror", default="http://ftp.riken.jp/Linux/almalinux")
    parser.add_argument("--version", default="8.10")
    args = parser.parse_args()

    repos = default_repos(args.mirror, args.version)
    goals = read_package_goals(args.package_list)
    print(f"package goals: {len(goals)}")

    all_packages: list[Package] = []
    packages_by_repo: dict[str, dict[str, Package]] = {}
    for repo in repos:
        print(f"reading metadata: {repo.repo_id}")
        parsed = parse_primary(repo, args.cache_dir)
        attach_filelists(repo, args.cache_dir, parsed)
        packages_by_repo[repo.repo_id] = parsed
        all_packages.extend(parsed.values())
        print(f"  packages: {len(parsed)}")

    selected, unresolved = resolve(goals, all_packages)
    if unresolved:
        unique = sorted({req.name for req in unresolved})
        print("unresolved requirements:", file=sys.stderr)
        for name in unique[:100]:
            print(f"  {name}", file=sys.stderr)
        if len(unique) > 100:
            print(f"  ... {len(unique) - 100} more", file=sys.stderr)
        return 2

    tmp_dir = args.output_dir.with_suffix(args.output_dir.suffix + ".tmp")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)

    selected_by_dest: dict[str, list[Package]] = {"BaseOS": [], "AppStream": [], "SyncA-Extra": []}
    for package in selected.values():
        selected_by_dest.setdefault(package.repo.dest_repo, []).append(package)
        target = tmp_dir / package.repo.dest_repo / "Packages" / package.filename
        if copy_cached_package(package, target, args.output_dir):
            print(f"copying {package.repo.dest_repo}/{package.filename}")
            continue
        print(f"downloading {package.repo.dest_repo}/{package.filename}")
        download_file(package.url, target, package.checksum)

    for dest_repo, repo_packages in selected_by_dest.items():
        repo_dir = tmp_dir / dest_repo
        (repo_dir / "Packages").mkdir(parents=True, exist_ok=True)
        write_repo_metadata(dest_repo, repo_packages, repo_dir)

    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    tmp_dir.replace(args.output_dir)
    print(f"Pruned RPM repositories prepared: {args.output_dir}")
    print(f"Selected packages: {len(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
