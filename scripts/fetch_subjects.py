#!/usr/bin/env python3
"""Download pinned Maven subjects; verify every published byte before use.

Only standard-library modules are required. Source mode also fetches POMs and
extracts Java/Kotlin/Scala/Groovy sources into the original gt/sources layout.
Missing source artifacts remain unavailable rather than being replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parents[1]
ALLOWED_HOSTS = {"repo.maven.apache.org", "repo1.maven.org"}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_target(root, relative):
    value = str(relative)
    parts = PurePosixPath(value)
    if (not value or "\\" in value or parts.is_absolute()
            or any(p in ("..", ".") or ":" in p for p in parts.parts)):
        raise ValueError(f"Unsafe relative path: {value!r}")
    destination = root.joinpath(*parts.parts).resolve()
    if not destination.is_relative_to(root):
        raise ValueError(f"Path escapes output root: {value!r}")
    return destination


def matches(path, record):
    return (path.is_file() and path.stat().st_size == record["size_bytes"]
            and sha256(path) == record["sha256"])


def validate_record(record):
    parsed = urllib.parse.urlparse(record["url"])
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Subject URL must be an HTTPS Maven Central URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Subject URL contains unexpected authentication or parameters")
    if not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
        raise ValueError("Missing/invalid pinned SHA256")
    if not isinstance(record["size_bytes"], int) or record["size_bytes"] < 0:
        raise ValueError("Missing/invalid pinned byte count")


def download(record, destination, timeout, attempts, force):
    validate_record(record)
    if matches(destination, record):
        return "verified cache"
    if destination.exists() and not force:
        raise ValueError(f"Existing file fails checksum: {destination}; use --force to replace it")
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    if partial.is_symlink():
        raise ValueError(f"Refusing a symbolic-link partial download: {partial}")
    if partial.exists() and partial.stat().st_size > record["size_bytes"]:
        partial.unlink()
    for attempt in range(attempts):
        try:
            offset = partial.stat().st_size if partial.exists() else 0
            if offset == record["size_bytes"] and matches(partial, record):
                os.replace(partial, destination)
                return "verified resumed download"
            if offset == record["size_bytes"]:
                partial.unlink()
                offset = 0
            headers = {"User-Agent": "threadlocal-analyzer-evaluation/1.0"}
            if offset:
                headers["Range"] = f"bytes={offset}-"
            request = urllib.request.Request(record["url"], headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = response.getcode()
                if offset and status == 206:
                    content_range = response.headers.get("Content-Range", "")
                    if not content_range.startswith(f"bytes {offset}-"):
                        raise ValueError("Server returned an inconsistent partial range")
                    mode = "ab"
                elif status == 200:
                    mode = "wb"  # Server ignored Range: safely restart this file.
                else:
                    raise ValueError(f"Unexpected HTTP status {status}")
                with partial.open(mode) as stream:
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        stream.write(chunk)
            if not matches(partial, record):
                # An incomplete transfer can be resumed; a complete corrupt file cannot.
                if partial.stat().st_size >= record["size_bytes"]:
                    partial.unlink()
                raise ValueError("Downloaded byte count or SHA256 does not match the frozen manifest")
            os.replace(partial, destination)
            return "verified download"
        except (OSError, ValueError, urllib.error.URLError) as error:
            if attempt + 1 == attempts:
                raise RuntimeError(f"Download failed for {record['url']}: {error}") from error
            time.sleep(min(3 * (attempt + 1), 9))
    raise RuntimeError("No download attempt was made")


def extract_sources(archive, destination):
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    written = 0
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            if item.is_dir() or not item.filename.endswith((".java", ".kt", ".scala", ".groovy")):
                continue
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Source archive contains a symbolic link")
            target = safe_target(destination, item.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Refresh the extracted file from the verified archive, not an old source tree.
            temporary = target.with_name(target.name + ".part")
            if temporary.is_symlink():
                raise ValueError("Refusing a symbolic-link extracted-source temporary file")
            with source.open(item) as incoming, temporary.open("wb") as outgoing:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                    outgoing.write(chunk)
            os.replace(temporary, target)
            written += 1
    return written


def selected_releases(manifest, split="all", ids=None, limit=None):
    requested = set(ids or [])
    known = {b["id"] for r in manifest["releases"] for b in r["records"]}
    if requested - known:
        raise ValueError("Unknown prepared record IDs: " + ",".join(sorted(requested - known)))
    releases = [r for r in manifest["releases"]
                if (split == "all" or split in r["splits"])
                and (not requested or any(b["id"] in requested for b in r["records"]))]
    return releases if limit is None else releases[:limit]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=REPO / "manifests/artifacts.json")
    parser.add_argument("--output-root", type=Path, default=REPO)
    parser.add_argument("--mode", choices=("binary", "source", "both"), default="both")
    parser.add_argument("--split", choices=("all", "design", "heldout"), default="all")
    parser.add_argument("--ids", help="Comma-separated prepared record IDs; selects both releases")
    parser.add_argument("--limit", type=int, help="Limit the number of distinct releases after filtering")
    parser.add_argument("--dry-run", action="store_true", help="Print selection without creating files")
    parser.add_argument("--verify-only", action="store_true", help="Check downloaded files without network access")
    parser.add_argument("--no-extract", action="store_true", help="Keep verified source archives without extracting")
    parser.add_argument("--force", action="store_true", help="Replace an existing checksum-mismatched file")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be nonnegative")
    if args.timeout <= 0 or args.attempts < 1:
        parser.error("--timeout must be positive and --attempts at least one")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        parser.error("Unsupported artifacts manifest schema")
    root = args.output_root.resolve()
    records = selected_releases(manifest, args.split, args.ids.split(",") if args.ids else [], args.limit)
    failures = 0
    for release in records:
        modes = (["binary"] if args.mode == "binary" else ["source", "pom"] if args.mode == "source" else ["binary", "source", "pom"])
        for kind in modes:
            artifact = release[kind]
            if not artifact["available_in_snapshot"]:
                print(f"UNAVAILABLE {release['coordinate']} {kind}: {artifact.get('availability_status', 'not cached')}")
                continue
            destination = safe_target(root, artifact["path"])
            validate_record(artifact)
            if args.dry_run:
                print(f"{kind:6} {release['coordinate']} {artifact['size_bytes']}B {artifact['url']} -> {artifact['path']}")
                continue
            try:
                if args.verify_only:
                    if not matches(destination, artifact):
                        raise ValueError(f"Missing or checksum-mismatched file: {destination}")
                    status = "verified cache"
                else:
                    status = download(artifact, destination, args.timeout, args.attempts, args.force)
                print(f"{kind:6} {release['coordinate']} {status}")
                if kind == "source" and not args.no_extract and not args.verify_only:
                    count = extract_sources(destination, destination.parent / "src")
                    print(f"       extracted {count} source files")
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
                failures += 1
                print(f"ERROR {release['coordinate']} {kind}: {error}")
    print(f"Selected {len(records)} distinct releases; failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
