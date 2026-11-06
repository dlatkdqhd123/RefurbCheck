#!/usr/bin/env python3
"""Sign reviewed RefurbCheck reference data without including a private key.

This publishes DATA, not an APK, engine, executable rule, or arbitrary command.
The tool does not fetch upstream IOCs and never changes their retrieval dates.
Review/update the independently licensed assets and provenance first. Requires
Python 3 and OpenSSL. Keep the signing key offline/outside the repository.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
CONTEXT = b"RefurbCheck catalog update v1\0"
FILES = ["malware_catalog.json", "malware_clamav.tsv", "malware_eset.tsv",
         "malware_echap.tsv", "malware_mvt.tsv", "malware_clamav_allow.tsv"]
SOURCES = ["clamav.android", "eset.android", "echap.stalkerware", "mvt.android", "clamav.allow"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Publication time must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--created-at", required=True, help="ISO 8601 publication timestamp, including Z/offset")
    parser.add_argument("--expires-days", type=int, default=30)
    parser.add_argument("--assets", type=Path, default=ASSETS)
    parser.add_argument("--output", type=Path, default=ROOT / "data/catalog-updates/catalog-update.zip")
    parser.add_argument("--initialize-trust", action="store_true", help="One-time: write public key and initial baked-in floor; changes APK trust")
    args = parser.parse_args()
    private = args.private_key.expanduser().resolve(strict=True)
    if private == ROOT or ROOT in private.parents:
        parser.error("Private signing material must be outside this repository")
    if os.name == "posix" and private.stat().st_mode & 0o077:
        parser.error("Private key must not be group/world-readable (use chmod 600)")
    if not 1 <= args.sequence <= 1_000_000_000 or not 1 <= args.expires_days <= 30:
        parser.error("Sequence must be 1..1000000000; validity must be 1..30 days")
    created = utc(args.created_at)
    expires = created + timedelta(days=args.expires_days)
    data = {name: (args.assets / name).read_bytes() for name in FILES}
    if any(not payload for payload in data.values()) or sum(map(len, data.values())) > 16 * 1024 * 1024:
        parser.error("Empty or oversized catalog data")
    metadata = json.loads(data[FILES[0]].decode("utf-8"), object_pairs_hook=no_duplicates)
    if metadata.get("schema") != "refurbcheck-malware-catalog-v1":
        parser.error("Unsupported catalog metadata schema")
    retrieved = metadata.get("retrievedAtEpochMillis")
    if type(retrieved) is not int or retrieved <= 0 or retrieved > int(created.timestamp() * 1000) + 300_000:
        parser.error("Source retrieval time is invalid/later than publication; do not relabel it")
    if int(created.timestamp() * 1000) - retrieved > 30 * 86400 * 1000:
        parser.error("Source retrieval is over 30 days old: refresh and review sources first")
    descriptions = metadata["datasets"] + [metadata["clamavSourceOnlyAllowlist"]]
    if len(descriptions) != 5:
        parser.error("Exactly four independent sources plus a ClamAV-only allowlist are required")
    index = []
    counts = []
    for name, source, description in zip(FILES[1:], SOURCES, descriptions):
        payload = data[name]
        if description["asset"] != name or description["sha256"] != digest(payload) or description["sizeBytes"] != len(payload):
            parser.error("Metadata/file digest or size mismatch: " + name)
        if description["sourceIds"] != [source] or not description["license"]:
            parser.error("Source or license metadata mismatch: " + name)
        text = payload.decode("utf-8", errors="strict")
        if not text.endswith("\n"):
            parser.error("Dataset is truncated: " + name)
        rows = [line for line in text.splitlines() if line and not line.startswith("#")]
        if not rows or len(rows) != len(set(rows)) or len(rows) != description["entryCount"]:
            parser.error("Dataset entry count/duplicate mismatch: " + name)
        for row in rows:
            fields = row.split("\t")
            if len(fields) != 5 or fields[4] != source:
                parser.error("Unexpected dataset row/source: " + name)
            algorithm, signature, size, label, _ = fields
            width = {"md5": 32, "sha1": 40, "sha256": 64}.get(algorithm)
            if width is None or not re.fullmatch("[0-9a-f]{" + str(width) + "}", signature):
                parser.error("Unsupported/malformed exact hash: " + name)
            if size != "*" and (not re.fullmatch(r"0|[1-9][0-9]*", size) or int(size) > (1 << 63) - 1):
                parser.error("Malformed size: " + name)
            if not label or len(label) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in label):
                parser.error("Malformed reference label: " + name)
        index.append({"asset": name, "sha256": digest(payload)})
        counts.append(len(rows))
    catalog_digest = digest(json.dumps(index, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
    if index != metadata["catalogIndex"] or metadata["catalogDigest"] != catalog_digest or metadata["entryCount"] != sum(counts[:4]):
        parser.error("Catalog index digest or total count mismatch")
    public_der = subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    public_path = ASSETS / "catalog_update_key.der"
    config = ROOT / "app/src/main/java/io/github/refurbcheck/CatalogUpdateConfig.java"
    if args.initialize_trust and (public_path.exists() or config.exists()):
        parser.error("Initialization refuses to overwrite an existing trust anchor; use a reviewed key-rotation change")
    if not args.initialize_trust and (not public_path.is_file() or public_path.read_bytes() != public_der):
        parser.error("Signing key does not match the pinned app public key")
    manifest = {
        "schema": "refurbcheck-catalog-update-v1", "sequence": args.sequence,
        "createdAtEpochMillis": int(created.timestamp() * 1000),
        "expiresAtEpochMillis": int(expires.timestamp() * 1000),
        "files": [{"name": name, "sizeBytes": len(data[name]), "sha256": digest(data[name])} for name in FILES],
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private)],
                               input=CONTEXT + manifest_bytes, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    if len(signature) != 384:
        parser.error("An RSA 3072-bit update signing key is required")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=False) as archive:
        for name, payload in [("manifest.json", manifest_bytes), ("manifest.sig", signature)] + list(data.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    bundle = output.getvalue()
    if len(bundle) > 8 * 1024 * 1024:
        parser.error("Bundle exceeds the 8 MiB app limit")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bundle)
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(digest(bundle) + "  " + args.output.name + "\n")
    args.output.with_suffix(".manifest.json").write_bytes(manifest_bytes)
    if args.initialize_trust:
        public_path.write_bytes(public_der)
        config.write_text('''package io.github.refurbcheck;

/** Generated public trust anchor/floor. No private key belongs in this repository. */
final class CatalogUpdateConfig {
    private CatalogUpdateConfig() { }
    static final long INITIAL_SEQUENCE=''' + str(args.sequence) + '''L;
    static final String INITIAL_BUNDLE_SHA256="''' + digest(bundle) + '''";
    static final String UPDATE_PUBLIC_KEY_SHA256="''' + digest(public_der) + '''";
    static final String UPDATE_URL="https://raw.githubusercontent.com/dlatkdqhd123/RefurbCheck/catalog-updates/catalog-update.zip";
}
''', encoding="utf-8")
    print(json.dumps({"sequence": args.sequence, "bundleSha256": digest(bundle), "bundleBytes": len(bundle),
                      "updatePublicKeySha256": digest(public_der), "sourceSnapshotDate": metadata["snapshotDate"],
                      "sourceRetrievedAtEpochMillis": retrieved, "expiresAt": expires.isoformat(),
                      "entryCount": metadata["entryCount"]}, indent=2))


if __name__ == "__main__":
    main()
