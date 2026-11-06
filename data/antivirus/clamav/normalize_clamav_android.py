#!/usr/bin/env python3
"""Build a narrow ClamAV Android file-hash subset from verified CVDs.

SPDX-License-Identifier: MIT
This original conversion script is separate from the GPL-2.0-only ClamAV data.
It does not implement libclamav or execute signature bytecode.

The extraction route requires an official sigtool executable, represented by
--sigtool-command-json (an argv array), and preserves every selected raw line,
the full hash allow/ignore lists, the CVD's COPYING, and provenance.
The rebuild route verifies the recorded hashes of packaged raw inputs and
recreates the TSVs without downloading any data or malware samples.
"""
import argparse
import collections
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tarfile

HEX = re.compile(r"[0-9a-f]+\Z")
SIZE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
NAME = re.compile(r"[A-Za-z0-9_.+()/-]+\Z")
ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}
ALLOWED_CATEGORIES = {
    "Malware", "Trojan", "Dropper", "Spyware", "Ransomware",
    "Downloader", "Keylogger", "Virus",
}
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 128


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hash_path(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def file_hash_line(line):
    columns = line.split(":")
    if not 3 <= len(columns) <= 5:
        raise ValueError("Unsupported hash-signature field count")
    value, size, name = columns[:3]
    value = value.lower()
    if len(value) not in ALGORITHMS or not HEX.fullmatch(value):
        raise ValueError("Malformed file hash")
    if size != "*" and (not SIZE.fullmatch(size) or int(size) > 2**63 - 1):
        raise ValueError("Malformed exact file size")
    if not NAME.fullmatch(name):
        raise ValueError("Malformed signature name")
    levels = columns[3:]
    if any(not SIZE.fullmatch(level) for level in levels):
        raise ValueError("Malformed engine functionality level")
    return ALGORITHMS[len(value)], value, size, name, levels


def android_name(name):
    return name.startswith(("Andr.", "Android."))


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract(cvd_dir, out, command):
    raw_dir = out / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    records = []
    input_files = {}
    for basename in ("main", "daily"):
        path = cvd_dir / (basename + ".cvd")
        proc = subprocess.run(command + ["--info", str(path)], capture_output=True,
                              text=True, timeout=90, check=False)
        verification_text = proc.stdout + proc.stderr
        (out / (basename + ".cvd.sigtool.txt")).write_text(verification_text, encoding="utf-8")
        if proc.returncode != 0 or "Verification OK." not in verification_text:
            raise ValueError("Official sigtool did not verify " + basename)
        selected = {}
        members = {}
        omitted = collections.Counter()
        with path.open("rb") as stream:
            header = stream.read(512).decode("ascii").rstrip(" \r\n\x00")
            header_columns = header.split(":")
            if len(header_columns) != 9 or header_columns[0] != "ClamAV-VDB":
                raise ValueError("Invalid CVD header")
            with tarfile.open(fileobj=stream, mode="r|gz") as archive:
                for index, member in enumerate(archive):
                    if index >= MAX_MEMBERS:
                        raise ValueError("Too many CVD members")
                    name = member.name
                    if (not member.isfile() or "/" in name or "\\" in name
                            or name in {"", ".", ".."} or name in members
                            or member.size > MAX_MEMBER_BYTES):
                        raise ValueError("Unsafe CVD member")
                    extension = pathlib.Path(name).suffix
                    info = {"bytes": member.size}
                    if name == "COPYING" or extension in {".info", ".fp", ".sfp", ".ign", ".ign2"}:
                        data = archive.extractfile(member).read()
                        selected[name] = data
                        info["sha256"] = digest(data)
                    elif extension in {".hdb", ".hsb", ".hdu", ".hsu", ".ndb", ".ldb"}:
                        full_hash = hashlib.sha256()
                        android_lines = []
                        line_count = 0
                        for raw in archive.extractfile(member):
                            line_count += 1
                            full_hash.update(raw)
                            line = raw.rstrip(b"\r\n").decode("ascii")
                            if not line:
                                continue
                            name_field = (line.split(":")[2] if extension in {".hdb", ".hsb", ".hdu", ".hsu"}
                                          else line.split(";" if extension == ".ldb" else ":")[0])
                            if android_name(name_field):
                                if extension in {".hdb", ".hsb"}:
                                    android_lines.append(raw)
                                else:
                                    omitted[extension] += 1
                        info.update({"sha256": full_hash.hexdigest(), "lines": line_count,
                                     "selectedAndroidLines": len(android_lines)})
                        if extension in {".hdb", ".hsb"}:
                            selected[name + ".android"] = b"".join(android_lines)
                    members[name] = info
        signed_info = selected[basename + ".info"].decode("ascii").splitlines()
        signed_header = signed_info[0].split(":")
        if len(signed_header) != 9 or any(signed_header[i] != header_columns[i] for i in (0, 1, 2, 3, 4, 7, 8)):
            raise ValueError("CVD outer metadata differs from signed internal metadata")
        verified_members = []
        for line in signed_info[1:]:
            if not line or line.startswith("DSIG:"):
                continue
            name, length, expected = line.split(":")
            if name not in members or members[name]["bytes"] != int(length):
                raise ValueError("Internal CVD file-size mismatch")
            actual = members[name].get("sha256")
            if actual is not None:
                if actual != expected:
                    raise ValueError("Internal CVD SHA256 mismatch")
                verified_members.append(name)
        for name, data in selected.items():
            filename = basename + "-COPYING.txt" if name == "COPYING" else name
            target = raw_dir / filename
            target.write_bytes(data)
            input_files[filename] = {"bytes": len(data), "sha256": digest(data)}
        record = {
            "filename": path.name, "bytes": path.stat().st_size,
            "sha256": hash_path(path), "version": int(header_columns[2]),
            "buildTimeUtcDisplay": header_columns[1], "buildTimeEpoch": int(header_columns[8]),
            "publisher": header_columns[7], "allFormatsSignatureCount": int(header_columns[3]),
            "minimumFunctionalityLevel": int(header_columns[4]),
            "embeddedSignatureVerifiedBy": "official ClamAV sigtool 1.5.4",
            "embeddedSignatureAlgorithm": "legacy ClamAV RSA/MD5 CVD signature",
            "detachedModernSignatureVerified": False,
            "signedInternalMetadataMatched": True,
            "selectedSourceMembersSha256Verified": verified_members,
            "members": members, "omittedAndroidOtherFormats": dict(omitted),
        }
        download_record = path.with_name(path.name + ".download.json")
        if download_record.exists():
            record["download"] = json.loads(download_record.read_text())
        records.append(record)
    licenses = [raw_dir / "main-COPYING.txt", raw_dir / "daily-COPYING.txt"]
    if licenses[0].read_bytes() != licenses[1].read_bytes():
        raise ValueError("CVD license copies differ; review required")
    (out / "COPYING-ClamAV.txt").write_bytes(licenses[0].read_bytes())
    provenance = {
        "schema": "refurbcheck-clamav-subset-provenance-v1",
        "generatedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dataLicense": "GPL-2.0-only",
        "dataLicenseEvidence": ["COPYING-ClamAV.txt", "https://packages.fedoraproject.org/pkgs/clamav/clamav-data/index.html"],
        "fullClamAvEngineIncluded": False,
        "source": "https://www.clamav.net/",
        "sourceId": "clamav.android",
        "inputFiles": input_files,
        "cvds": records,
    }
    save_json(out / "provenance.json", provenance)
    return provenance


def rebuild(out, provenance):
    raw = out / "raw"
    for name, meta in provenance["inputFiles"].items():
        path = raw / name
        if path.stat().st_size != meta["bytes"] or hash_path(path) != meta["sha256"]:
            raise ValueError("Packaged raw source differs: " + name)
    ignored_names = set()
    for path in sorted(raw.glob("*.ign2")):
        for line in path.read_text().splitlines():
            if line and not line.startswith("#"):
                ignored_names.add(line.split(":")[0])
    for path in sorted(raw.glob("*.ign")):
        for line in path.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            columns = line.split(":")
            if len(columns) != 3 or not SIZE.fullmatch(columns[1]):
                raise ValueError("Unsupported legacy ignore format")
            ignored_names.add(columns[2])
    allow_rows = set()
    for path in sorted(list(raw.glob("*.fp")) + list(raw.glob("*.sfp"))):
        for line in path.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            algorithm, value, size, name, levels = file_hash_line(line)
            if levels:
                raise ValueError("Unexpected allow-list functionality qualifiers")
            allow_rows.add((algorithm, value, size, name, "clamav.allow"))
    allow_digests = {(row[0], row[1]) for row in allow_rows}
    rows = []
    excluded = []
    categories = collections.Counter()
    qualifiers = collections.Counter()
    for path in sorted(raw.glob("*.android")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if not line:
                continue
            algorithm, value, size, name, levels = file_hash_line(line)
            if not android_name(name):
                raise ValueError("A non-Android signature entered selected source")
            category = name.split(".")[1]
            categories[category] += 1
            qualifiers[":".join(levels) or "none"] += 1
            reason = None
            if name in ignored_names:
                reason = "retired_by_ignore_list"
            elif category not in ALLOWED_CATEGORIES:
                reason = "adware_tool_packed_or_unsupported_category"
            elif (algorithm, value) in allow_digests:
                reason = "hash_present_in_file_allow_list"
            if reason:
                excluded.append({"reason": reason, "file": path.name, "line": number, "raw": line})
                continue
            if levels and (int(levels[0]) > 234 or (len(levels) == 2 and int(levels[1]) < 234)):
                raise ValueError("Signature outside reference engine functionality range")
            rows.append((algorithm, value, size, name, "clamav.android"))
    # Keep one original name per exact algorithm/digest/size key. Preserve alias
    # rows in the conversion ledger, so the source and the decision are reviewable.
    unique = {}
    for row in sorted(rows):
        key = row[:3]
        if key in unique:
            excluded.append({"reason": "duplicate_hash_size_alias", "raw": "\t".join(row)})
        else:
            unique[key] = row
    final_rows = sorted(unique.values())
    for filename, table in [("clamav-android.tsv", final_rows), ("clamav-allow.tsv", sorted(allow_rows))]:
        text = "".join("\t".join(row) + "\n" for row in table)
        (out / filename).write_text(text, encoding="ascii", newline="\n")
    save_json(out / "excluded-records.json", excluded)
    counts = {
        "selectedRawAndroidHashRecords": sum(categories.values()),
        "categoriesBeforeFiltering": dict(categories),
        "functionalityQualifiersBeforeFiltering": dict(qualifiers),
        "excluded": dict(collections.Counter(x["reason"] for x in excluded)),
        "retiredNamesLoaded": len(ignored_names),
        "finalHashRecords": len(final_rows),
        "finalAlgorithms": dict(collections.Counter(x[0] for x in final_rows)),
        "finalExactSizes": sum(x[2] != "*" for x in final_rows),
        "fileAllowRecords": len(allow_rows),
        "fileAllowAlgorithms": dict(collections.Counter(x[0] for x in allow_rows)),
    }
    provenance["selectionPolicy"] = {
        "formats": ["hdb", "hsb"], "platformPrefixes": ["Andr.", "Android."],
        "categories": sorted(ALLOWED_CATEGORIES),
        "puaFormatsExcluded": ["hdu", "hsu"],
        "otherFormatsNotImplemented": ["ndb", "ldb", "bytecode", "yara", "mdb", "msb", "imp", "cdb"],
        "ignoreHandling": "Conservatively remove every matching signature name, including MD5-qualified ignore names.",
        "allowHandling": "Conservatively exclude selected rules whose algorithm/digest occurs in the complete fp/sfp lists. Also retain complete fp/sfp table for per-file runtime allow matching scoped to ClamAV rules.",
        "fileSize": "Preserve exact byte length or '*' from source. Do not treat zero as wildcard.",
        "functionalityRange": "Check source min/max against reference sigtool 1.5.4 FLEVEL 234; preserve original qualifiers in raw source. Only raw whole-file hash comparisons are implemented.",
        "fileSemantics": "Exact raw-file hashes only. ZIP/APK entry bytes may also be hashed independently; no HTML/text normalization, emulation, decryption, PE sections or general ClamAV engine behavior is implied.",
        "duplicateHandling": "One lexical-first original signature name per algorithm/digest/size; aliases recorded separately.",
    }
    provenance["counts"] = counts
    provenance["outputs"] = {name: {"bytes": (out / name).stat().st_size, "sha256": hash_path(out / name)}
                             for name in ("clamav-android.tsv", "clamav-allow.tsv", "excluded-records.json")}
    save_json(out / "provenance.json", provenance)
    print(json.dumps({"counts": counts, "outputs": provenance["outputs"]}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cvd-dir", type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--sigtool-command-json", help="JSON argv prefix for an installed official sigtool")
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.rebuild:
        provenance = json.loads((args.out / "provenance.json").read_text())
    else:
        if not args.cvd_dir or not args.sigtool_command_json:
            parser.error("--cvd-dir and --sigtool-command-json are required for extraction")
        command = json.loads(args.sigtool_command_json)
        if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
            parser.error("sigtool command must be a nonempty JSON array of strings")
        provenance = extract(args.cvd_dir, args.out, command)
    rebuild(args.out, provenance)


if __name__ == "__main__":
    main()
