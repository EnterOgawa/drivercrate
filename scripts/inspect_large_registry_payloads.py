"""大型公式ZIPの有限・非実行構造診断（ADR 0242）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
INFと一覧だけを読む。本体展開・署名合格・driver導入・実端末列挙は行わない。
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import time
import zipfile

import collector_registry as cr
import collector_large_payload_evidence as lp


MAX_ENTRIES = 32768
MAX_EXPANDED = 8 * lp.GIB
MAX_INF = 4 * 1024 ** 2
MAX_INFS = 512
MAX_INF_TOTAL = 64 * 1024 ** 2
MAX_SECONDS = 180
KNOWN_UPDATE_REFERENCES = {"firmwareresource", "firmwarefilename", "firmwareversion", "updatecapsule"}


def file_hash(path: Path) -> str:
    """最大2GiBのregular fileを固定1MiB単位でhash化し、metadata変化を拒否する。"""
    cr.regular_path(path)
    before = path.stat()
    cr.require(0 < before.st_size <= 2 * lp.GIB, "PAYLOAD_SIZE")
    value = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 ** 2):
            total += len(chunk)
            cr.require(total <= 2 * lp.GIB, "PAYLOAD_SIZE")
            value.update(chunk)
    cr.regular_path(path)
    after = path.stat()
    cr.require(total == before.st_size and (before.st_size, before.st_mtime_ns) ==
               (after.st_size, after.st_mtime_ns), "INPUT_CHANGED")
    return value.hexdigest()


def validate_entries(entries: list[zipfile.ZipInfo]) -> dict:
    """ZIP宣言のpath・重複・圧縮形式・展開予算を検査する。全memberのCRC確認ではない。"""
    cr.require(len(entries) <= MAX_ENTRIES, "ENTRY_BUDGET")
    names = set()
    extensions = Counter()
    expanded = 0
    inf_bytes = 0
    infs = 0
    for entry in entries:
        name = entry.orig_filename
        parts = PurePosixPath(name.rstrip("/")).parts
        cr.require(name == entry.filename and 0 < len(name) <= 1024 and not name.startswith("/") and "\\" not in name and
                   ":" not in name and "\x00" not in name and
                   all(ord(c) >= 32 and ord(c) != 127 for c in name) and parts and
                   all(p not in {"", ".", ".."} and not p.endswith((" ", ".")) for p in name.rstrip("/").split("/")),
                   "MEMBER_PATH")
        key = name.rstrip("/").casefold()
        cr.require(key not in names, "DUPLICATE_MEMBER")
        names.add(key)
        mode = entry.external_attr >> 16
        cr.require(not stat.S_ISLNK(mode) and (not stat.S_IFMT(mode) or
                   stat.S_ISDIR(mode) or stat.S_ISREG(mode)), "MEMBER_SPECIAL")
        cr.require(not entry.flag_bits & 1 and entry.compress_type in
                   {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, "MEMBER_ENCODING")
        cr.require(0 <= entry.file_size <= MAX_EXPANDED and 0 <= entry.compress_size <= 2 * lp.GIB,
                   "MEMBER_SIZE")
        cr.require(entry.file_size <= 200 * max(entry.compress_size, 1), "COMPRESSION_RATIO")
        expanded += entry.file_size
        cr.require(expanded <= MAX_EXPANDED, "EXPANSION_BUDGET")
        if entry.is_dir():
            cr.require(entry.file_size == 0, "DIRECTORY_BYTES")
            continue
        extension = PurePosixPath(name).suffix.lower()
        extensions[extension if re.fullmatch(r"\.[a-z0-9_+-]{1,16}", extension) else "OTHER"] += 1
        if extension == ".inf":
            infs += 1
            inf_bytes += entry.file_size
            cr.require(0 < entry.file_size <= MAX_INF and infs <= MAX_INFS and inf_bytes <= MAX_INF_TOTAL,
                       "INF_BUDGET")
    return {"entries": len(entries), "declaredExpandedBytes": expanded, "declaredInfBytes": inf_bytes,
            "infs": infs, "extensions": dict(sorted(extensions.items()))}


def inf_facts(raw: bytes, ordinal: int) -> dict:
    """INFの公開宣言を保守診断として読み、Models ID・file path・registry値を出力しない。"""
    cr.require(0 < len(raw) <= MAX_INF, "INF_BUDGET")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1252")
    version = {}
    directives = Counter()
    markers = set()
    section = ""
    for rawline in text.splitlines():
        line = rawline.split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        directives[key] += 1
        if key in KNOWN_UPDATE_REFERENCES:
            markers.add(key)
        if section == "version" and key in {"class", "driverver"}:
            # 最小ASCII宣言だけを出し、%Strings%解決・適合判定の代用にしない。
            value = value.strip().strip('"')
            if re.fullmatch(r"[A-Za-z0-9., /_-]{1,100}", value):
                version[key] = value
    return {"ordinal": ordinal, "infSha256": cr.digest(raw), "declarations": version,
            "hasExternalDependencyDirective": bool(directives["include"] or directives["needs"]),
            "hasCoInstallerRegistration": bool(directives["coinstallers32"]),
            "hasExecutionDirective": any(directives[k] for k in
                ("registerdlls", "unregisterdlls", "runpresetupcommands", "runpostsetupcommands")),
            "firmwareDirectiveMarkers": sorted(markers)}


def inspect_zip(path: Path, expected_hash: str) -> dict:
    """公式byteを前後hashへ拘束し、有限ZIP診断を返す。CATや内部EXEを実行・認証しない。"""
    started = time.monotonic()
    cr.require(file_hash(path) == expected_hash, "PAYLOAD_HASH_BINDING")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        inventory = validate_entries(entries)
        facts = []
        for entry in entries:
            cr.require(time.monotonic() - started <= MAX_SECONDS, "INSPECTION_TIME_BUDGET")
            if not entry.is_dir() and PurePosixPath(entry.filename).suffix.lower() == ".inf":
                # declared sizeを確認したINFだけを読み、CRC不一致はzipfileの例外で拒否する。
                facts.append(inf_facts(archive.read(entry), len(facts) + 1))
    cr.require(file_hash(path) == expected_hash, "INPUT_CHANGED")
    cr.require(time.monotonic() - started <= MAX_SECONDS, "INSPECTION_TIME_BUDGET")
    return {"archiveSha256": expected_hash, "archiveBytes": path.stat().st_size,
            "inventory": inventory, "infFacts": facts, "allMemberCrcChecked": False,
            "contentSignatureVerified": False, "installerExecuted": False}


def main() -> int:
    """実取得証拠と同じrecordの新規診断JSONだけを生成する。未知例外の文字列を保存しない。

    最終JSONはxbで新規作成し、streamはwithで終了処理を行う。保存例外は伝播し、
    部分出力を自動削除しないため、同じ既存pathへの再実行は拒否される。
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--payload-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    registry = cr.validate_registry(cr.read_json(args.registry))
    evidence = lp.validate_large_evidence(registry, cr.read_json(args.evidence))
    cr.regular_path(args.payload_directory, directory=True)
    cr.require(not args.output.exists(), "OUTPUT_EXISTS")
    cr.check_ancestors(args.output)
    formats = {i["recordId"]: i["format"] for i in evidence["plan"]["items"]}
    results = []
    for row in evidence["evidence"]["acquisitions"]:
        result = {"recordId": row["recordId"], "state": "NOT_CHECKED", "reason": row["reason"]}
        if row["state"] == "DOWNLOADED":
            path = args.payload_directory / (row["recordId"] + "." + formats[row["recordId"]].lower())
            try:
                cr.require(path.stat().st_size == row["bytes"], "PAYLOAD_SIZE")
                if formats[row["recordId"]] == "ZIP":
                    result.update(state="STATIC_INVENTORY", reason="NONE", facts=inspect_zip(path, row["sha256"]))
                else:
                    cr.require(file_hash(path) == row["sha256"], "PAYLOAD_HASH_BINDING")
                    result.update(state="SFX_INSPECTION_PENDING", reason="NON_EXECUTING_DECODER_PENDING",
                                  archiveSha256=row["sha256"], archiveBytes=row["bytes"])
            except cr.RegistryError as error:
                result.update(state="STRUCTURE_REJECTED", reason=str(error))
            except (zipfile.BadZipFile, UnicodeError, OSError, RuntimeError):
                result.update(state="STRUCTURE_UNCONFIRMED", reason="STATIC_READ_FAILED")
        results.append(result)
        print(row["recordId"], result["state"], result["reason"])
    document = {"schema": "dc-large-payload-static-diagnostics-v1", "researchOnly": True,
                "publishable": False, "installAuthorized": False,
                "registrySha256": evidence["evidence"]["registrySha256"],
                "largePayloadEvidenceSha256": cr.digest(cr.json_bytes(evidence)),
                "toolSha256": file_hash(Path(__file__)),
                "checkedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "samples": results}
    with args.output.open("xb") as stream:
        stream.write(cr.json_bytes(document))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
