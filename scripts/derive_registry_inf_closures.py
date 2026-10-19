"""公式元ZIPに結合したliteral INF閉包の非実行生成・再検証（ADR 0242）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
選択ZIPは研究入力。元byteの由来を保持し、CAT署名・導入権限を独自発行しない。
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath
import re
import time
import zipfile

import collector_registry as cr
import collector_large_payload_evidence as lp
import inspect_large_registry_payloads as ip


PLAN_SCHEMA = "dc-inf-closure-selection-plan-v1"
PROOF_SCHEMA = "dc-derived-inf-closures-v1"
MAX_MEMBERS = 256
MAX_EXPANDED = 256 * 1024 ** 2


def references(raw: bytes) -> set[str]:
    """同directoryのliteral CatalogFile／SourceDisksFilesだけを読む。未知参照を推定しない。"""
    cr.require(0 < len(raw) <= ip.MAX_INF, "INF_SIZE")
    text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    section = ""
    names = set()
    catalogs = set()
    source_files = set()
    disk_ids = set()
    declared_disks = set()
    for rawline in text.splitlines():
        line = rawline.split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line:
            continue
        key, value = (s.strip() for s in line.split("=", 1))
        if section == "version" and key.lower().startswith("catalogfile"):
            catalogs.add(value)
        if section == "sourcedisksfiles" or section.startswith("sourcedisksfiles."):
            fields = [s.strip() for s in value.split(",")]
            cr.require(fields and re.fullmatch(r"[0-9]{1,9}", fields[0]) is not None and
                       all(not f for f in fields[1:]), "NON_LITERAL_SOURCE")
            disk_ids.add(fields[0])
            cr.require(key.casefold() not in source_files, "DUPLICATE_SOURCE")
            source_files.add(key.casefold())
            names.add(key)
        if section == "sourcedisksnames" or section.startswith("sourcedisksnames."):
            # descriptionは許可するがcab/tag/pathによる別配布・subpathを推定しない。
            fields = [s.strip() for s in value.split(",")]
            cr.require(re.fullmatch(r"[0-9]{1,9}", key) is not None and
                       all(not f for f in fields[1:]), "NON_LITERAL_DISK")
            declared_disks.add(key)
    cr.require(catalogs and source_files and disk_ids <= declared_disks, "MISSING_LITERAL_REFERENCE")
    names |= catalogs
    cr.require(len(names) + 1 <= MAX_MEMBERS and
               all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", name) is not None and
                   not name.endswith((".", " ")) for name in names), "NON_LITERAL_REFERENCE")
    cr.require(len({n.casefold() for n in names}) == len(names), "AMBIGUOUS_REFERENCE")
    return names


def select_members(archive: zipfile.ZipFile, inf_member: str) -> list[zipfile.ZipInfo]:
    """元一覧を有限検証し、明示INFとliteral参照の実memberを一意に解決する。"""
    entries = archive.infolist()
    ip.validate_entries(entries)
    by_name = {e.filename.casefold(): e for e in entries if not e.is_dir()}
    inf = by_name.get(inf_member.casefold())
    cr.require(inf is not None and inf.filename == inf_member and
               PurePosixPath(inf_member).suffix.lower() == ".inf", "SELECTED_INF")
    parent = str(PurePosixPath(inf_member).parent)
    prefix = "" if parent == "." else parent + "/"
    selected = [inf]
    for name in sorted(references(archive.read(inf)), key=str.casefold):
        member = by_name.get((prefix + name).casefold())
        cr.require(member is not None, "REFERENCE_MISSING")
        selected.append(member)
    cr.require(len(selected) <= MAX_MEMBERS and sum(e.file_size for e in selected) <= MAX_EXPANDED and
               all(e.file_size <= lp.NATIVE_INPUT_BYTES for e in selected), "CLOSURE_BUDGET")
    return sorted(selected, key=lambda e: e.filename)


def validate_selection(large: dict, plan: dict) -> dict:
    """一回16閉包までの明示recordと安全なINF member指定を検証する。"""
    cr.fields(plan, {"schema", "revision", "selections"}, "SELECTION_FIELDS")
    cr.require(plan["schema"] == PLAN_SCHEMA, "SELECTION_SCHEMA")
    cr.identity(plan["revision"])
    rows = plan["selections"]
    cr.require(isinstance(rows, list) and 1 <= len(rows) <= 16, "SELECTION_BUDGET")
    acquisitions = {r["recordId"]: r for r in large["evidence"]["acquisitions"]}
    formats = {i["recordId"]: i["format"] for i in large["plan"]["items"]}
    seen = set()
    selected = set()
    for row in rows:
        cr.fields(row, {"id", "recordId", "infMember"}, "SELECTION_ITEM_FIELDS")
        key = cr.identity(row["id"])
        cr.require(key not in seen, "DUPLICATE_SELECTION")
        seen.add(key)
        record = row["recordId"]
        cr.require(isinstance(record, str) and record in acquisitions and
                   acquisitions[record]["state"] == "DOWNLOADED" and formats[record] == "ZIP", "SELECTION_RECORD")
        member = row["infMember"]
        cr.require(isinstance(member, str) and len(member) <= 160 and
                   re.fullmatch(r"[A-Za-z0-9_. /-]+\.inf", member) is not None and
                   not member.startswith("/") and all(p not in {"", ".", ".."} and
                       not p.endswith((" ", ".")) for p in member.split("/")), "SELECTION_MEMBER")
        pair = (record, member.casefold())
        cr.require(pair not in selected, "DUPLICATE_INF_SELECTION")
        selected.add(pair)
    return plan


def create_closure(source: Path, source_hash: str, inf_member: str, destination: Path) -> dict:
    """元memberを変更せず新規ZIPへstream copyし、元・派生・全member hashを返す。

    元・派生archiveとmember streamは各contextで終了処理を行う。予算・CRC・
    書込み・終了処理の失敗は呼出し元へ伝播し、部分destinationを自動削除しない。
    """
    started = time.monotonic()
    cr.require(ip.file_hash(source) == source_hash, "SOURCE_HASH_BINDING")
    cr.require(not destination.exists(), "OUTPUT_EXISTS")
    cr.check_ancestors(destination)
    members = []
    with zipfile.ZipFile(source) as original:
        selected = select_members(original, inf_member)
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as derived:
            for entry in selected:
                value = hashlib.sha256()
                count = 0
                info = zipfile.ZipInfo(entry.filename, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                with original.open(entry) as incoming, derived.open(info, "w") as outgoing:
                    while chunk := incoming.read(1024 ** 2):
                        count += len(chunk)
                        cr.require(count <= entry.file_size and
                                   time.monotonic() - started <= ip.MAX_SECONDS, "CLOSURE_STREAM_BUDGET")
                        outgoing.write(chunk)
                        value.update(chunk)
                cr.require(count == entry.file_size, "CLOSURE_MEMBER_SIZE")
                members.append({"sourcePath": entry.filename, "bytes": count, "sha256": value.hexdigest()})
    cr.require(destination.stat().st_size <= lp.NATIVE_INPUT_BYTES, "CLOSURE_ARCHIVE_BUDGET")
    cr.require(ip.file_hash(source) == source_hash, "INPUT_CHANGED")
    return {"sourceArchiveSha256": source_hash, "sourceInfMember": inf_member,
            "sourceInfSha256": next(m["sha256"] for m in members if m["sourcePath"] == inf_member),
            "derivedArchiveSha256": ip.file_hash(destination), "derivedArchiveBytes": destination.stat().st_size,
            "members": members}


def verify_closure(source: Path, derived: Path, proof: dict) -> None:
    """元一覧・元member・派生一覧・派生memberを再照合し、偽の再pack由来を拒否する。"""
    started = time.monotonic()
    cr.require(ip.file_hash(source) == proof["sourceArchiveSha256"] and
               ip.file_hash(derived) == proof["derivedArchiveSha256"] and
               derived.stat().st_size == proof["derivedArchiveBytes"], "CLOSURE_HASH_BINDING")
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(derived) as copied:
        expected = select_members(original, proof["sourceInfMember"])
        ip.validate_entries(copied.infolist())
        cr.require([e.filename for e in copied.infolist()] == [e.filename for e in expected] and
                   [m["sourcePath"] for m in proof["members"]] == [e.filename for e in expected], "CLOSURE_MEMBER_SET")
        for item, member in zip(expected, proof["members"], strict=True):
            cr.fields(member, {"sourcePath", "bytes", "sha256"}, "CLOSURE_MEMBER_FIELDS")
            cr.require(type(member["bytes"]) is int and member["bytes"] == item.file_size and
                       copied.getinfo(item.filename).file_size == item.file_size,
                       "CLOSURE_MEMBER_SIZE")
            for archive in (original, copied):
                value = hashlib.sha256()
                with archive.open(item.filename) as stream:
                    for chunk in iter(lambda: stream.read(1024 ** 2), b""):
                        cr.require(time.monotonic() - started <= ip.MAX_SECONDS, "CLOSURE_VERIFY_TIME_BUDGET")
                        value.update(chunk)
                cr.require(value.hexdigest() == member["sha256"], "CLOSURE_MEMBER_HASH")
        inf_hash = next(m["sha256"] for m in proof["members"] if m["sourcePath"] == proof["sourceInfMember"])
        cr.require(inf_hash == proof["sourceInfSha256"], "INF_HASH_BINDING")
    cr.require(ip.file_hash(source) == proof["sourceArchiveSha256"] and
               ip.file_hash(derived) == proof["derivedArchiveSha256"], "INPUT_CHANGED")
    cr.require(time.monotonic() - started <= ip.MAX_SECONDS, "CLOSURE_VERIFY_TIME_BUDGET")


def verify_derivation(large: dict, proof: dict, sources: Path, closures: Path) -> None:
    """閉じた研究証拠をplan・取得record・元byteへ拘束してから全閉包を再検証する。"""
    cr.fields(proof, {"schema", "researchOnly", "publishable", "installAuthorized", "registrySha256",
                      "largePayloadEvidenceSha256", "plan", "planSha256", "toolSha256", "checkedAt", "closures"},
              "DERIVATION_FIELDS")
    cr.require(proof["schema"] == PROOF_SCHEMA and proof["researchOnly"] is True and
               proof["publishable"] is False and proof["installAuthorized"] is False, "DERIVATION_SCHEMA")
    cr.require(proof["registrySha256"] == large["evidence"]["registrySha256"] and
               proof["largePayloadEvidenceSha256"] == cr.digest(cr.json_bytes(large)), "DERIVATION_SOURCE_BINDING")
    plan = validate_selection(large, proof["plan"])
    cr.require(proof["planSha256"] == cr.digest(cr.json_bytes(plan)), "DERIVATION_PLAN_BINDING")
    cr.sha256(proof["toolSha256"])
    cr.require(proof["toolSha256"] is not None and
               cr.timestamp(proof["checkedAt"]) >= cr.timestamp(large["evidence"]["asOf"]), "DERIVATION_TIME")
    cr.require(isinstance(proof["closures"], list) and len(proof["closures"]) == len(plan["selections"]),
               "DERIVATION_CLOSURE_SET")
    acquisitions = {r["recordId"]: r for r in large["evidence"]["acquisitions"]}
    for selected, closure in zip(plan["selections"], proof["closures"], strict=True):
        cr.fields(closure, {"id", "recordId", "sourceArchiveSha256", "sourceInfMember", "sourceInfSha256",
                            "derivedArchiveSha256", "derivedArchiveBytes", "members"}, "DERIVED_CLOSURE_FIELDS")
        cr.require(closure["id"] == selected["id"] and closure["recordId"] == selected["recordId"] and
                   closure["sourceInfMember"] == selected["infMember"] and closure["sourceArchiveSha256"] ==
                   acquisitions[selected["recordId"]]["sha256"], "DERIVED_CLOSURE_BINDING")
        for key in ("sourceInfSha256", "derivedArchiveSha256"):
            cr.sha256(closure[key])
            cr.require(closure[key] is not None, "DERIVED_HASH_REQUIRED")
        cr.require(type(closure["derivedArchiveBytes"]) is int and
                   0 < closure["derivedArchiveBytes"] <= lp.NATIVE_INPUT_BYTES and
                   isinstance(closure["members"], list) and 1 <= len(closure["members"]) <= MAX_MEMBERS,
                   "DERIVED_CLOSURE_BUDGET")
        verify_closure(sources / (closure["recordId"] + ".zip"), closures / (closure["id"] + ".zip"), closure)


def main() -> int:
    """明示planの研究用閉包を新しいwork出力へ生成し、各閉包を直後に再検証する。

    閉包と最終proofは逐次保存する。後続の生成・検証・保存に失敗しても先行成果と
    部分directoryを保持し、全体のrollbackや既存出力の上書きを行わない。
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--payload-directory", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    registry = cr.validate_registry(cr.read_json(args.registry))
    large = lp.validate_large_evidence(registry, cr.read_json(args.evidence))
    plan = validate_selection(large, cr.read_json(args.plan))
    if args.verify:
        proof = cr.read_json(args.output_directory / "derivation.json")
        cr.require(proof.get("plan") == plan, "DERIVATION_PLAN_BINDING")
        verify_derivation(large, proof, args.payload_directory, args.output_directory)
        print("Verified closures", len(proof["closures"]), "installerExecutions", 0)
        return 0
    cr.require(not args.output_directory.exists(), "OUTPUT_EXISTS")
    cr.check_ancestors(args.output_directory)
    cr.regular_path(args.payload_directory, directory=True)
    args.output_directory.mkdir(parents=True, exist_ok=False)
    acquisitions = {r["recordId"]: r for r in large["evidence"]["acquisitions"]}
    rows = []
    for selected in plan["selections"]:
        source = args.payload_directory / (selected["recordId"] + ".zip")
        destination = args.output_directory / (selected["id"] + ".zip")
        closure = create_closure(source, acquisitions[selected["recordId"]]["sha256"], selected["infMember"], destination)
        verify_closure(source, destination, closure)
        rows.append({"id": selected["id"], "recordId": selected["recordId"], **closure})
    proof = {"schema": PROOF_SCHEMA, "researchOnly": True, "publishable": False, "installAuthorized": False,
             "registrySha256": large["evidence"]["registrySha256"],
             "largePayloadEvidenceSha256": cr.digest(cr.json_bytes(large)), "plan": plan,
             "planSha256": cr.digest(cr.json_bytes(plan)), "toolSha256": ip.file_hash(Path(__file__)),
             "checkedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "closures": rows}
    with (args.output_directory / "derivation.json").open("xb") as stream:
        stream.write(cr.json_bytes(proof))
    print("Closures", len(rows), "installerExecutions", 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
