"""公開調査台帳の非通信検証・研究用索引・可搬snapshot生成（ADR 0227／0233／0237／0324／0327）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
開発用toolであり、native collectorの実行権限やdriver導入許可を発行しない。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import stat
import sys
import unicodedata
from datetime import datetime
from urllib.parse import unquote, unquote_to_bytes, urlsplit
import zipfile


MAX_JSON_BYTES = 16 * 1024 * 1024  # 1 fileの開発用読込み予算。対応製品の総数ではない。
REGISTRY_SCHEMA = "dc-public-driver-registry-v1"
QUERY_REGISTRY_SCHEMA = "dc-public-driver-registry-v2"
QUERY_SNAPSHOT_SCHEMA = "dc-portable-research-snapshot-v3"
COLLECTIONS = ("sources", "products", "records", "observations")
SNAPSHOT_FILES = tuple(f"{name}.json" for name in COLLECTIONS) + ("index/drivers.json",)
SCOPES = {"WINDOWS_10_X64", "WINDOWS_11_X64", "WINDOWS_SERVER_X64"}
CATEGORIES = {"LAN", "WIFI", "BLUETOOTH", "DISPLAY", "AUDIO", "SERIAL", "STORAGE",
              "CHIPSET", "USB", "PRINT", "OTHER_DRIVER"}
PRIVATE_TEXT = re.compile(
    r"(?i)(?:(?<![a-z0-9])[a-z]:[\\/]|\\\\|(?:PCI|USB|ACPI|HID)\\|S-1-[0-9-]+|"
    r"(?:password|credential|access_token|private_key|authorization)\s*[:=]|"
    r"-----BEGIN .*PRIVATE KEY-----|\bgh[pousr]_[a-z0-9]+|\bgithub_pat_[a-z0-9_]+)"
)


class RegistryError(ValueError):
    """入力値を通常logへ漏らさず、拒否理由のcodeだけを返す。"""


def require(condition: bool, code: str) -> None:
    """契約違反を検出した時点で後続の生成を中止する。"""
    if not condition:
        raise RegistryError(code)


def fields(value: object, expected: set[str], code: str) -> dict:
    """未知fieldと欠損を拒否し、dictionaryを返す。"""
    require(isinstance(value, dict) and set(value) == expected, code)
    return value


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    """JSONの同名key上書きを許可しない。"""
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_json(raw: bytes) -> dict:
    """UTF-8 JSONを容量制限と重複key検査付きで解析する。"""
    require(len(raw) <= MAX_JSON_BYTES, "JSON_SIZE")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys,
                          parse_constant=lambda _: require(False, "JSON_CONSTANT"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RegistryError("JSON_ENCODING_OR_SYNTAX") from error


def regular_path(path: Path, directory: bool = False) -> None:
    """リンク・junction等を拒否し、要求されたfile種別を確認する。"""
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ), "REPARSE_PATH")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            "PATH_TYPE")


def read_json(path: Path) -> dict:
    """開発用fileを有限byteで読み、読取り中の変更を検出する。"""
    regular_path(path)
    before = path.stat()
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    regular_path(path)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
            "INPUT_CHANGED")
    return parse_json(raw)


def json_bytes(value: object) -> bytes:
    """UTF-8 BOMなし・LFの決定的なJSON表現を生成する。"""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def digest(raw: bytes) -> str:
    """byte列のSHA-256を小文字hexで返す。署名として扱わない。"""
    return hashlib.sha256(raw).hexdigest()


def label(value: object) -> str:
    """公開表示名の正規形・長さ・秘密と端末path混入を検査する。"""
    require(isinstance(value, str) and 0 < len(value) <= 1024, "LABEL_TYPE_OR_SIZE")
    require(value == unicodedata.normalize("NFC", " ".join(value.split())) and
            all(not unicodedata.category(char).startswith("C") for char in value),
            "LABEL_CANONICAL")
    require(not PRIVATE_TEXT.search(value), "PRIVATE_TEXT")
    return value


def identity(value: object) -> str:
    """不透明な公開台帳IDを検査する。URLや製品名から導入IDを作らない。"""
    require(isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", value),
            "IDENTITY")
    return value


def timestamp(value: object) -> datetime:
    """明示UTC秒精度の確認日時を解析する。"""
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
            "TIMESTAMP")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise RegistryError("TIMESTAMP") from error


def observation_timestamp(value: object) -> datetime:
    """原HTTP観測だけのUTC小数1～6桁を保持し、世代日時の秒限定契約を変更しない。"""
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.[0-9]{1,6})?Z", value),
        "OBSERVATION_TIMESTAMP")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise RegistryError("OBSERVATION_TIMESTAMP") from error


def sha256(value: object) -> None:
    """未確認を表すnullか、SHA-256の正規表現を受け付ける。"""
    require(value is None or (isinstance(value, str) and
            re.fullmatch(r"[0-9a-f]{64}", value)), "SHA256")


def public_numeric_query(query: object, *, purpose: str) -> bool:
    """単一の公開数値selectorを用途限定で判定する（ADR 0237）。通信権限は発行しない。"""
    require(type(purpose) is str and purpose in {"PAGE", "PAYLOAD"}, "URL_PURPOSE")
    require(type(query) is str, "URL_QUERY_TYPE")
    keys = "id|drid|download_id|file_id|product_id" + ("|file" if purpose == "PAYLOAD" else "")
    return re.fullmatch(r"(?:" + keys + r")=[0-9]{1,20}", query) is not None


def public_payload_basename_query(query: object, *, purpose: str) -> bool:
    """公開basenameを本体用途だけで判定する（ADR 0324）。公式性と通信許可は発行しない。"""
    require(type(purpose) is str and purpose in {"PAGE", "PAYLOAD"}, "URL_PURPOSE")
    require(type(query) is str, "URL_QUERY_TYPE")
    return purpose == "PAYLOAD" and re.fullmatch(
        r"fileName=[A-Za-z0-9_-]{1,100}\.[A-Za-z0-9]{1,8}", query) is not None


def public_payload_response_header_query(query: object, *, purpose: str) -> bool:
    """二応答header指定の閉じた構文を本体用途だけで判定する（ADR 0327）。

    URI queryとfilename*を各一回だけ独立にdecodeし、元URLを書き換えない。
    型・用途違反はRegistryError、未対応構文はFalseとし、公式性・通信・導入許可は発行しない。
    """
    require(type(purpose) is str and purpose in {"PAGE", "PAYLOAD"}, "URL_PURPOSE")
    require(type(query) is str, "URL_QUERY_TYPE")
    # PAGEや過長queryへ新しい保存構文を広げない。
    if purpose != "PAYLOAD" or len(query) > 1536:
        return False

    def decode_ascii_once(value: str) -> str | None:
        """一層のunreserved／percent tripletだけをASCIIへdecodeする。"""
        # Raw区切り・plus・不正percentをform decodeで救済しない。
        if re.fullmatch(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+", value) is None:
            return None
        try:
            return unquote_to_bytes(value).decode("ascii")
        except UnicodeDecodeError:
            return None

    pairs = query.split("&")
    # 二key各一回以外と余分な等号を拒否する。
    if len(pairs) != 2 or any(pair.count("=") != 1 for pair in pairs):
        return False
    rows = [pair.split("=", 1) for pair in pairs]
    if {row[0] for row in rows} != {"response-content-disposition", "response-content-type"}:
        return False
    values = {key: decode_ascii_once(value) for key, value in rows}
    disposition = values["response-content-disposition"]
    # 観測されたheader literalだけを認め、一般header parserとして扱わない。
    if disposition is None or values["response-content-type"] not in {
            "application/octet-stream", "application/octet-stream;"}:
        return False
    prefix = "attachment;filename*=UTF-8''"
    if not disposition.startswith(prefix):
        return False
    filename = decode_ascii_once(disposition[len(prefix):])
    # 二層後のbasenameだけを検査し、秘密・非ASCII・過長を拒否する。
    if filename is None or not 1 <= len(filename) <= 180 or PRIVATE_TEXT.search(filename):
        return False
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.() -]*)\.(zip|exe|msi|cab|7z|rar)", filename, re.I)
    if match is None or ".." in filename or match[1].endswith((" ", ".")):
        return False
    # 予約名比較時だけ第一component末尾spaceを除き、元filenameは保持する。
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        stem + str(number) for stem in ("COM", "LPT") for number in range(1, 10)}
    if match[1].split(".")[0].rstrip(" ").upper() in reserved:
        return False
    depth = 0
    # 有限basenameを走査し、対応する深さ一の括弧だけを認める。
    for char in match[1]:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if depth not in (0, 1):
            return False
    return depth == 0


def public_query_selector(query: object, *, purpose: str) -> bool:
    """数値・本体basename・二応答header指定の閉じた保存構文を用途別に共有する。"""
    return (public_numeric_query(query, purpose=purpose) or
            public_payload_basename_query(query, purpose=purpose) or
            public_payload_response_header_query(query, purpose=purpose))


def public_url(value: object, *, allow_public_query: bool = False, purpose: str = "PAGE") -> str:
    """公開HTTPSと明示mode・用途限定の配布selectorを検査する。通信権限は発行しない。"""
    require(type(allow_public_query) is bool, "URL_QUERY_MODE")
    require(type(purpose) is str and purpose in {"PAGE", "PAYLOAD"}, "URL_PURPOSE")
    require(isinstance(value, str) and 0 < len(value) <= 2048, "URL_TYPE_OR_SIZE")
    require(not any(char.isspace() or ord(char) < 32 for char in value) and
            not PRIVATE_TEXT.search(value), "URL_PRIVATE_TEXT")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise RegistryError("URL_SYNTAX") from error
    require(parsed.scheme == "https" and host and parsed.username is None and
            parsed.password is None and port in (None, 443) and
            not parsed.fragment and "#" not in value,
            "URL_POLICY")
    # Queryを書換えず、用途ごとの閉じた保存構文だけを許可する。
    if "?" in value:
        require(allow_public_query and public_query_selector(parsed.query, purpose=purpose),
            "URL_QUERY_POLICY")
    require(host == host.lower() and re.fullmatch(r"[a-z0-9.-]+", host) and
            "." in host and not host.endswith((".local", ".internal", ".localhost", ".lan", "."))
            and not host.startswith("localhost."), "URL_HOST")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise RegistryError("URL_IP_LITERAL")
    require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part)
                for part in host.split(".")), "URL_HOST")
    decoded = value
    for _ in range(3):
        decoded = unquote(decoded)
        require(not any(ord(char) < 32 for char in decoded) and "\\" not in decoded,
                "URL_ENCODED_CONTROL")
    return value


def id_list(value: object, allow_empty: bool = False) -> list[str]:
    """重複のない参照ID集合を検査する。"""
    require(isinstance(value, list) and (allow_empty or len(value) > 0), "ID_LIST")
    for entry in value:
        identity(entry)
    require(len(set(value)) == len(value), "DUPLICATE_REFERENCE")
    return value


def validate_registry(registry: dict) -> dict:
    """共通台帳のshape・参照・根拠状態を検査し、順序を正規化して返す。"""
    fields(registry, {"schema", "revision", "asOf", *COLLECTIONS}, "REGISTRY_FIELDS")
    require(registry["schema"] in {REGISTRY_SCHEMA, QUERY_REGISTRY_SCHEMA}, "REGISTRY_SCHEMA")
    allow_public_query = registry["schema"] == QUERY_REGISTRY_SCHEMA
    identity(registry["revision"])
    as_of = timestamp(registry["asOf"])
    maps = {}
    for name in COLLECTIONS:
        items = registry[name]
        require(isinstance(items, list), "COLLECTION_TYPE")
        mapped = {}
        for item in items:
            require(isinstance(item, dict) and "id" in item, "ITEM_TYPE")
            key = identity(item["id"])
            require(key not in mapped, "DUPLICATE_ID")
            mapped[key] = item
        maps[name] = mapped
    sources, products, records, observations = (maps[name] for name in COLLECTIONS)
    require(sources and products, "EMPTY_REGISTRY")
    for source in sources.values():
        fields(source, {"id", "manufacturer", "officialPage", "collectionMethod"}, "SOURCE_FIELDS")
        label(source["manufacturer"])
        public_url(source["officialPage"], allow_public_query=allow_public_query)
        require(source["collectionMethod"] in {"MANUAL_RESEARCH", "LEGACY_ASUS_METADATA"},
                "COLLECTION_METHOD")
    seen_products = set()
    used_records = set()
    used_sources = set()
    for product in products.values():
        fields(product, {"id", "manufacturer", "model", "driverCategory", "sourceIds",
                         "recordIds", "researchState", "reason"}, "PRODUCT_FIELDS")
        for name in ("manufacturer", "model", "driverCategory"):
            label(product[name])
        require(product["driverCategory"] in CATEGORIES, "DRIVER_CATEGORY")
        product_key = tuple(product[name].casefold() for name in
                            ("manufacturer", "model", "driverCategory"))
        require(product_key not in seen_products, "DUPLICATE_PRODUCT")
        seen_products.add(product_key)
        for source_id in id_list(product["sourceIds"]):
            require(source_id in sources and sources[source_id]["manufacturer"] ==
                    product["manufacturer"], "PRODUCT_SOURCE")
            used_sources.add(source_id)
        for record_id in id_list(product["recordIds"], allow_empty=True):
            require(record_id in records, "PRODUCT_RECORD")
            used_records.add(record_id)
        require(product["researchState"] in {"METADATA_SAVED", "PAGE_ONLY", "RESEARCH_REQUIRED"},
                "RESEARCH_STATE")
        require(product["reason"] in {"NONE", "HTTP_403", "DOWNLOAD_TABLE_UNAVAILABLE",
                                     "LEGACY_PARSE_EMPTY", "LEGACY_REDIRECT_REJECTED"}, "REASON")
        has_records = bool(product["recordIds"])
        require((product["researchState"] == "METADATA_SAVED") == has_records and
                (product["reason"] == "NONE") == has_records, "PRODUCT_STATE")
    require(used_sources == set(sources), "ORPHAN_SOURCE")
    require(used_records == set(records), "ORPHAN_RECORD")
    for record in records.values():
        fields(record, {"id", "sourceId", "title", "driverCategory", "operatingSystems",
                        "packageVersion", "driverVersion", "publishedDate", "downloadUrl",
                        "linkState", "publishedSha256", "contentState"}, "RECORD_FIELDS")
        require(record["sourceId"] in sources, "RECORD_SOURCE")
        for name in ("title", "driverCategory"):
            label(record[name])
        require(record["driverCategory"] in CATEGORIES, "DRIVER_CATEGORY")
        for name in ("packageVersion", "driverVersion"):
            if record[name] is not None:
                label(record[name])
        scopes = record["operatingSystems"]
        require(isinstance(scopes, list) and scopes and all(isinstance(entry, str) for entry in scopes)
                and set(scopes) <= SCOPES and len(set(scopes)) == len(scopes), "OS_SCOPE")
        if record["publishedDate"] is not None:
            value = record["publishedDate"]
            require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value), "DATE")
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError as error:
                raise RegistryError("DATE") from error
        require(record["linkState"] in {"MISSING", "OFFICIAL_LINK", "HEAD_OK"}, "LINK_STATE")
        require((record["downloadUrl"] is None) == (record["linkState"] == "MISSING"), "LINK_URL")
        if record["downloadUrl"] is not None:
            public_url(record["downloadUrl"], allow_public_query=allow_public_query, purpose="PAYLOAD")
        sha256(record["publishedSha256"])
        require(record["contentState"] == "NOT_DOWNLOADED", "UNSUPPORTED_CONTENT_CLAIM")
    for product in products.values():
        for record_id in product["recordIds"]:
            record = records[record_id]
            require(record["sourceId"] in product["sourceIds"] and record["driverCategory"] ==
                    product["driverCategory"], "PRODUCT_RECORD_BINDING")
    observed_products = set()
    metadata_records = set()
    linked_records = set()
    head_records = set()
    for observation in observations.values():
        fields(observation, {"id", "productId", "recordId", "checkedAt", "kind", "method",
                             "evidenceUrl", "httpStatus", "evidenceSha256"}, "OBSERVATION_FIELDS")
        product_id = observation["productId"]
        require(isinstance(product_id, str) and product_id in products, "OBSERVATION_PRODUCT")
        product = products[product_id]
        observed_products.add(product_id)
        require(observation_timestamp(observation["checkedAt"]) <= as_of, "FUTURE_OBSERVATION")
        require(observation["kind"] in {"LEGACY_METADATA", "LEGACY_FAILURE", "OFFICIAL_PAGE",
                                        "OFFICIAL_LINK", "HEAD", "PAGE_FAILED"}, "OBSERVATION_KIND")
        require(observation["method"] in {"LEGACY_PROJECTION", "WEB_REVIEW", "LOCAL_HTTP"},
                "OBSERVATION_METHOD")
        status = observation["httpStatus"]
        require(status is None or (type(status) is int and 100 <= status <= 599), "HTTP_STATUS")
        sha256(observation["evidenceSha256"])
        record_id = observation["recordId"]
        if record_id is not None:
            require(isinstance(record_id, str) and record_id in product["recordIds"],
                    "OBSERVATION_RECORD")
        kind = observation["kind"]
        url = observation["evidenceUrl"]
        if url is not None:
            public_url(url, allow_public_query=allow_public_query,
                       purpose="PAYLOAD" if kind == "HEAD" else "PAGE")
        if kind.startswith("LEGACY_"):
            require(observation["method"] == "LEGACY_PROJECTION" and url is None and
                    observation["evidenceSha256"] is not None and all(
                        sources[key]["collectionMethod"] == "LEGACY_ASUS_METADATA"
                        for key in product["sourceIds"]), "LEGACY_EVIDENCE")
            if kind == "LEGACY_METADATA":
                require(record_id is not None and status == 200, "LEGACY_METADATA")
                metadata_records.add(record_id)
            else:
                require(not product["recordIds"] and record_id is None, "LEGACY_FAILURE")
        elif kind == "HEAD":
            require(record_id is not None and url == records[record_id]["downloadUrl"] and
                    status == 200 and observation["method"] == "LOCAL_HTTP", "HEAD_EVIDENCE")
            head_records.add(record_id)
        else:
            require(url in {sources[key]["officialPage"] for key in product["sourceIds"]},
                    "PAGE_EVIDENCE")
            if kind == "PAGE_FAILED":
                require(record_id is None and status is not None and status >= 400,
                        "FAILED_EVIDENCE")
            elif kind in {"OFFICIAL_LINK", "OFFICIAL_PAGE"} and record_id is not None:
                metadata_records.add(record_id)
                if kind == "OFFICIAL_LINK":
                    require(records[record_id]["downloadUrl"] is not None, "LINK_EVIDENCE")
                    linked_records.add(record_id)
    require(observed_products == set(products), "UNOBSERVED_PRODUCT")
    require(metadata_records == set(records), "UNOBSERVED_RECORD")
    for record_id, record in records.items():
        require((record_id in linked_records) == (record["linkState"] != "MISSING"),
                "LINK_EVIDENCE_STATE")
        require((record_id in head_records) == (record["linkState"] == "HEAD_OK"),
                "HEAD_EVIDENCE_STATE")
    normalized = {key: registry[key] for key in ("schema", "revision", "asOf")}
    for name in COLLECTIONS:
        normalized[name] = []
        for item in sorted(registry[name], key=lambda entry: entry["id"]):
            copied = dict(item)
            for key in ("recordIds", "sourceIds", "operatingSystems"):
                if key in copied:
                    copied[key] = sorted(copied[key])
            normalized[name].append(copied)
    return normalized


def counts(registry: dict) -> dict:
    """製品、配布record、リンクと本体の実績を別に集計する。"""
    records = {entry["id"]: entry for entry in registry["records"]}
    saved = [entry for entry in registry["products"] if entry["recordIds"]]
    return {
        "registeredManufacturers": len({entry["manufacturer"] for entry in registry["products"]}),
        "manufacturersWithMetadata": len({entry["manufacturer"] for entry in saved}),
        "targetProducts": len(registry["products"]), "productsWithMetadata": len(saved),
        "productsWithoutMetadata": len(registry["products"]) - len(saved),
        "distributionRecords": len(records),
        "recordsWithOfficialLinks": sum(entry["downloadUrl"] is not None for entry in records.values()),
        "recordsWithHead200": sum(entry["linkState"] == "HEAD_OK" for entry in records.values()),
        "productsWithOfficialLinks": sum(any(records[key]["downloadUrl"] is not None
                                               for key in entry["recordIds"]) for entry in saved),
        "payloadsDownloaded": 0, "contentsVerified": 0, "deviceApplicabilityMeasured": 0,
        "uniquePayloads": None,
    }


def research_index(registry: dict) -> dict:
    """全調査対象と保留を残す索引を生成する。導入許可には使用しない。"""
    query_mode = registry["schema"] == QUERY_REGISTRY_SCHEMA
    return {"schema": "dc-local-research-index-v3" if query_mode else "dc-local-research-index-v1",
            **({"registrySchema": QUERY_REGISTRY_SCHEMA} if query_mode else {}),
            "revision": registry["revision"],
            "asOf": registry["asOf"], "researchOnly": True, "publishable": False,
            "installAuthorized": False, "applicability": "NOT_CHECKED",
            "counts": counts(registry),
            **{name: registry[name] for name in ("sources", "products", "records")}}


def collection_schema(registry_schema: str, name: str) -> str:
    """台帳世代と集合documentのURL契約を同じ世代へ結合する。"""
    require(registry_schema in {REGISTRY_SCHEMA, QUERY_REGISTRY_SCHEMA}, "REGISTRY_SCHEMA")
    return f"dc-public-driver-{name}-v{2 if registry_schema == QUERY_REGISTRY_SCHEMA else 1}"


def snapshot_manifest(registry: dict, content: dict[str, bytes], *, payload: bool = False) -> dict:
    """旧生成byteを維持し、新世代には台帳schemaと証拠有無を明示する。"""
    query_mode = registry["schema"] == QUERY_REGISTRY_SCHEMA
    return {"schema": QUERY_SNAPSHOT_SCHEMA if query_mode else (
                "dc-portable-research-snapshot-v2" if payload else "dc-portable-research-snapshot-v1"),
            **({"registrySchema": QUERY_REGISTRY_SCHEMA, "includesPayloadEvidence": payload}
               if query_mode else {}),
            "revision": registry["revision"], "asOf": registry["asOf"],
            "registrySha256": digest(json_bytes(registry)),
            "files": [{"path": name, "bytes": len(raw), "sha256": digest(raw)}
                      for name, raw in sorted(content.items())]}


def manifest_registry_schema(manifest: dict, *, payload: bool = False) -> str:
    """Manifest世代・証拠有無と閉じたfield集合を検証し、台帳schemaを返す。"""
    query_mode = manifest.get("schema") == QUERY_SNAPSHOT_SCHEMA
    expected = {"schema", "revision", "asOf", "registrySha256", "files"}
    fields(manifest, expected | ({"registrySchema", "includesPayloadEvidence"} if query_mode else set()),
           "MANIFEST_FIELDS")
    if query_mode:
        require(manifest["registrySchema"] == QUERY_REGISTRY_SCHEMA and
                type(manifest["includesPayloadEvidence"]) is bool and
                manifest["includesPayloadEvidence"] == payload, "MANIFEST_REGISTRY_BINDING")
        return QUERY_REGISTRY_SCHEMA
    require(manifest["schema"] == ("dc-portable-research-snapshot-v2" if payload else
                                  "dc-portable-research-snapshot-v1"), "MANIFEST_SCHEMA")
    return REGISTRY_SCHEMA


def snapshot_content(registry: dict) -> dict[str, bytes]:
    """入力台帳からmanifestを含む閉じたsnapshotのbyteを生成する。"""
    registry = validate_registry(registry)
    content = {f"{name}.json": json_bytes({"schema": collection_schema(registry["schema"], name),
               "revision": registry["revision"], "asOf": registry["asOf"], "items": registry[name]})
               for name in COLLECTIONS}
    content["index/drivers.json"] = json_bytes(research_index(registry))
    require(all(len(raw) <= MAX_JSON_BYTES for raw in content.values()), "OUTPUT_SIZE")
    content["manifest.json"] = json_bytes(snapshot_manifest(registry, content))
    return content


def check_ancestors(path: Path) -> None:
    """存在する親directoryにreparseがないことを確認する。"""
    for parent in path.absolute().parents:
        if parent.exists():
            regular_path(parent, directory=True)


def write_snapshot(registry: dict, output: Path) -> None:
    """新規出力だけを作成する。途中失敗した出力は自動修復・上書きしない。"""
    content = snapshot_content(registry)
    require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    check_ancestors(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "index").mkdir()
    for name, raw in content.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    verify_snapshot(output)


def tree_files(root: Path) -> set[str]:
    """snapshotの有限の構成を検査し、未知fileやdirectoryを拒否する。"""
    regular_path(root, directory=True)
    found = set()
    for item in root.iterdir():
        if item.name == "index":
            regular_path(item, directory=True)
            for child in item.iterdir():
                regular_path(child)
                found.add("index/" + child.name)
        else:
            regular_path(item)
            found.add(item.name)
    require(found == {*SNAPSHOT_FILES, "manifest.json"}, "SNAPSHOT_FILE_SET")
    return found


def verify_snapshot(root: Path) -> dict:
    """copyされたsnapshotを再構築・再計算し、hashと索引の整合性を確認する。

    ローカルfileを読み、streamは本関数と読取りhelperが閉じる。不整合とI/O失敗は
    伝播し、入力を変更しない。hash整合は署名元の認証や収集・導入・公開許可ではない。
    """
    check_ancestors(root)
    tree_files(root)
    manifest = read_json(root / "manifest.json")
    registry = {"schema": manifest_registry_schema(manifest),
                "revision": manifest["revision"], "asOf": manifest["asOf"]}
    for name in COLLECTIONS:
        document = read_json(root / f"{name}.json")
        fields(document, {"schema", "revision", "asOf", "items"}, "COLLECTION_FIELDS")
        require(document["schema"] == collection_schema(registry["schema"], name) and
                document["revision"] == registry["revision"] and document["asOf"] == registry["asOf"],
                "COLLECTION_BINDING")
        registry[name] = document["items"]
    registry = validate_registry(registry)
    expected = snapshot_content(registry)
    # 全fileを再計算した正規byteと照合し、manifestだけの付替えを合格にしない。
    for name, raw in expected.items():
        path = root / name
        regular_path(path)
        with path.open("rb") as stream:
            actual = stream.read(MAX_JSON_BYTES + 1)
        require(actual == raw, "SNAPSHOT_CONTENT_OR_HASH")
    tree_files(root)
    return registry


def write_zip(root: Path, output: Path) -> None:
    """検証したsnapshotを決定的ZIPへ格納する。既存ZIPを上書きしない。

    archiveは本関数が閉じる。I/O失敗は伝播し、途中まで作成したZIPは残す。
    署名・通信・移設先の保護state初期化や収集開始は行わない。
    """
    registry = verify_snapshot(root)
    require(not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    check_ancestors(output)
    content = snapshot_content(registry)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(content):
            info = zipfile.ZipInfo("collector-data/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content[name])


def main() -> int:
    """通信・署名・実機導入を行わない開発CLIの入口。"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "build"):
        sub = commands.add_parser(command)
        sub.add_argument("registry", type=Path)
        if command == "build":
            sub.add_argument("output", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("snapshot", type=Path)
    package = commands.add_parser("zip")
    package.add_argument("snapshot", type=Path)
    package.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.command in ("validate", "build"):
            check_ancestors(args.registry)
            registry = validate_registry(read_json(args.registry))
            if args.command == "build":
                write_snapshot(registry, args.output)
        else:
            registry = verify_snapshot(args.snapshot)
            if args.command == "zip":
                write_zip(args.snapshot, args.output)
        print(json.dumps({"result": "OK", "counts": counts(registry)}, sort_keys=True))
        return 0
    except (RegistryError, OSError, ValueError, TypeError, KeyError) as error:
        code = str(error) if isinstance(error, RegistryError) else type(error).__name__
        print(json.dumps({"result": "REJECTED", "reason": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
