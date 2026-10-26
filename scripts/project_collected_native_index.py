"""明示collector evidenceを用途別の未署名v2へ投影する（ADR0337／0339／0343／0346）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
研究台帳・実端末inventoryを入力せず、実検査入力時だけ独立attestationを生成する。Grantは生成しない。
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

import collector_registry as cr

PAGE = "https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html"
SOURCE = "INTEL_ETHERNET_WINDOWS11"
MAX_EVIDENCE = 1024 * 1024
MAX_BODY = 512 * 1024
# 配布用の公開pinは用途識別だけであり、署名鍵やgrantを取得しない。
DISTRIBUTION_PUBLIC_FINGERPRINT = "0ac4d0ce9873c82b3c7bb7bd3fb3f5d2a57044bf968c5c6e2af02176cee39d3f"
DISTRIBUTION_KEY_ID = "distribution-index-" + DISTRIBUTION_PUBLIC_FINGERPRINT[:32]
PINNED_STATIC_REVALIDATION_V1 = "PINNED_STATIC_REVALIDATION_V1"
PINNED_STATIC_REVALIDATION_V2 = "PINNED_STATIC_REVALIDATION_V2"
METADATA_BOUND_SCOPE = "dc-metadata-bound-distribution-acquisition-scope-v2"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
TECHNICAL_REVIEW_INPUTS = {"bindingBody", "bindingRelease", "bindingReview", "bindingScript"}
# 新しい配布発行だけへ適用する。旧scope/raw recordの期限を変換しない。
DISTRIBUTION_PROJECTION_POLICY_REVISION = 2
DISTRIBUTION_RECORD_VALIDITY = timedelta(days=8)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def raw_json(path: Path, maximum: int) -> dict:
    """最大maximum byteの非空UTF-8 JSONを読み、streamを閉じて解析結果を返す。

    pathの保護・用途は呼出し側が確認する。容量・JSON拒否とI/O例外は伝播し、
    本関数では署名や取得権限を確定しない。
    """
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum, "INPUT_SIZE")
    return cr.parse_json(raw)


def text(value: object, maximum: int = 512) -> str:
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum and
            not any(ord(character) < 32 for character in value), "PUBLIC_TEXT")
    return value


def known(value: str) -> dict:
    return {"state": "KNOWN", "value": value, "reason": ""}


def unknown(reason: str) -> dict:
    return {"state": "UNKNOWN", "value": "", "reason": reason}


def unknown_hash() -> dict:
    return {"state": "UNKNOWN", "sha256": "", "evidenceUrl": "",
            "evidenceSha256": "", "reason": "payload hash not projected from metadata"}


def digest(value: object) -> str:
    """公表hexの大小文字だけをdigest値へ正規化し、別値や不正入力は許可しない。"""
    require(type(value) is str and re.fullmatch(r"[0-9A-Fa-f]{64}", value) is not None,
            "NATIVE_PUBLIC_DIGEST")
    return value.lower()


def published_digests(release: dict) -> dict[str, str]:
    """v1/v2の掲載算法を全部検査し、一方の不正を他方で救済しない。"""
    schema = release.get("schema")
    require(schema in {"dc-saved-release-analysis-v1", "dc-saved-release-analysis-v2"}, "NATIVE_RELEASE_BINDING")
    require((schema == "dc-saved-release-analysis-v2") == ("publishedSha512" in release), "NATIVE_PUBLIC_DIGEST")
    values = {}
    for algorithm, length in (("sha256", 64), ("sha512", 128)):
        field = "published" + algorithm.capitalize()
        value = release.get(field, "")
        require(type(value) is str and (value == "" or re.fullmatch(r"[0-9A-Fa-f]{%d}" % length, value)),
                "NATIVE_PUBLIC_DIGEST")
        if value:
            values[algorithm] = value.lower()
    require(bool(values) and (schema != "dc-saved-release-analysis-v2" or "sha512" in values), "NATIVE_PUBLIC_DIGEST")
    return values


def release_binding(release: dict) -> dict:
    """保存metadataを期待値として検査し、観測時刻/本文を新HTTP証拠へ読み替えない。"""
    require(type(release) is dict and release.get("source") == SOURCE and
            release.get("distributionPage") == PAGE and release.get("freshNetworkEvidence") is False and
            release.get("acquisitionAuthority") is False, "NATIVE_RELEASE_BINDING")
    hashes = published_digests(release)
    fields = {"schema", "source", "bodySha256", "bodyBytes", "observedUtcSeconds", "distributionPage",
              "freshNetworkEvidence", "acquisitionAuthority", "termsDocumentState", "payloadUrl", "fileName",
              "packageVersion", "publishedSha256", "termsText", "termsTextUtf8Bytes", "termsTextSha256",
              "termsRevision", "htmlExtraction", "parserRevision"}
    cr.fields(release, fields | ({"publishedSha512"} if release["schema"] == "dc-saved-release-analysis-v2" else set()) |
              ({"publishedSizeBytes"} if "publishedSizeBytes" in release else set()), "NATIVE_RELEASE_FIELDS")
    require(type(release["bodyBytes"]) is int and 0 < release["bodyBytes"] <= MAX_BODY and
            type(release["parserRevision"]) is int and release["parserRevision"] > 0 and
            type(release["observedUtcSeconds"]) is str and
            re.fullmatch(r"[1-9][0-9]{0,11}", release["observedUtcSeconds"]) is not None and
            release["termsDocumentState"] == "HTML_EXTRACTED_BINDING_UNCONFIRMED", "NATIVE_RELEASE_BINDING")
    terms = release["termsText"].encode("utf-8", errors="strict")
    require(0 < len(terms) == release["termsTextUtf8Bytes"] and
            hashlib.sha256(terms).hexdigest() == release["termsTextSha256"], "NATIVE_TERMS_DIGEST")
    version = text(release.get("packageVersion"), 128)
    require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,7}", version) is not None, "NATIVE_PACKAGE_METADATA")
    filename = "Wired_driver_" + version + "_x64.zip"
    url = text(release.get("payloadUrl"), 2048)
    parts = urlsplit(url)
    require(release.get("fileName") == filename and parts.scheme == "https" and
            parts.netloc == "downloadmirror.intel.com" and not parts.query and not parts.fragment and
            re.fullmatch(r"/[0-9]+/" + re.escape(filename), parts.path) is not None, "NATIVE_PACKAGE_METADATA")
    exact = release.get("publishedSizeBytes")
    require("publishedSizeBytes" not in release or
            (type(exact) is int and 0 < exact <= MAX_ARCHIVE_BYTES), "NATIVE_PACKAGE_SIZE")
    return {"payloadUrl": url, "fileName": filename, "packageVersion": version,
            "publishedDigests": hashes, "publishedSizeBytes": exact}


def relative_inf(value: object) -> str:
    """操作者が選ぶINFを安全なarchive相対pathへ限定する。"""
    value = text(value, 512)
    require("\\" not in value and not value.startswith("/") and value.lower().endswith(".inf") and
            all(part not in {"", ".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                for part in value.split("/")), "NATIVE_INF_SELECTOR")
    return value


def metadata_acquisition_binding(scope: dict) -> tuple[dict, dict, bytes]:
    """明示scopeの閉集合とexpected原byteを検査し、未取得内容は補完しない。"""
    binding = scope["acquisitionBinding"]
    cr.fields(binding, {"expectedRelease", "selectedInf", "modelSection", "maximumBytes"}, "ACQUISITION_BINDING_FIELDS")
    raw, expected = _revalidation_artifact(binding["expectedRelease"], 65536)
    release_binding(expected)
    relative_inf(binding["selectedInf"])
    section = text(binding["modelSection"], 512)
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", section) is not None and
            ".ntamd64" in section.lower(), "NATIVE_MODEL_SELECTOR")
    maximum = binding["maximumBytes"]
    require(type(maximum) is int and 0 < maximum <= MAX_ARCHIVE_BYTES and
            (expected.get("publishedSizeBytes") is None or expected["publishedSizeBytes"] <= maximum),
            "NATIVE_PACKAGE_SIZE")
    return binding, expected, raw


def bytes_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _project_metadata(scope: dict, evidence: dict, generation: int, now: datetime,
                      *, daily: bool = False) -> tuple[bytes, bytes, bytes, dict]:
    require(type(generation) is int and 0 < generation <= 9007199254740991, "GENERATION")
    require(scope.get("schema") == "dc-fixed-collector-native-index-scope-v1" and
            scope.get("targetCount") == 1 and scope.get("source") == SOURCE and
            scope.get("distributionPage") == PAGE and scope.get("sourceId") == "intel-ethernet-win11" and
            scope.get("recordId") == "intel-wired-31-2-2-win11", "FIXED_SCOPE")
    return _project_metadata_for_scope(scope, evidence, generation, now, daily=daily)


def _project_metadata_for_scope(scope: dict, evidence: dict, generation: int, now: datetime,
                                *, daily: bool = False) -> tuple[bytes, bytes, bytes, dict]:
    """各公開入口が用途別scope/世代を検査した後、共通の原観測を結合する。"""
    if not daily:
        cr.fields(evidence, {"schema", "manifestSha256", "contractSha256", "source", "httpStatus",
                            "lastSuccessfulValidationAt", "bodySha256", "bodyBytesBase64", "records"}, "COLLECTED_FIELDS")
    require(evidence["schema"] == ("dc-collector-daily-receipt-v1" if daily else "dc-collector-evidence-v1") and
            evidence["source"] == SOURCE and type(evidence["httpStatus"]) in {int, float} and
            evidence["httpStatus"] in ({200, 304} if daily else {200}) and
            evidence["manifestSha256"] == scope["collectorManifestSha256"], "COLLECTION_BINDING")
    for field in ("manifestSha256", "contractSha256", "bodySha256"):
        require(type(evidence[field]) is str and re.fullmatch(r"[0-9a-f]{64}", evidence[field]) is not None,
                "COLLECTED_DIGEST")
    require(type(evidence["bodyBytesBase64"]) is str, "BODY_TYPE")
    body = base64.b64decode(evidence["bodyBytesBase64"], validate=True)
    require(0 < len(body) <= MAX_BODY and hashlib.sha256(body).hexdigest() == evidence["bodySha256"], "BODY_DIGEST")
    body.decode("utf-8", errors="strict")
    observed = evidence["lastSuccessfulValidationAt"]
    require(type(observed) in {int, float} and not isinstance(observed, bool) and observed > 0 and
            int(observed) == observed and observed <= int(now.timestamp()), "OBSERVATION_TIME")
    observed_utc = datetime.fromtimestamp(int(observed), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = evidence["records"]
    require(type(rows) is list and len(rows) == 1, "RECORD_COUNT")
    row = cr.fields(rows[0], {"fingerprint", "displayTitle", "driverCategory", "operatingSystem",
                             "packageVersion", "publishedDate"}, "COLLECTED_RECORD_FIELDS")
    require(type(row["fingerprint"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["fingerprint"]) is not None,
            "RECORD_FINGERPRINT")
    # 固定source/page/manifestを検証したnative adapterの正確な射影だけを追加する。
    # 空分類一般や名称から適用性を推測せず、x64分類は固定native契約を根拠とする。
    explicit_classification = (row["operatingSystem"] in {"Windows 11", "Windows 11 64-bit"} and
                               row["driverCategory"] in {"Ethernet", "LAN", "Network"})
    native_classification = (row["operatingSystem"] == "Microsoft Windows 11" and
                             row["driverCategory"] == "" and
                             row["displayTitle"] == "Intel Ethernet Network Adapters")
    require(explicit_classification or native_classification, "COLLECTED_CLASSIFICATION")
    version = text(row["packageVersion"], 128)
    product = text(row["displayTitle"])
    date = row["publishedDate"]
    published_date = unknown("native published date is not an ISO calendar literal")
    if type(date) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date):
        datetime.strptime(date, "%Y-%m-%d")
        published_date = known(date)
    descriptor = {"schema": "driver-index-acquisition-v1", "state": "UNKNOWN",
                  "reason": "collection metadata does not issue acquisition attestation",
                  "payloadUrl": "", "fileName": "", "format": "UNKNOWN", "expectedContentType": "",
                  "maximumBytes": 0, "route": [],
                  "terms": {"state": "UNKNOWN", "reason": "terms document not projected", "evidenceUrl": "",
                            "evidenceSha256": "", "revisionKind": "NONE", "revision": "", "textDocument": None},
                  "prerequisites": {"state": "UNKNOWN", "reason": "conditions not projected", "items": []},
                  "publisher": unknown("payload signature not inspected"), "attestation": None}
    record = {"schema": "driver-index-record-v2", "sourceId": scope["sourceId"], "recordId": scope["recordId"],
              "product": product, "targetOs": known("WINDOWS_11"), "architecture": known("X64"),
              "driverKind": known("NORMAL_DRIVER"), "version": known(version), "publishedDate": published_date,
              "acquisition": known("STANDARD_INF_ARCHIVE"),
              "packageEvidence": {"publishedHash": unknown_hash(), "calculatedHash": unknown_hash(),
                                  "size": {"state": "UNKNOWN", "valueBytes": 0, "reason": "payload not acquired"}},
              "lastSuccessfulObservationUtc": known(observed_utc), "inspectionStage": "METADATA_ONLY",
              "publishedIdentityEvidence": {"state": "UNKNOWN", "kind": "UNKNOWN", "pnpIds": [],
                                            "classGuid": "", "nestedArchiveIdentity": "", "infIdentity": "", "modelSection": "",
                                            "evidenceUrl": "", "evidenceSha256": "",
                                            "reason": "public INF/CAT identity not acquired or inspected"},
              "acquisitionDescriptor": descriptor}
    raw_record = bytes_json(record)
    source = {"sourceId": scope["sourceId"], "officialOrigin": "https://www.intel.com/", "distributionPage": PAGE,
              "officialEvidence": {"state": "PUBLISHED", "kind": "OFFICIAL_PAGE", "evidenceUrl": PAGE,
                                   "evidenceSha256": evidence["bodySha256"], "reason": ""}}
    index = {"schema": "driver-index-records-v2", "assetGeneration": generation, "sources": [source],
             "records": [{"recordBytesBase64": base64.b64encode(raw_record).decode("ascii"),
                          "recordSha256": hashlib.sha256(raw_record).hexdigest()}]}
    raw_index = bytes_json(index)
    packed = gzip.compress(raw_index, mtime=0)
    digest = hashlib.sha256(packed).hexdigest()
    manifest = {"schema": "driver-index-manifest-v1", "repository": "EnterOgawa/drivercrate", "channel": "driver-index",
                "keyId": scope["keyId"], "generation": generation, "assetGeneration": generation,
                "publishedAtUtc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiresAtUtc": ((datetime.fromtimestamp(int(observed), timezone.utc) if daily else now) +
                                 timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "asset": {"tag": f"index-v1-{now:%Y%m%d}-{digest}", "name": "index.json.gz", "compression": "gzip",
                          "sizeBytes": len(packed), "sha256": digest},
                "quality": {"sourceCount": 1, "recordCount": 1, "metadataOnlyCount": 1,
                            "contentInspectedCount": 0, "unconfirmedCount": 0}}
    report = {"realCollectedTargets": 1, "realMetadataRecords": 1, "realContentInspected": 0, "realPayloads": 0,
              "actualDeviceCandidates": None, "publishedIdentityKnown": 0, "acquisitionAttestations": 0,
              "bodySha256": evidence["bodySha256"], "bodyBytes": len(body), "observationUtc": observed_utc,
              "nativeFingerprint": row["fingerprint"], "recordSha256": hashlib.sha256(raw_record).hexdigest(),
              "assetSha256": digest, "generation": generation, "projection": "confirmed-observation republication",
              "realInstall": 0, "publication": 0}
    return raw_index, packed, b"\n" + bytes_json(manifest), report


def project(scope: dict, evidence: dict, generation: int, now: datetime) -> tuple[bytes, bytes, bytes, dict]:
    """受入専用1..3の従来契約を維持する。日次運用世代とは分離する。"""
    require(type(generation) is int and 0 < generation <= 3, "GENERATION")
    return _project_metadata(scope, evidence, generation, now)


def _validated_daily_generation(receipt: dict, now: datetime) -> int:
    """原日次receiptの全field・時刻・body投影結合を検査し、申告世代だけを返す。

    入力は変更せず、200/304の変換や予約発行を行わない。既存の日次検査順を保つ。
    """
    cr.fields(receipt, {"schema", "outcome", "generation", "previousReceiptSha256", "manifestSha256",
                       "contractSha256", "day", "source", "httpStatus", "lastFetchedAt",
                       "lastSuccessfulValidationAt", "lastAttemptAt", "notBefore", "requestBindingSha256",
                       "bodySha256", "projectionSha256", "bodyBytesBase64", "projectionBytesBase64",
                       "records", "error", "stateError"}, "DAILY_RECEIPT_FIELDS")
    require(receipt["schema"] == "dc-collector-daily-receipt-v1" and receipt["source"] == SOURCE,
            "DAILY_RECEIPT_BINDING")
    require((receipt["outcome"], receipt["httpStatus"]) in
            {("NEW_200", 200), ("REVALIDATED_304", 304)} and
            type(receipt["httpStatus"]) in {int, float} and
            type(receipt["error"]) in {int, float} and receipt["error"] == 0 and
            type(receipt["stateError"]) in {int, float} and receipt["stateError"] == 0,
            "DAILY_NOT_A_NEW_OBSERVATION")
    generation = receipt["generation"]
    require(type(generation) in {int, float} and 4 <= generation <= 9007199254740991 and
            int(generation) == generation, "DAILY_GENERATION")
    previous = receipt["previousReceiptSha256"]
    require((generation == 4 and previous == "") or
            (generation > 4 and type(previous) is str and re.fullmatch(r"[0-9a-f]{64}", previous) is not None),
            "DAILY_PREVIOUS_RECEIPT")
    for field in ("lastFetchedAt", "lastSuccessfulValidationAt", "lastAttemptAt", "notBefore"):
        value = receipt[field]
        require(type(value) in {int, float} and 0 < value <= 253402300799 and int(value) == value,
                "DAILY_TIME")
    fetched, validated, attempted = (receipt[field] for field in
                                    ("lastFetchedAt", "lastSuccessfulValidationAt", "lastAttemptAt"))
    require(attempted <= validated <= int(now.timestamp()) < validated + 86400 and fetched <= validated and
            receipt["notBefore"] == validated + 86400, "DAILY_OBSERVATION_TIME")
    require((receipt["httpStatus"] == 200 and fetched == validated) or
            (receipt["httpStatus"] == 304 and fetched < attempted), "DAILY_FETCH_TIME")
    require(type(receipt["day"]) is str and re.fullmatch(r"[0-9]{8}", receipt["day"]) is not None,
            "DAILY_DAY")
    datetime.strptime(receipt["day"], "%Y%m%d")
    for field in ("requestBindingSha256", "projectionSha256"):
        require(digest(receipt[field]) == receipt[field], "DAILY_DIGEST")
    require(type(receipt["projectionBytesBase64"]) is str, "DAILY_PROJECTION_TYPE")
    raw_projection = base64.b64decode(receipt["projectionBytesBase64"], validate=True)
    require(0 < len(raw_projection) <= MAX_BODY and
            hashlib.sha256(raw_projection).hexdigest() == receipt["projectionSha256"], "DAILY_PROJECTION_DIGEST")
    projected = cr.parse_json(raw_projection)
    cr.fields(projected, {"requestBindingSha256", "bodySha256", "lastFetchedAt", "records"}, "DAILY_PROJECTION_FIELDS")
    require(all(projected[field] == receipt[field] for field in projected), "DAILY_PROJECTION_BINDING")
    return int(generation)


def project_daily(scope: dict, receipt: dict, now: datetime) -> tuple[bytes, bytes, bytes, dict]:
    """元200と今回実304を区別し、保護storeが予約した運用世代だけを投影する。"""
    generation = _validated_daily_generation(receipt, now)
    result = _project_metadata(scope, receipt, generation, now, daily=True)
    result[3].update(observationKind=receipt["outcome"], httpStatus=receipt["httpStatus"],
                     originalFetchedAt=receipt["lastFetchedAt"],
                     previousReceiptSha256=receipt["previousReceiptSha256"],
                     newHttp200Count=int(receipt["httpStatus"] == 200),
                     revalidatedHttp304Count=int(receipt["httpStatus"] == 304),
                     projection="daily metadata observation; acquisition remains unknown")
    return result


class TermsDom(HTMLParser):
    """原pageの実要素だけを読む監視側の有限確認。Scriptを実行しない。

    elementsはtextarea開始tag自身を含み、その内容中の疑似tagを除く開始tagと属性mapを
    RAM内に保持し、規約bindingの一意照合に使う。textareaは開始tagの記録後に抑止へ移り、
    終了tagで解除する状態flagである。raw_documentsはlicenseModal内のcontent-rawだけを
    保持し、補助textareaの内容を許諾documentへ混ぜない。
    """

    def __init__(self, body: str):
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.textarea = False
        self.capture_raw_document = False
        self.license_divs: list[bool] = []
        self.raw_documents: list[str] = []
        self.feed(body)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.textarea:
            return
        names = [name for name, _ in attrs]
        require(len(names) == len(set(names)), "DOM_DUPLICATE_ATTRIBUTE")
        attributes = {name: value or "" for name, value in attrs}
        self.elements.append((tag, attributes))
        if tag == "div":
            self.license_divs.append(attributes.get("id") == "licenseModal" or
                                     bool(self.license_divs and self.license_divs[-1]))
        if tag == "textarea":
            self.textarea = True
            self.capture_raw_document = (attributes.get("id") == "content-raw" and
                                         bool(self.license_divs and self.license_divs[-1]))
            if self.capture_raw_document:
                self.raw_documents.append("")

    def handle_endtag(self, tag: str) -> None:
        if self.textarea:
            if tag == "textarea":
                self.textarea = False
                self.capture_raw_document = False
            return
        if tag == "div" and self.license_divs:
            self.license_divs.pop()

    def handle_data(self, data: str) -> None:
        """raw許諾documentをRAM内へ保持し、旧新同値だけを確認する。"""
        if self.capture_raw_document:
            self.raw_documents[-1] += data


def confirm_terms_review(body: bytes, release: dict, review: dict, script: dict,
                         now: datetime) -> dict:
    """手動非実行レビューを実原script/hash/DOMへ結合し、numeric gateの意味を推測しない。"""
    require(review.get("schema") == "dc-static-terms-binding-review-v1" and
            review.get("reviewMethod") == "MANUAL_NONEXECUTED_STATIC_LINK_REVIEW" and
            review.get("source") == SOURCE and review.get("pageSha256") == release["bodySha256"] and
            review.get("payloadUrl") == release["payloadUrl"] and
            review.get("termsRevision") == release["termsRevision"] and
            review.get("numericModalMappingClaimed") is False, "TERMS_REVIEW_BINDING")
    require(script.get("schema") == "dc-collected-terms-script-v1" and script.get("source") == SOURCE and
            script.get("pageUrl") == PAGE and script.get("pageSha256") == release["bodySha256"] and
            script.get("pageObservedUtcSeconds") == release["observedUtcSeconds"] and
            script.get("httpStatus") == 200 and script.get("scriptExecuted") is False and
            script.get("scriptFreshNetworkEvidence") is True and script.get("pageFreshNetworkEvidence") is False and
            script.get("payloadGet") == 0, "TERMS_SCRIPT_RECEIPT")
    raw_script = base64.b64decode(script["scriptBytesBase64"], validate=True)
    require(0 < len(raw_script) <= 65536 and len(raw_script) == script["scriptSizeBytes"] and
            hashlib.sha256(raw_script).hexdigest() == script["scriptSha256"] == review.get("scriptSha256") and
            script["scriptUrl"] == review.get("scriptUrl") and
            script["scriptUrl"].startswith("https://www.intel.com/") and
            "?" not in script["scriptUrl"] and "#" not in script["scriptUrl"], "TERMS_SCRIPT_DIGEST")
    source = raw_script.decode("utf-8", errors="strict")
    observed = int(script["scriptObservedUtcSeconds"])
    reviewed = review["checkedAtUtcSeconds"]
    require(type(reviewed) is int and 0 < int(release["observedUtcSeconds"]) <= observed <= reviewed <= int(now.timestamp()),
            "TERMS_REVIEW_TIME")
    roles = {"DOWNLOAD_CLASS_HANDLER", "DATASET_PAYLOAD_TO_BOUND_LINK", "NONEMPTY_RAW_TO_DIALOG",
             "RAW_DOCUMENT_PRESENTATION", "EXACT_CONTAINER_ACCEPT", "ACCEPT_BOUND_LINK"}
    witnesses = review.get("scriptWitnesses")
    require(type(witnesses) is list and len(witnesses) == len(roles) and
            {row.get("role") for row in witnesses} == roles, "TERMS_WITNESS_ROLES")
    for row in witnesses:
        cr.fields(row, {"role", "literal"}, "TERMS_WITNESS_FIELDS")
        literal = text(row["literal"], 512)
        require(source.count(literal) == 1, "TERMS_WITNESS_EXACT")
    # 意味確認は手動レビューの責任であり、一致件数だけをJavaScript実行証明へ変換しない。
    dom = TermsDom(body.decode("utf-8", errors="strict"))
    def unique(tag: str, key: str, value: str) -> dict[str, str]:
        rows = [attrs for kind, attrs in dom.elements if kind == tag and attrs.get(key) == value]
        require(len(rows) == 1, "TERMS_DOM_UNIQUE")
        return rows[0]
    trigger = unique("button", "data-modal-id", "1")
    require(trigger.get("data-href") == release["payloadUrl"] and
            "available-download-button__cta" in trigger.get("class", "").split(), "TERMS_DOM_TRIGGER")
    unique("div", "id", "licenseModal")
    raw = unique("textarea", "id", "content-raw")
    require("license-modal-content_body_license-text-raw" in raw.get("class", "").split(), "TERMS_DOM_RAW")
    require(len(dom.raw_documents) == 1, "TERMS_DOM_RAW")
    for token in ("license-modal__dialog", "license-modal-big-bag-container",
                  "license-modal-content-license__btn--btn-accept",
                  "license-modal-content-footer-download__restart-link"):
        require(sum(token in attrs.get("class", "").split() for _, attrs in dom.elements) == 1,
                "TERMS_DOM_HANDLER_TARGET")
    html = dict(release["htmlExtraction"])
    html["bindingEvidenceUrl"] = script["scriptUrl"]
    html["bindingEvidenceSha256"] = script["scriptSha256"]
    return html


def _revalidation_artifact(value: dict, maximum: int) -> tuple[bytes, dict]:
    """厳密な原byte wrapperを検査し、自己pinを由来や権限へ昇格しない。"""
    require(type(value) is dict, "TERMS_REVALIDATION_TYPE")
    cr.fields(value, {"bytesBase64", "sha256"}, "TERMS_REVALIDATION_FIELDS")
    require(type(value["bytesBase64"]) is str and type(value["sha256"]) is str and
            re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None,
            "TERMS_REVALIDATION_TYPE")
    require(len(value["bytesBase64"]) <= ((maximum + 2) // 3) * 4, "TERMS_REVALIDATION_SIZE")
    raw = base64.b64decode(value["bytesBase64"], validate=True)
    require(0 < len(raw) <= maximum and hashlib.sha256(raw).hexdigest() == value["sha256"],
            "TERMS_REVALIDATION_PIN")
    parsed = cr.parse_json(raw)
    require(type(parsed) is dict, "TERMS_REVALIDATION_TYPE")
    return raw, parsed


def confirm_pinned_static_terms_revalidation(body: bytes, release: dict, review: dict,
                                            script: dict, now: datetime) -> dict:
    """旧manual原byte/時刻と新機械再確認を別に保ち、同一templateだけを受理する。"""
    require(type(review) is dict, "TERMS_REVALIDATION_TYPE")
    cr.fields(review, {"schema", "reviewMethod", "originalRelease", "originalReview", "originalScript",
                       "freshRelease", "freshScript", "originalManualCheckedAtUtcSeconds",
                       "revalidatedCheckedAtUtcSeconds"}, "TERMS_REVALIDATION_FIELDS")
    require(len(bytes_json(review)) <= MAX_EVIDENCE, "TERMS_REVALIDATION_SIZE")
    require(review["schema"] == "dc-static-terms-binding-review-v2" and
            review["reviewMethod"] == PINNED_STATIC_REVALIDATION_V1, "TERMS_REVIEW_MODE")
    _, old_release = _revalidation_artifact(review["originalRelease"], MAX_EVIDENCE)
    _, old_review = _revalidation_artifact(review["originalReview"], 65536)
    _, old_script = _revalidation_artifact(review["originalScript"], MAX_EVIDENCE)
    _, fresh_release = _revalidation_artifact(review["freshRelease"], MAX_EVIDENCE)
    _, fresh_script = _revalidation_artifact(review["freshScript"], MAX_EVIDENCE)
    require(fresh_release == release and fresh_script == script, "TERMS_REVALIDATION_PIN")
    release_fields = {"schema", "source", "bodySha256", "bodyBytes", "observedUtcSeconds",
                      "distributionPage", "freshNetworkEvidence", "acquisitionAuthority",
                      "termsDocumentState", "payloadUrl", "fileName", "packageVersion", "publishedSha256",
                      "termsText", "termsTextUtf8Bytes", "termsTextSha256", "termsRevision", "htmlExtraction",
                      "parserRevision"}
    for document in (release, old_release):
        cr.fields(document, release_fields, "TERMS_REVALIDATION_FIELDS")
        require(all(type(document[key]) is int and document[key] > 0 for key in
                    ("bodyBytes", "termsTextUtf8Bytes", "parserRevision")) and
                document["freshNetworkEvidence"] is False and document["acquisitionAuthority"] is False,
                "TERMS_REVALIDATION_TYPE")
        extraction = document["htmlExtraction"]
        cr.fields(extraction, {"profile", "selector", "containerSelector", "linkSelector", "payloadAttribute",
                               "documentSha256", "documentSizeBytes", "textSha256", "textSizeBytes",
                               "bindingEvidenceUrl", "bindingEvidenceSha256"}, "TERMS_REVALIDATION_FIELDS")
        require(extraction["profile"] == "TEXTAREA_HTML_DOCUMENT_V1" and
                extraction["payloadAttribute"] == "data-href" and
                extraction["bindingEvidenceUrl"] == extraction["bindingEvidenceSha256"] == "",
                "TERMS_REVIEW_BINDING")
        for key, expected in (("selector", {"tag": "textarea", "attribute": "id", "value": "content-raw"}),
                              ("containerSelector", {"tag": "div", "attribute": "id", "value": "licenseModal"}),
                              ("linkSelector", {"tag": "button", "attribute": "data-modal-id", "value": "1"})):
            require(extraction[key] == expected, "TERMS_REVIEW_BINDING")
        require(type(extraction["documentSizeBytes"]) is int and 0 < extraction["documentSizeBytes"] <= 262144 and
                type(extraction["textSizeBytes"]) is int and extraction["textSizeBytes"] > 0,
                "TERMS_REVALIDATION_TYPE")
    manual_fields = {"schema", "reviewMethod", "source", "pageSha256", "payloadUrl", "termsRevision",
                     "numericModalMappingClaimed", "scriptSha256", "scriptUrl", "checkedAtUtcSeconds",
                     "scriptWitnesses"}
    optional_manual = {"scriptExecuted": False, "meaning": None, "reviewOfFreshScriptBytes": True,
                       "pageFreshNetworkEvidence": False, "actualDeviceChecked": False,
                       "termsConsent": False, "payloadGet": 0, "realInstall": 0}
    require(manual_fields <= set(old_review) <= manual_fields | set(optional_manual),
            "TERMS_REVALIDATION_FIELDS")
    for key, expected in optional_manual.items():
        if key in old_review:
            require((type(old_review[key]) is str and 0 < len(old_review[key]) <= 4096) if key == "meaning"
                    else type(old_review[key]) is type(expected) and old_review[key] == expected,
                    "TERMS_REVALIDATION_TYPE")
    require(hashlib.sha256(body).hexdigest() == old_release["bodySha256"],
            "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    # 原manualの時刻と原script/releaseをそのまま旧検査へ渡す。機械処理をmanualと偽らない。
    html = confirm_terms_review(body, old_release, old_review, old_script, now)
    require(type(review["originalManualCheckedAtUtcSeconds"]) is int and
            review["originalManualCheckedAtUtcSeconds"] == old_review["checkedAtUtcSeconds"],
            "TERMS_REVIEW_TIME")
    checked = review["revalidatedCheckedAtUtcSeconds"]
    require(type(checked) is int and checked > 0, "TERMS_REVALIDATION_TYPE")
    # 原releaseの全fieldを維持し、今回の解析時刻以外の差を意味同等と推測しない。
    require(set(release) == set(old_release) and all(release[key] == old_release[key]
            for key in old_release if key != "observedUtcSeconds"),
            "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    script_fields = {"schema", "source", "pageUrl", "pageSha256", "pageObservedUtcSeconds",
                     "scriptUrl", "scriptSha256", "scriptSizeBytes", "scriptBytesBase64",
                     "scriptObservedUtcSeconds", "httpStatus", "pageFreshNetworkEvidence",
                     "scriptFreshNetworkEvidence", "scriptExecuted", "payloadGet"}
    cr.fields(script, script_fields, "TERMS_REVALIDATION_FIELDS")
    cr.fields(old_script, script_fields, "TERMS_REVALIDATION_FIELDS")
    require(all(script[key] == old_script[key] for key in script_fields -
                {"pageObservedUtcSeconds", "scriptObservedUtcSeconds"}),
            "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    require(script["pageObservedUtcSeconds"] == release["observedUtcSeconds"] and
            type(script["httpStatus"]) is int and type(script["payloadGet"]) is int and
            type(script["scriptSizeBytes"]) is int and
            script["scriptExecuted"] is False and script["pageFreshNetworkEvidence"] is False and
            script["scriptFreshNetworkEvidence"] is True, "TERMS_SCRIPT_RECEIPT")
    for value in (release["observedUtcSeconds"], script["scriptObservedUtcSeconds"]):
        require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,11}", value) is not None,
                "TERMS_REVALIDATION_TYPE")
    observed = int(release["observedUtcSeconds"])
    fresh_observed = int(script["scriptObservedUtcSeconds"])
    require(0 < observed <= fresh_observed <= checked <= int(now.timestamp()) < observed + 86400,
            "TERMS_REVIEW_TIME")
    require(0 < len(body) <= 256 * 1024, "DAILY_PREPARATION_BODY_SIZE")
    # 旧検査で確かめた同一body/同一scriptのDOMと六witnessをそのまま利用する。
    return html


def make_pinned_static_terms_revalidation(body: bytes, originals: dict[str, bytes], original_pins: dict[str, str],
                                         release_raw: bytes, script_raw: bytes,
                                         checked_at: int, now: datetime, *,
                                         mode: str = PINNED_STATIC_REVALIDATION_V1) -> bytes:
    """明示承認pinの原三文書と新native二文書を別の機械receiptへ結合する。"""
    require(type(originals) is dict and type(original_pins) is dict, "TERMS_REVALIDATION_TYPE")
    require(mode in {PINNED_STATIC_REVALIDATION_V1, PINNED_STATIC_REVALIDATION_V2}, "TERMS_REVIEW_MODE")
    technical = bool(set(originals) & TECHNICAL_REVIEW_INPUTS)
    require(not technical or mode == PINNED_STATIC_REVALIDATION_V2, "TERMS_REVIEW_MODE")
    cr.fields(originals, {"release", "review", "script"} | ({"body"} if mode == PINNED_STATIC_REVALIDATION_V2 else set()) |
              (TECHNICAL_REVIEW_INPUTS if technical else set()), "TERMS_REVALIDATION_FIELDS")
    cr.fields(original_pins, set(originals), "TERMS_REVALIDATION_FIELDS")
    def artifact(raw: bytes, maximum: int) -> dict:
        """原byteを変更せず、有限wrapperへ保存する。"""
        require(type(raw) is bytes and 0 < len(raw) <= maximum, "TERMS_REVALIDATION_SIZE")
        return {"bytesBase64": base64.b64encode(raw).decode("ascii"), "sha256": hashlib.sha256(raw).hexdigest()}
    for key, raw in originals.items():
        require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == original_pins[key],
                "TERMS_REVALIDATION_PIN")
    result = {"schema": "dc-static-terms-binding-review-v2", "reviewMethod": PINNED_STATIC_REVALIDATION_V1,
              "originalRelease": artifact(originals["release"], MAX_EVIDENCE),
              "originalReview": artifact(originals["review"], 65536),
              "originalScript": artifact(originals["script"], MAX_EVIDENCE),
              "freshRelease": artifact(release_raw, MAX_EVIDENCE),
              "freshScript": artifact(script_raw, MAX_EVIDENCE),
              "originalManualCheckedAtUtcSeconds": cr.parse_json(originals["review"])["checkedAtUtcSeconds"],
              "revalidatedCheckedAtUtcSeconds": checked_at}
    if mode == PINNED_STATIC_REVALIDATION_V2:
        result.update(schema="dc-static-terms-binding-review-v3", reviewMethod=mode,
                      originalBody=artifact(originals["body"], MAX_BODY))
        if technical:
            result.update({name: artifact(originals[name], 65536 if name == "bindingReview" else MAX_EVIDENCE)
                           for name in TECHNICAL_REVIEW_INPUTS})
    release, script = cr.parse_json(release_raw), cr.parse_json(script_raw)
    (confirm_metadata_bound_terms_revalidation if mode == PINNED_STATIC_REVALIDATION_V2 else
     confirm_pinned_static_terms_revalidation)(body, release, result, script, now)
    return bytes_json(result)


def confirm_metadata_bound_terms_revalidation(body: bytes, release: dict, review: dict,
                                              script: dict, now: datetime) -> dict:
    """原manualを原bodyで検査し、同一許諾/scriptの新payload bindingだけを再確認する。"""
    technical = bool(set(review) & TECHNICAL_REVIEW_INPUTS)
    cr.fields(review, {"schema", "reviewMethod", "originalRelease", "originalReview", "originalScript",
                       "originalBody", "freshRelease", "freshScript", "originalManualCheckedAtUtcSeconds",
                       "revalidatedCheckedAtUtcSeconds"} | (TECHNICAL_REVIEW_INPUTS if technical else set()), "TERMS_REVALIDATION_FIELDS")
    require(review["schema"] == "dc-static-terms-binding-review-v3" and
            review["reviewMethod"] == PINNED_STATIC_REVALIDATION_V2 and
            len(bytes_json(review)) <= MAX_EVIDENCE, "TERMS_REVIEW_MODE")
    _, old_release = _revalidation_artifact(review["originalRelease"], MAX_EVIDENCE)
    _, old_review = _revalidation_artifact(review["originalReview"], 65536)
    _, old_script = _revalidation_artifact(review["originalScript"], MAX_EVIDENCE)
    _, fresh_release = _revalidation_artifact(review["freshRelease"], MAX_EVIDENCE)
    _, fresh_script = _revalidation_artifact(review["freshScript"], MAX_EVIDENCE)
    artifact = review["originalBody"]
    cr.fields(artifact, {"bytesBase64", "sha256"}, "TERMS_REVALIDATION_FIELDS")
    require(type(artifact["bytesBase64"]) is str and len(artifact["bytesBase64"]) <= ((MAX_BODY+2)//3)*4,
            "TERMS_REVALIDATION_SIZE")
    old_body = base64.b64decode(artifact["bytesBase64"], validate=True)
    require(0 < len(old_body) <= MAX_BODY and hashlib.sha256(old_body).hexdigest() ==
            artifact["sha256"] == old_release["bodySha256"], "TERMS_REVALIDATION_PIN")
    require(fresh_release == release and fresh_script == script, "TERMS_REVALIDATION_PIN")
    release_binding(old_release)
    release_binding(release)
    confirm_terms_review(old_body, old_release, old_review, old_script, now)
    original_checked = old_review["checkedAtUtcSeconds"]
    if technical:
        _, binding_release = _revalidation_artifact(review["bindingRelease"], MAX_EVIDENCE)
        _, binding_review = _revalidation_artifact(review["bindingReview"], 65536)
        _, binding_script = _revalidation_artifact(review["bindingScript"], MAX_EVIDENCE)
        body_artifact = review["bindingBody"]
        cr.fields(body_artifact, {"bytesBase64", "sha256"}, "TERMS_REVALIDATION_FIELDS")
        require(type(body_artifact["bytesBase64"]) is str and len(body_artifact["bytesBase64"]) <= ((MAX_BODY+2)//3)*4,
                "TERMS_REVALIDATION_SIZE")
        binding_body = base64.b64decode(body_artifact["bytesBase64"], validate=True)
        require(0 < len(binding_body) <= MAX_BODY and hashlib.sha256(binding_body).hexdigest() ==
                body_artifact["sha256"] == binding_release["bodySha256"] and len(binding_body) == binding_release["bodyBytes"],
                "TERMS_REVALIDATION_PIN")
        release_binding(binding_release)
        require(all(binding_release[key] == old_release[key] for key in
                    ("termsText", "termsTextUtf8Bytes", "termsTextSha256", "termsRevision")),
                "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
        confirm_terms_review(binding_body, binding_release, binding_review, binding_script, now)
        # 新scriptの手動技術reviewは外部pinから選ぶ。旧同意・旧manual原byteを上書きしない。
        old_body, old_release, old_review, old_script = binding_body, binding_release, binding_review, binding_script
    require(hashlib.sha256(body).hexdigest() == release["bodySha256"] and len(body) == release["bodyBytes"],
            "NATIVE_RELEASE_BINDING")
    # 許諾全文とselector/DOM契約を維持し、版/URL/本文hashだけを旧版へ固定しない。
    terms_fields = ("termsText", "termsTextUtf8Bytes", "termsTextSha256", "termsRevision")
    require(all(release[key] == old_release[key] for key in terms_fields), "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    old_dom = TermsDom(old_body.decode("utf-8", errors="strict"))
    new_dom = TermsDom(body.decode("utf-8", errors="strict"))
    require(len(old_dom.raw_documents) == len(new_dom.raw_documents) == 1 and
            old_dom.raw_documents == new_dom.raw_documents, "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    extraction = release["htmlExtraction"]
    old_extraction = old_release["htmlExtraction"]
    require(extraction == old_extraction, "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    require(set(script) == set(old_script) and all(script[key] == old_script[key] for key in old_script
            if key not in {"pageSha256", "pageObservedUtcSeconds", "scriptObservedUtcSeconds"}),
            "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    checked = review["revalidatedCheckedAtUtcSeconds"]
    require(type(checked) is int and type(review["originalManualCheckedAtUtcSeconds"]) is int and
            review["originalManualCheckedAtUtcSeconds"] == original_checked, "TERMS_REVIEW_TIME")
    for value in (release["observedUtcSeconds"], script["scriptObservedUtcSeconds"]):
        require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,11}", value), "TERMS_REVALIDATION_TYPE")
    observed = int(release["observedUtcSeconds"])
    require(0 < original_checked <= old_review["checkedAtUtcSeconds"] <= checked and
            0 < observed <= int(script["scriptObservedUtcSeconds"]) <=
            checked <= int(now.timestamp()) < observed + 86400, "TERMS_REVIEW_TIME")
    # 原manualの六witnessを借りる一時照合view。保存された原manualと原時刻は変更しない。
    bound_review = dict(old_review, pageSha256=release["bodySha256"], payloadUrl=release["payloadUrl"],
                        checkedAtUtcSeconds=checked)
    return confirm_terms_review(body, release, bound_review, script, now)


def project_acquisition(scope: dict, evidence: dict, release: dict, inspection: dict,
                        review: dict, script: dict, generation: int,
                        now: datetime) -> tuple[bytes, bytes, bytes, dict]:
    """既存原観測と一INFの実内容receiptを共通KNOWN v2へ投影する。Grantを発行しない。"""
    require(type(generation) is int and 4 <= generation <= 8, "ACQUISITION_GENERATION")
    return _project_acquisition_from_metadata(project(scope, evidence, 1, now), evidence,
                                              release, inspection, review, script, generation, now)


def _project_acquisition_from_metadata(metadata: tuple[bytes, bytes, bytes, dict], evidence: dict,
                                       release: dict, inspection: dict, review: dict, script: dict,
                                       generation: int, now: datetime, *,
                                       terms_review_mode: str | None = None,
                                       validity: timedelta = timedelta(days=1),
                                       acquisition_binding: dict | None = None) -> tuple[bytes, bytes, bytes, dict]:
    """元page/実内容/terms/script/個別期限を同じ検査順で一INFへ結合する。"""
    raw_index, _, raw_manifest, base_report = metadata
    index = cr.parse_json(raw_index)
    manifest = cr.parse_json(raw_manifest)
    record = cr.parse_json(base64.b64decode(index["records"][0]["recordBytesBase64"], validate=True))
    body = base64.b64decode(evidence["bodyBytesBase64"], validate=True)
    require(release.get("schema") in {"dc-saved-release-analysis-v1", "dc-saved-release-analysis-v2"} and release.get("source") == SOURCE and
            release.get("bodySha256") == evidence["bodySha256"] and release.get("bodyBytes") == len(body) and
            release.get("observedUtcSeconds") == str(int(evidence["lastSuccessfulValidationAt"])) and
            release.get("distributionPage") == PAGE and release.get("freshNetworkEvidence") is False and
            release.get("acquisitionAuthority") is False and
            release.get("termsDocumentState") == "HTML_EXTRACTED_BINDING_UNCONFIRMED", "NATIVE_RELEASE_BINDING")
    if acquisition_binding is None:
        require(release.get("payloadUrl") == "https://downloadmirror.intel.com/923981/Wired_driver_31.2.2_x64.zip" and
                release.get("fileName") == "Wired_driver_31.2.2_x64.zip" and release.get("packageVersion") == "31.2.2" and
                digest(release.get("publishedSha256")) == "2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5", "FIXED_PACKAGE")
    else:
        _, expected = _revalidation_artifact(acquisition_binding["expectedRelease"], 65536)
        require(release_binding(release) == release_binding(expected) and all(release[key] == expected[key]
                for key in ("termsText", "termsTextUtf8Bytes", "termsTextSha256", "termsRevision")),
                "NATIVE_EXPECTED_RELEASE_BINDING")
    terms = release["termsText"].encode("utf-8", errors="strict")
    require(len(terms) == release["termsTextUtf8Bytes"] and
            hashlib.sha256(terms).hexdigest() == release["termsTextSha256"] and
            release["htmlExtraction"]["textSha256"] == release["termsTextSha256"] and
            release["htmlExtraction"]["textSizeBytes"] == len(terms), "NATIVE_TERMS_DIGEST")
    require(terms_review_mode in {None, PINNED_STATIC_REVALIDATION_V1, PINNED_STATIC_REVALIDATION_V2}, "TERMS_REVIEW_MODE")
    require(acquisition_binding is None or terms_review_mode == PINNED_STATIC_REVALIDATION_V2, "TERMS_REVIEW_MODE")
    html = (confirm_terms_review(body, release, review, script, now) if terms_review_mode is None else
            confirm_metadata_bound_terms_revalidation(body, release, review, script, now)
            if terms_review_mode == PINNED_STATIC_REVALIDATION_V2 else
            confirm_pinned_static_terms_revalidation(body, release, review, script, now))
    selected_inf = "PRO2500/Winx64/W11/e2fn.inf" if acquisition_binding is None else acquisition_binding["selectedInf"]
    selected_section = "Intel.NTamd64.10.0.1..22000" if acquisition_binding is None else acquisition_binding["modelSection"]
    if acquisition_binding is None:
        require(inspection.get("archiveSha256") == digest(release["publishedSha256"]) and
                inspection.get("archiveBytes") == 40477087, "NATIVE_PACKAGE_BINDING")
    else:
        hashes = published_digests(release)
        size = inspection.get("archiveBytes")
        require(inspection.get("schema") == "dc-inspected-public-identities-v3" and
                type(size) is int and 0 < size <= acquisition_binding["maximumBytes"] and
                (release.get("publishedSizeBytes") is None or size == release["publishedSizeBytes"]) and
                re.fullmatch(r"[0-9a-f]{64}", inspection.get("archiveSha256", "")) is not None and
                re.fullmatch(r"[0-9a-f]{128}", inspection.get("archiveSha512", "")) is not None and
                all(inspection["archive"+algorithm.capitalize()] == value for algorithm, value in hashes.items()),
                "NATIVE_PACKAGE_BINDING")
    require(inspection.get("schema") in {"dc-inspected-public-identities-v2", "dc-inspected-public-identities-v3"} and
            type(inspection.get("inspectionError")) is int and inspection.get("inspectionError") == 0 and
            inspection.get("officialAuthority") is False and inspection.get("actualApplicabilityChecked") is False and
            inspection.get("selectedOnly") is True and inspection.get("selectedInf") == selected_inf.replace("/", "\\") and
            type(inspection.get("verifiedIdentityInfs")) is int and
            inspection.get("verifiedIdentityInfs") == 1 and len(inspection.get("infs", [])) == 1, "NATIVE_PACKAGE_BINDING")
    inf = inspection["infs"][0]
    require(all(type(inf.get(field)) is int for field in ("state", "contentError", "identityError")) and
            inf.get("state") == 2 and inf.get("contentError") == 0 and inf.get("identityError") == 0 and
            inf.get("publishedIdentityKnown") is True and inf.get("infIdentity") == selected_inf,
            "NATIVE_INF_BINDING")
    if acquisition_binding is None:
        require(inf.get("infSha256") == "a93fa3c2b8725aed2081e0d239766474fac205f75ddbe16849502af6acba2417" and
                inf.get("driverVersion") == "2.1.5.7" and len(inf.get("models", [])) == 2, "NATIVE_INF_BINDING")
    else:
        require(re.fullmatch(r"[0-9a-f]{64}", inf.get("infSha256", "")) is not None and
                re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,7}", inf.get("driverVersion", "")) is not None and
                inf.get("classGuid", "").lower() == "{4d36e972-e325-11ce-bfc1-08002be10318}" and
                type(inf.get("models")) is list and 0 < len(inf["models"]) <= 256, "NATIVE_INF_BINDING")
    publisher = text(inf.get("verifiedPublisher"))
    models = [row for row in inf["models"] if row.get("modelSection") == selected_section]
    require(len(models) == 1, "NATIVE_MODEL_SECTION")
    model = models[0]
    require(model.get("modelSection") == selected_section and
            type(model.get("pnpIds")) is list and 0 < len(model["pnpIds"]) <= 128, "NATIVE_MODEL_SECTION")
    ids = []
    seen = set()
    for item in model["pnpIds"]:
        cr.fields(item, {"kind", "value"}, "NATIVE_ID_FIELDS")
        require(item["kind"] in {"HARDWARE", "COMPATIBLE"}, "NATIVE_ID_KIND")
        text(item["value"], 512)
        identity = (item["kind"], item["value"])
        if identity not in seen:
            seen.add(identity)
            ids.append(dict(item))
    observed = int(evidence["lastSuccessfulValidationAt"])
    content_checked = int(inspection["contentCheckedUtcSeconds"])
    review_checked = review["checkedAtUtcSeconds"] if terms_review_mode is None else review["revalidatedCheckedAtUtcSeconds"]
    checked = max(content_checked, review_checked)
    require(observed <= content_checked <= checked <= int(now.timestamp()), "NATIVE_CONTENT_TIME")
    observed_at = datetime.fromtimestamp(observed, timezone.utc)
    # 発行fresh窓24hは配布recordの8日と独立に保つ。古い六入力を再発行しない。
    require(now < observed_at + timedelta(days=1) and
            datetime.fromtimestamp(checked, timezone.utc) < observed_at + timedelta(days=1), "EVIDENCE_EXPIRED")
    expiry = observed_at + validity
    iso = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
    record["version"] = known(inf["driverVersion"])
    record["publishedDate"] = known(datetime.strptime(inf["driverDate"], "%m/%d/%Y").strftime("%Y-%m-%d"))
    def hash_evidence(digest: str, url: str, source_digest: str) -> dict:
        return {"state": "KNOWN", "sha256": digest, "evidenceUrl": url,
                "evidenceSha256": source_digest, "reason": ""}
    payload = release["payloadUrl"]
    body_hash = evidence["bodySha256"]
    record["packageEvidence"] = {
        "publishedHash": (hash_evidence(digest(release["publishedSha256"]), PAGE, body_hash)
                          if release.get("publishedSha256") else
                          dict(unknown_hash(), reason="published SHA-512 verified by collector; SHA-256 not published")),
        "calculatedHash": hash_evidence(inspection["archiveSha256"], payload, inspection["archiveSha256"]),
        "size": {"state": "KNOWN", "valueBytes": inspection["archiveBytes"], "reason": ""}}
    record["inspectionStage"] = "CONTENT_INSPECTED"
    record["publishedIdentityEvidence"] = {"state": "PUBLISHED", "kind": "INF", "pnpIds": ids,
        "classGuid": inf["classGuid"], "nestedArchiveIdentity": "", "infIdentity": inf["infIdentity"], "modelSection": model["modelSection"],
        "evidenceUrl": payload, "evidenceSha256": inf["infSha256"], "reason": ""}
    record["acquisitionDescriptor"] = {"schema": "driver-index-acquisition-v1", "state": "KNOWN", "reason": "",
        "payloadUrl": payload, "fileName": release["fileName"], "format": "ZIP", "expectedContentType": "application/zip",
        "maximumBytes": 128 * 1024 * 1024 if acquisition_binding is None else acquisition_binding["maximumBytes"],
        "route": [{"url": payload, "kind": "OFFICIAL_CDN_LINK", "evidenceUrl": PAGE, "evidenceSha256": body_hash}],
        "terms": {"state": "ACCEPTANCE_REQUIRED", "reason": "", "evidenceUrl": PAGE, "evidenceSha256": body_hash,
                  "revisionKind": "VENDOR_LITERAL", "revision": release["termsRevision"],
                  "textDocument": {"url": PAGE, "sha256": body_hash, "sizeBytes": len(body),
                                   "contentType": "text/html; charset=utf-8", "htmlExtraction": html}},
        "prerequisites": {"state": "KNOWN", "reason": "", "items": []}, "publisher": known(publisher),
        "attestation": {"kind": "COLLECTOR_VERIFIED_OFFICIAL_ROUTE", "policyRevision": 1,
                        "checkedAtUtc": iso(datetime.fromtimestamp(checked, timezone.utc)), "validUntilUtc": iso(expiry),
                        "authorityMethod": "OFFICIAL_SITE_CONTROL_AND_LINK", "authorityEvidenceUrl": PAGE,
                        "authorityEvidenceSha256": body_hash}}
    raw_record = bytes_json(record)
    index["assetGeneration"] = generation
    index["records"] = [{"recordBytesBase64": base64.b64encode(raw_record).decode("ascii"),
                         "recordSha256": hashlib.sha256(raw_record).hexdigest()}]
    raw_index = bytes_json(index)
    packed = gzip.compress(raw_index, mtime=0)
    asset_hash = hashlib.sha256(packed).hexdigest()
    manifest.update(generation=generation, assetGeneration=generation, expiresAtUtc=iso(expiry))
    manifest["asset"] = {"tag": f"index-v1-{now:%Y%m%d}-{asset_hash}", "name": "index.json.gz", "compression": "gzip",
                         "sizeBytes": len(packed), "sha256": asset_hash}
    manifest["quality"] = {"sourceCount": 1, "recordCount": 1, "metadataOnlyCount": 0,
                           "contentInspectedCount": 1, "unconfirmedCount": 0}
    report = dict(base_report, projection="saved-observation selected-INF acquisition projection",
                  generation=generation, realContentInspected=1, publishedIdentityKnown=1,
                  acquisitionAttestations=1, publishedIds=len(ids), unprojectedModelSections=len(inf["models"])-1,
                  actualDeviceCandidates=None, realPayloads=0, scriptExecuted=0, termsConsent=False,
                  packageVersion=release["packageVersion"], driverVersion=inf["driverVersion"],
                  recordSha256=hashlib.sha256(raw_record).hexdigest(), assetSha256=asset_hash)
    return raw_index, packed, b"\n" + bytes_json(manifest), report


def _validate_distribution_scope(scope: dict) -> None:
    """配布専用scopeの全fieldと完全公開pinを検査し、用途の相互代用を拒否する。"""
    fields = {"schema", "targetCount", "source", "distributionPage", "sourceId", "recordId",
              "collectorManifestSha256", "keyId", "publicFingerprint", "projectionPolicyRevision"}
    require(type(scope) is dict, "DISTRIBUTION_SCOPE_TYPE")
    metadata_bound = scope.get("schema") == METADATA_BOUND_SCOPE
    if metadata_bound:
        fields.add("acquisitionBinding")
    cr.fields(scope, fields, "DISTRIBUTION_SCOPE_FIELDS")
    string_fields = fields - {"targetCount", "projectionPolicyRevision", "acquisitionBinding"}
    require(all(type(scope[field]) is str for field in string_fields) and
            type(scope["targetCount"]) is int and scope["targetCount"] == 1 and
            type(scope["projectionPolicyRevision"]) is int and
            scope["projectionPolicyRevision"] == DISTRIBUTION_PROJECTION_POLICY_REVISION, "DISTRIBUTION_SCOPE_TYPE")
    require(scope["schema"] in {"dc-fixed-distribution-acquisition-scope-v1", METADATA_BOUND_SCOPE} and
            scope["source"] == SOURCE and scope["distributionPage"] == PAGE and
            scope["sourceId"] == "intel-ethernet-win11" and
            (bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", scope["recordId"])) if metadata_bound else
             scope["recordId"] == "intel-wired-31-2-2-win11") and
            re.fullmatch(r"[0-9a-f]{64}", scope["collectorManifestSha256"]) is not None,
            "DISTRIBUTION_SCOPE_BINDING")
    require(scope["publicFingerprint"] == DISTRIBUTION_PUBLIC_FINGERPRINT and
            scope["keyId"] == DISTRIBUTION_KEY_ID, "DISTRIBUTION_PUBLIC_PIN")
    if metadata_bound:
        metadata_acquisition_binding(scope)


def project_distribution_acquisition(scope: dict, evidence: dict, release: dict, inspection: dict,
                                     review: dict, script: dict, generation: int,
                                     now: datetime, *, terms_review_mode: str | None = None) -> tuple[bytes, bytes, bytes, dict]:
    """厳密な配布scopeと原検査束を未署名v2へ投影する。予約/署名/取得権限は発行しない。

    scopeの公開pinは用途識別だけとする。原観測/内容/規約の共通検査後に一選択INFを
    出力し、失敗は例外として伝播する。入力を変更せず、通信・file I/Oも行わない。
    """
    _validate_distribution_scope(scope)
    require(type(generation) is int and 1 <= generation <= 9007199254740991,
            "DISTRIBUTION_GENERATION")
    require(isinstance(now, datetime) and now.tzinfo is not None and
            now.utcoffset() == timedelta(0) and now.microsecond == 0, "DISTRIBUTION_UTC_SECONDS")
    # 旧scopeのschemaを書換えず、専用scope全検査後に共通の原観測/実内容検査へ進む。
    metadata = _project_metadata_for_scope(scope, evidence, generation, now)
    require(evidence["records"][0]["packageVersion"] == release.get("packageVersion"),
            "DISTRIBUTION_PACKAGE_VERSION")
    result = _project_acquisition_from_metadata(
        metadata, evidence,
        release, inspection, review, script, generation, now, validity=DISTRIBUTION_RECORD_VALIDITY,
        terms_review_mode=terms_review_mode, acquisition_binding=scope.get("acquisitionBinding"))
    result[3].update(projection="distribution selected-INF acquisition projection",
                     projectionPolicyRevision=DISTRIBUTION_PROJECTION_POLICY_REVISION,
                     publicFingerprint=DISTRIBUTION_PUBLIC_FINGERPRINT,
                     unsigned=True, authorityIssued=False)
    return result


def project_daily_distribution_acquisition(scope: dict, receipt: dict, release: dict, inspection: dict,
                                           review: dict, script: dict,
                                           now: datetime, *, terms_review_mode: str | None = None) -> tuple[bytes, bytes, bytes, dict]:
    """厳密日次200/304と原内容検査を未署名取得索引へ結合する（ADR0364）。

    scope/receipt/検査文書は呼出し中だけ借用し、schema・時刻・body・世代を変更しない。
    世代は原receiptから導出する。304を新200へ数えず、古い検査時刻の自動更新もしない。
    検査失敗は原例外を伝播する。I/O・予約・署名・公式authority・取得/導入grantは発行しない。
    """
    _validate_distribution_scope(scope)
    require(isinstance(now, datetime) and now.tzinfo is not None and
            now.utcoffset() == timedelta(0) and now.microsecond == 0, "DISTRIBUTION_UTC_SECONDS")
    generation = _validated_daily_generation(receipt, now)
    metadata = _project_metadata_for_scope(scope, receipt, generation, now, daily=True)
    require(receipt["records"][0]["packageVersion"] == release.get("packageVersion"),
            "DISTRIBUTION_PACKAGE_VERSION")
    result = _project_acquisition_from_metadata(
        metadata, receipt, release, inspection, review, script, generation, now,
        terms_review_mode=terms_review_mode, validity=DISTRIBUTION_RECORD_VALIDITY,
        acquisition_binding=scope.get("acquisitionBinding"))
    result[3].update(projection="daily distribution selected-INF acquisition projection",
                     projectionPolicyRevision=DISTRIBUTION_PROJECTION_POLICY_REVISION,
                     publicFingerprint=DISTRIBUTION_PUBLIC_FINGERPRINT,
                     unsigned=True, authorityIssued=False,
                     observationKind=receipt["outcome"], httpStatus=receipt["httpStatus"],
                     originalFetchedAt=receipt["lastFetchedAt"],
                     previousReceiptSha256=receipt["previousReceiptSha256"],
                     newHttp200Count=int(receipt["httpStatus"] == 200),
                     revalidatedHttp304Count=int(receipt["httpStatus"] == 304))
    if terms_review_mode in {PINNED_STATIC_REVALIDATION_V1, PINNED_STATIC_REVALIDATION_V2}:
        result[3].update(termsReviewMode=terms_review_mode,
                         originalManualCheckedAtUtcSeconds=review["originalManualCheckedAtUtcSeconds"],
                         revalidatedCheckedAtUtcSeconds=review["revalidatedCheckedAtUtcSeconds"])
    return result


def main() -> int:
    """明示したローカル証拠を投影し、未署名索引・manifest・報告の四fileを新規保存する。

    日次modeはmetadata専用とする。署名・公開・収集・取得grant発行は行わない。
    既存出力は拒否する。各streamは本入口で閉じ、書込み途中の失敗は伝播して
    先に作成した出力を残すため、四file全体の原子的commitは保証しない。
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--generation", type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--daily", action="store_true", help="保護store予約世代の日次receiptをmetadata-onlyへ投影")
    mode.add_argument("--distribution-acquisition", action="store_true",
                      help="厳密な配布scope/原検査束を未署名の一INF索引へ投影")
    parser.add_argument("--output-prefix", type=Path, required=True)
    parser.add_argument("--parsed-release", type=Path)
    parser.add_argument("--inspected-package", type=Path)
    parser.add_argument("--terms-review", type=Path)
    parser.add_argument("--terms-script", type=Path)
    args = parser.parse_args()
    acquisition = (args.parsed_release, args.inspected_package, args.terms_review, args.terms_script)
    if args.distribution_acquisition:
        require(all(acquisition) and args.generation is not None, "DISTRIBUTION_ACQUISITION_INPUT_SET")
    scope = raw_json(args.scope, 65536)
    evidence = raw_json(args.evidence, MAX_EVIDENCE)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    require(not any(acquisition) or all(acquisition), "ACQUISITION_INPUT_SET")
    if args.daily:
        require(not any(acquisition) and args.generation is None, "DAILY_METADATA_ONLY")
        raw_index, packed, manifest, report = project_daily(scope, evidence, now)
    elif args.distribution_acquisition:
        raw_index, packed, manifest, report = project_distribution_acquisition(scope, evidence,
            raw_json(args.parsed_release, MAX_EVIDENCE), raw_json(args.inspected_package, MAX_EVIDENCE),
            raw_json(args.terms_review, 65536), raw_json(args.terms_script, MAX_EVIDENCE), args.generation, now)
    elif all(acquisition):
        raw_index, packed, manifest, report = project_acquisition(scope, evidence,
            raw_json(args.parsed_release, MAX_EVIDENCE), raw_json(args.inspected_package, MAX_EVIDENCE),
            raw_json(args.terms_review, 65536), raw_json(args.terms_script, MAX_EVIDENCE), args.generation, now)
    else:
        raw_index, packed, manifest, report = project(scope, evidence, args.generation, now)
    outputs = [(".index.json", raw_index), (".index.json.gz", packed), (".manifest.raw.json", manifest),
               (".projection.json", bytes_json(report))]
    require(all(not Path(str(args.output_prefix)+suffix).exists() for suffix, _ in outputs), "OUTPUT_EXISTS")
    for suffix, raw in outputs:
        with Path(str(args.output_prefix)+suffix).open("xb") as stream:
            stream.write(raw)
            stream.flush()
    print(json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
