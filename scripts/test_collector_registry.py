"""共通調査台帳・可搬snapshotの非通信回帰試験。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
全fileは試験専用temporary directoryに作り、native storeや端末構成を変更しない。
"""

import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote, urlsplit

import collector_registry as cr
import project_legacy_collector_registry as legacy


def fixture() -> dict:
    """架空の公開製品と公式page根拠を持つ最小台帳を返す。"""
    return {
        "schema": cr.REGISTRY_SCHEMA, "revision": "test-01", "asOf": "2026-10-03T00:00:00Z",
        "sources": [{"id": "source-one", "manufacturer": "Example", "officialPage":
                     "https://vendor.example.org/drivers", "collectionMethod": "MANUAL_RESEARCH"}],
        "products": [{"id": "product-one", "manufacturer": "Example", "model": "Device One",
                      "driverCategory": "LAN", "sourceIds": ["source-one"], "recordIds": ["record-one"],
                      "researchState": "METADATA_SAVED", "reason": "NONE"}],
        "records": [{"id": "record-one", "sourceId": "source-one", "title": "Network driver",
                     "driverCategory": "LAN", "operatingSystems": ["WINDOWS_11_X64"],
                     "packageVersion": "1.0", "driverVersion": None, "publishedDate": None,
                     "downloadUrl": "https://cdn.example.org/driver.zip", "linkState": "HEAD_OK",
                     "publishedSha256": None, "contentState": "NOT_DOWNLOADED"}],
        "observations": [{"id": "page-one", "productId": "product-one", "recordId": "record-one",
                          "checkedAt": "2026-10-02T00:00:00Z", "kind": "OFFICIAL_LINK",
                          "method": "WEB_REVIEW", "evidenceUrl": "https://vendor.example.org/drivers",
                          "httpStatus": None, "evidenceSha256": None},
                         {"id": "head-one", "productId": "product-one", "recordId": "record-one",
                          "checkedAt": "2026-10-02T00:00:00Z", "kind": "HEAD", "method": "LOCAL_HTTP",
                          "evidenceUrl": "https://cdn.example.org/driver.zip", "httpStatus": 200,
                          "evidenceSha256": None}],
    }


class RegistryTests(unittest.TestCase):
    """schema・参照・数え方と研究用権限境界を検査する。"""

    def test_valid_and_safety_flags(self):
        """HEAD成功だけでは本文取得・適合・導入を許可しない。"""
        value = cr.validate_registry(fixture())
        index = cr.research_index(value)
        self.assertTrue(index["researchOnly"])
        self.assertFalse(index["publishable"])
        self.assertFalse(index["installAuthorized"])
        self.assertEqual(index["counts"]["payloadsDownloaded"], 0)
        self.assertEqual(index["counts"]["productsWithOfficialLinks"], 1)
        self.assertIsNone(index["counts"]["uniquePayloads"])

    def test_unknown_fields_and_schemas(self):
        """各集合と最上位の未知fieldを拒否する。"""
        for name in (None, *cr.COLLECTIONS):
            with self.subTest(collection=name):
                value = fixture()
                (value if name is None else value[name][0])["extra"] = "unused"
                with self.assertRaises(cr.RegistryError):
                    cr.validate_registry(value)
        value = fixture()
        value["schema"] = "future-schema"
        with self.assertRaises(cr.RegistryError):
            cr.validate_registry(value)

    def test_duplicate_keys_and_non_json_constants(self):
        """JSON同名keyとNaN等を拒否する。"""
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xef\xbb\xbf{}'):
            with self.subTest(raw=raw), self.assertRaises(cr.RegistryError):
                cr.parse_json(raw)

    def test_duplicate_id_in_every_collection(self):
        """同名IDを上書きやdedupで隠さない。"""
        for name in cr.COLLECTIONS:
            value = fixture()
            value[name].append(copy.deepcopy(value[name][0]))
            with self.subTest(collection=name), self.assertRaises(cr.RegistryError):
                cr.validate_registry(value)

    def test_duplicate_product_and_reference(self):
        """別IDでの同じ製品と、同じrecord参照の重複を拒否する。"""
        value = fixture()
        second = copy.deepcopy(value["products"][0])
        second["id"] = "other-product"
        value["products"].append(second)
        with self.assertRaisesRegex(cr.RegistryError, "DUPLICATE_PRODUCT"):
            cr.validate_registry(value)
        value = fixture()
        value["products"][0]["recordIds"].append("record-one")
        with self.assertRaisesRegex(cr.RegistryError, "DUPLICATE_REFERENCE"):
            cr.validate_registry(value)

    def test_missing_and_wrong_bindings(self):
        """存在しないsource、record、製品と別page根拠を拒否する。"""
        changes = [("products", "sourceIds", ["absent"]), ("products", "recordIds", ["absent"]),
                   ("records", "sourceId", "absent"), ("observations", "productId", "absent"),
                   ("observations", "recordId", "absent"),
                   ("observations", "evidenceUrl", "https://other.example.org/drivers")]
        for name, field, replacement in changes:
            value = fixture()
            value[name][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(cr.RegistryError):
                cr.validate_registry(value)

    def test_private_text_in_public_labels(self):
        """端末内path、生端末ID、SID、代表的credential形式を拒否する。"""
        for label in ("C:/private/item", r"USB\REDACTED", "S-1-5-21-123", "password=secret",
                      "ghp_examplefixture", "github_pat_examplefixture", "Device\nOne"):
            value = fixture()
            value["products"][0]["model"] = label
            with self.subTest(label=label), self.assertRaises(cr.RegistryError):
                cr.validate_registry(value)

    def test_unsafe_urls(self):
        """私的宛先・期限付き認証・query・fragmentと二重escapeを拒否する。"""
        for url in ("http://vendor.example.org/file", "https://user:secret@vendor.example.org/file",
                    "https://vendor.example.org/file?token=secret", "https://vendor.example.org/file#auth",
                    "https://127.0.0.1/file", "https://[::1]/file", "https://server.local/file",
                    "https://localhost/file", "https://localhost.example/file",
                    "https://vendor.example.org:444/file", "https://vendor.example.org/%250a",
                    "https://vendor.example.org/%5cprivate", "https://vendor.example.org/file?"):
            with self.subTest(url=url), self.assertRaises(cr.RegistryError):
                cr.public_url(url)
        self.assertEqual(cr.public_url("https://vendor.example.org/driver.zip"),
                         "https://vendor.example.org/driver.zip")

    def test_head_metadata_and_link_evidence_cannot_be_faked_by_flag(self):
        """対応する観測のない成功flagを拒否する。"""
        for remove in ("head-one", "page-one"):
            value = fixture()
            value["observations"] = [item for item in value["observations"] if item["id"] != remove]
            with self.subTest(remove=remove), self.assertRaises(cr.RegistryError):
                cr.validate_registry(value)
        value = fixture()
        value["observations"][1]["httpStatus"] = 404
        with self.assertRaises(cr.RegistryError):
            cr.validate_registry(value)

    def test_future_time_and_bad_date(self):
        """snapshot時点より後の観測と不正日付を拒否する。"""
        value = fixture()
        value["observations"][0]["checkedAt"] = "2026-10-04T00:00:00Z"
        with self.assertRaises(cr.RegistryError):
            cr.validate_registry(value)
        value = fixture()
        value["records"][0]["publishedDate"] = "2026-02-30"
        with self.assertRaises(cr.RegistryError):
            cr.validate_registry(value)

    def test_no_content_or_os_or_firmware_shortcut(self):
        """未取得の検査済みclaim・他architecture・firmware分類を拒否する。"""
        for field, replacement in (("contentState", "VERIFIED"), ("operatingSystems", ["WINDOWS_11_ARM64"]),
                                   ("publishedSha256", "unverified"), ("driverCategory", "FIRMWARE")):
            value = fixture()
            value["records"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(cr.RegistryError):
                cr.validate_registry(value)

    def test_shared_record_without_total_product_cap(self):
        """多数の製品が同じrecordを共有しても、packageを水増ししない。"""
        value = fixture()
        for position in range(1, 501):
            product = copy.deepcopy(value["products"][0])
            product["id"] = f"product-{position:04}"
            product["model"] = f"Device {position:04}"
            value["products"].append(product)
            observed = copy.deepcopy(value["observations"][0])
            observed["id"] = f"page-{position:04}"
            observed["productId"] = product["id"]
            value["observations"].append(observed)
        report = cr.counts(cr.validate_registry(value))
        self.assertEqual(report["targetProducts"], 501)
        self.assertEqual(report["distributionRecords"], 1)
        self.assertEqual(report["recordsWithOfficialLinks"], 1)

    def test_unordered_data_is_deterministic(self):
        """集合の順序を変えても同じsnapshot byteを生成する。"""
        value = fixture()
        reordered = copy.deepcopy(value)
        reordered["observations"].reverse()
        self.assertEqual(cr.snapshot_content(value), cr.snapshot_content(reordered))

    def test_page_only_stays_in_denominator(self):
        """配布表未解析の製品を分母から落とさない。"""
        value = fixture()
        value["records"] = []
        value["products"][0].update(recordIds=[], researchState="PAGE_ONLY",
                                     reason="DOWNLOAD_TABLE_UNAVAILABLE")
        value["observations"] = [value["observations"][0]]
        value["observations"][0].update(recordId=None, kind="OFFICIAL_PAGE")
        report = cr.counts(cr.validate_registry(value))
        self.assertEqual(report["targetProducts"], 1)
        self.assertEqual(report["productsWithMetadata"], 0)


class SnapshotTests(unittest.TestCase):
    """実temporary fileでcopy・再読込みと破損拒否を検査する。"""

    def setUp(self):
        """各試験に独立した所有temporary directoryを用意する。"""
        self.temp = tempfile.TemporaryDirectory(prefix="dc-registry-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "collector-data"
        cr.write_snapshot(fixture(), self.snapshot)

    def test_copy_and_rebuild(self):
        """別pathから再読込みし、同じhash・件数・観測で再生成する。"""
        copied = self.root / "other-account-path"
        shutil.copytree(self.snapshot, copied)
        registry = cr.verify_snapshot(copied)
        rebuilt = self.root / "rebuilt"
        cr.write_snapshot(registry, rebuilt)
        self.assertEqual(cr.snapshot_content(registry),
                         {name: (rebuilt / name).read_bytes() for name in cr.tree_files(rebuilt)})

    def test_no_overwrite(self):
        """生成済みsnapshotとZIPの内容を保持する。"""
        original = (self.snapshot / "manifest.json").read_bytes()
        with self.assertRaises(cr.RegistryError):
            cr.write_snapshot(fixture(), self.snapshot)
        self.assertEqual((self.snapshot / "manifest.json").read_bytes(), original)
        archive = self.root / "data.zip"
        cr.write_zip(self.snapshot, archive)
        with self.assertRaises(cr.RegistryError):
            cr.write_zip(self.snapshot, archive)

    def test_zip_determinism_and_content(self):
        """ZIPを二回生成し、同じbyteと相対file一覧を確認する。"""
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        cr.write_zip(self.snapshot, first)
        cr.write_zip(self.snapshot, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with cr.zipfile.ZipFile(first) as archive:
            self.assertEqual(set(archive.namelist()),
                             {"collector-data/" + name for name in cr.tree_files(self.snapshot)})
            for name in archive.namelist():
                self.assertEqual(archive.read(name), (self.snapshot / name.removeprefix("collector-data/")).read_bytes())

    def test_extra_file(self):
        """driver本体や余分なfileが混入したsnapshotを拒否する。"""
        (self.snapshot / "driver.exe").write_bytes(b"fixture")
        with self.assertRaises(cr.RegistryError):
            cr.verify_snapshot(self.snapshot)

    def test_missing_file(self):
        """必要fileの欠損を理由付きで拒否する。"""
        (self.snapshot / "records.json").unlink()
        with self.assertRaises(cr.RegistryError):
            cr.verify_snapshot(self.snapshot)

    def test_hash_damage(self):
        """生成索引の改ざんを受理しない。"""
        index_path = self.snapshot / "index/drivers.json"
        index = cr.read_json(index_path)
        index["counts"]["payloadsDownloaded"] = 1
        index_path.write_bytes(cr.json_bytes(index))
        with self.assertRaises(cr.RegistryError):
            cr.verify_snapshot(self.snapshot)

    def test_manifest_rehash_does_not_authorize_fake_count(self):
        """改ざん後にhashを付替えても索引を再計算して拒否する。"""
        path = self.snapshot / "index/drivers.json"
        index = cr.read_json(path)
        index["counts"]["targetProducts"] = 999
        raw = cr.json_bytes(index)
        path.write_bytes(raw)
        manifest_path = self.snapshot / "manifest.json"
        manifest = cr.read_json(manifest_path)
        for row in manifest["files"]:
            if row["path"] == "index/drivers.json":
                row.update(bytes=len(raw), sha256=cr.digest(raw))
        manifest_path.write_bytes(cr.json_bytes(manifest))
        with self.assertRaises(cr.RegistryError):
            cr.verify_snapshot(self.snapshot)

    def test_unknown_collection_schema(self):
        """構成fileだけのschema付替えを拒否する。"""
        path = self.snapshot / "records.json"
        value = cr.read_json(path)
        value["schema"] = "future"
        path.write_bytes(cr.json_bytes(value))
        with self.assertRaises(cr.RegistryError):
            cr.verify_snapshot(self.snapshot)

    def test_reparse_attribute_rejection(self):
        """Windows reparse属性の検査分岐を模擬して拒否を確認する。"""
        real_stat = self.snapshot.lstat()
        class ReparseStat:
            st_mode = real_stat.st_mode
            st_file_attributes = cr.stat.FILE_ATTRIBUTE_REPARSE_POINT
        with patch.object(Path, "lstat", return_value=ReparseStat()):
            with self.assertRaisesRegex(cr.RegistryError, "REPARSE_PATH"):
                cr.regular_path(self.snapshot, directory=True)



# 設計時54caseの値をそのまま固定する。旧work fixtureを変更・実行時参照しない。
RESPONSE_HEADER_QUERY_CASES = (
    ("saved-korg-literal", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, True),
    ("two-key-reverse-order", "https://cdn.example.test/files/package.exe?response-content-type=application%2Foctet-stream%3B&response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver_1.2%2528Win%252010%2529.ZIP", "PAYLOAD", True, True),
    ("no-trailing-mime-semicolon", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver-v2.cab&response-content-type=application%2Foctet-stream", "PAYLOAD", True, True),
    ("encoded-ascii-filename", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27%2544river.msi&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, True),
    ("mixed-hex-and-multidot", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3bfilename%2A%3DUTF-8%27%27Driver_1.2%2528x64%2529.7z&response-content-type=application%2Foctet-stream%3b", "PAYLOAD", True, True),
    ("rar-suffix", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.rar&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, True),
    ("safe-space", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%2520x64.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, True),
    ("old-numeric-payload", "https://cdn.example.test/files/package.exe?file=7", "PAYLOAD", True, True),
    ("old-numeric-page", "https://cdn.example.test/files/package.exe?id=7", "PAGE", True, True),
    ("old-basename", "https://cdn.example.test/files/package.exe?fileName=CH341SER.ZIP", "PAYLOAD", True, True),
    ("queryless", "https://cdn.example.test/files/package.exe", "PAGE", False, True),
    ("page-denied", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAGE", True, False),
    ("default-query-denied", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", False, False),
    ("extra-expiry", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B&Expires=1791660000", "PAYLOAD", True, False),
    ("extra-signature", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B&X-Amz-Signature=deadbeef", "PAYLOAD", True, False),
    ("extra-token", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B&token=fixture", "PAYLOAD", True, False),
    ("duplicate-key", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("single-key", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe", "PAYLOAD", True, False),
    ("unknown-key", "https://cdn.example.test/files/package.exe?response-content-encoding=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("encoded-key", "https://cdn.example.test/files/package.exe?%72esponse-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("empty-value", "https://cdn.example.test/files/package.exe?response-content-disposition=&response-content-type=application%2Foctet-stream", "PAYLOAD", True, False),
    ("raw-plus", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver+.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("encoded-plus-inner", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%252Bx64.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("raw-header-punctuation", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment;filename*=UTF-8''Driver.exe&response-content-type=application%2Foctet-stream", "PAYLOAD", True, False),
    ("invalid-percent", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%GG.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("crlf", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%250D%250A.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("nul", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%2500.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("del", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%257F.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("slash", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27dir%252FDriver.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("backslash", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27dir%255CDriver.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("traversal", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27..%252FDriver.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("dot-dot", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver..exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("nested-encoding", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%252528x64%252529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("extra-disposition-parameter", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe%3Bfilename%3DOther.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("legacy-filename", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%3DDriver.exe&response-content-type=application%2Foctet-stream", "PAYLOAD", True, False),
    ("language-nonempty", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27en%27Driver.exe&response-content-type=application%2Foctet-stream", "PAYLOAD", True, False),
    ("charset-nonutf8", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DISO-8859-1%27%27Driver.exe&response-content-type=application%2Foctet-stream", "PAYLOAD", True, False),
    ("inline-disposition", "https://cdn.example.test/files/package.exe?response-content-disposition=inline%3Bfilename%2A%3DUTF-8%27%27Driver.exe&response-content-type=application%2Foctet-stream", "PAYLOAD", True, False),
    ("mime-parameter", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe&response-content-type=application%2Foctet-stream%3Bcharset%3DUTF-8", "PAYLOAD", True, False),
    ("mime-extra-semicolon", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe&response-content-type=application%2Foctet-stream%3B%3B", "PAYLOAD", True, False),
    ("mime-unknown", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.exe&response-content-type=application%2Fx-msdownload", "PAYLOAD", True, False),
    ("unicode-filename", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%25E3%2581%2582.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("unknown-suffix", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver.html&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("unbalanced-parentheses", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%2528x64.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("nested-parentheses", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27Driver%2528%2528x64%2529%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("reserved-basename", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27CON.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("filename-too-long", "https://cdn.example.test/files/package.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("fragment", "https://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B#a", "PAYLOAD", True, False),
    ("user-info", "https://user@cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("ip-literal", "https://127.0.0.1/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("http", "http://cdn.korg.com/us/support/download/files/e7a98917678435e0ab2ebe1357aa8b58.exe?response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27DrvTools%2528115_r51e%2529.exe&response-content-type=application%2Foctet-stream%3B", "PAYLOAD", True, False),
    ("old-numeric-page-file-denied", "https://cdn.example.test/files/package.exe?file=7", "PAGE", True, False),
    ("old-basename-page-denied", "https://cdn.example.test/files/package.exe?fileName=CH341SER.ZIP", "PAGE", True, False),
    ("url-overlimit", "https://cdn.example.test/files/package.exe?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "PAYLOAD", True, False),
)
RESPONSE_HEADER_URL = RESPONSE_HEADER_QUERY_CASES[0][1]


def response_header_url(filename: str) -> str:
    """架空basenameを二層でencodeした試験専用URLを返す。"""
    return ("https://cdn.example.org/files/package?" +
            "response-content-disposition=" + quote("attachment;filename*=UTF-8''" +
                quote(filename, safe=""), safe="") +
            "&response-content-type=application%2Foctet-stream%3B")


class ResponseHeaderQueryTests(unittest.TestCase):
    """ADR 0327の保存構文と旧API・研究属性の境界を決定的に検査する。"""

    def test_original_design_cases(self):
        """原54case（正例11／拒否43）をproduction保存判定で再現する。"""
        self.assertEqual(len(RESPONSE_HEADER_QUERY_CASES), 54)
        self.assertEqual(sum(row[4] for row in RESPONSE_HEADER_QUERY_CASES), 11)
        for name, url, purpose, mode, expected in RESPONSE_HEADER_QUERY_CASES:
            with self.subTest(case=name):
                if expected:
                    self.assertEqual(cr.public_url(url, allow_public_query=mode, purpose=purpose), url)
                else:
                    with self.assertRaises(cr.RegistryError):
                        cr.public_url(url, allow_public_query=mode, purpose=purpose)

    def test_reserved_first_component_space_and_version(self):
        """第一dot前の末尾ASCII spaceを含む予約名を元URLの改変なしで拒否する。"""
        for filename in ("CON .v2.exe", "COM1 .v2.zip", "con   .v2.exe", "LPT9 .v2.cab"):
            url = response_header_url(filename)
            with self.subTest(filename=filename):
                self.assertFalse(cr.public_payload_response_header_query(
                    urlsplit(url).query, purpose="PAYLOAD"))
                with self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_POLICY"):
                    cr.public_url(url, allow_public_query=True, purpose="PAYLOAD")

    def test_types_purpose_and_existing_selectors(self):
        """従来のRegistryError契約と数値・fileNameの独立境界を保つ。"""
        for purpose in (None, True, 1, [], "LINK", "payload"):
            with self.subTest(purpose=purpose), self.assertRaisesRegex(cr.RegistryError, "URL_PURPOSE"):
                cr.public_payload_response_header_query("id=1", purpose=purpose)
        for query in (None, True, 1, [], b"id=1"):
            with self.subTest(query=query), self.assertRaisesRegex(cr.RegistryError, "URL_QUERY_TYPE"):
                cr.public_payload_response_header_query(query, purpose="PAYLOAD")
        query = urlsplit(RESPONSE_HEADER_URL).query
        self.assertFalse(cr.public_payload_response_header_query(query, purpose="PAGE"))
        self.assertFalse(cr.public_numeric_query(query, purpose="PAYLOAD"))
        self.assertFalse(cr.public_payload_basename_query(query, purpose="PAYLOAD"))
        for old in ("id=0001", "file=0001", "fileName=A.ZIP"):
            self.assertFalse(cr.public_payload_response_header_query(old, purpose="PAYLOAD"))
            self.assertTrue(cr.public_query_selector(old, purpose="PAYLOAD"))

    def test_filename_and_url_size_boundaries(self):
        """filename180文字・query1536文字・URL2048文字の有限境界を検査する。"""
        url = response_header_url("A" * 176 + ".exe")
        self.assertEqual(cr.public_url(url, allow_public_query=True, purpose="PAYLOAD"), url)
        for filename in ("A" * 177 + ".exe", "ghp_examplefixture.exe", "github_pat_examplefixture.zip",
                         "A((B)).exe", "A).exe", "A(.exe", "A+.exe", "A%.exe", "A..exe",
                         "A .exe", "A:.exe", "A/one.exe", "A\\one.exe", "A\x7f.exe"):
            with self.subTest(filename=filename), self.assertRaises(cr.RegistryError):
                cr.public_url(response_header_url(filename), allow_public_query=True, purpose="PAYLOAD")
        self.assertFalse(cr.public_payload_response_header_query("A" * 1537, purpose="PAYLOAD"))
        # 同じASCII basenameを別の正しいtriplet表現で上限まで拡張する。
        query = ("response-content-disposition=attachment%3Bfilename%2A%3DUTF-8%27%27" +
                 "%25%34%31" * 154 + "%41" * 3 + "A" * 18 + ".exe" +
                 "&response-content-type=application%2Foctet-stream%3B")
        self.assertEqual(len(query), 1536)
        self.assertTrue(cr.public_payload_response_header_query(query, purpose="PAYLOAD"))
        self.assertFalse(cr.public_payload_response_header_query(query.replace(".exe", "A.exe"),
                                                                purpose="PAYLOAD"))
        long_url = url.replace("/files/package", "/" + "a" * (2048 - len(url) + 13), 1)
        self.assertEqual(len(long_url), 2048)
        self.assertEqual(cr.public_url(long_url, allow_public_query=True, purpose="PAYLOAD"), long_url)
        with self.assertRaisesRegex(cr.RegistryError, "URL_TYPE_OR_SIZE"):
            cr.public_url(long_url + "A", allow_public_query=True, purpose="PAYLOAD")

    def test_v2_snapshot_storage_and_v1_page_refusal(self):
        """研究snapshotへ原URLを保存しても導入・公開・端末適用へ昇格しない。"""
        value = fixture()
        value["schema"] = cr.QUERY_REGISTRY_SCHEMA
        value["records"][0].update(downloadUrl=RESPONSE_HEADER_URL, linkState="OFFICIAL_LINK")
        value["observations"] = value["observations"][:1]
        valid = cr.validate_registry(value)
        content = cr.snapshot_content(valid)
        index = cr.parse_json(content["index/drivers.json"])
        self.assertTrue(index["researchOnly"])
        self.assertFalse(index["publishable"])
        self.assertFalse(index["installAuthorized"])
        self.assertEqual(index["applicability"], "NOT_CHECKED")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            cr.write_snapshot(valid, root)
            self.assertEqual(cr.verify_snapshot(root), valid)
            self.assertEqual(cr.snapshot_content(cr.verify_snapshot(root)), content)
        for target in ("source", "v1"):
            invalid = copy.deepcopy(value)
            if target == "source":
                invalid["sources"][0]["officialPage"] = RESPONSE_HEADER_URL
            else:
                invalid["schema"] = cr.REGISTRY_SCHEMA
            with self.subTest(target=target), self.assertRaises(cr.RegistryError):
                cr.validate_registry(invalid)


class LegacyTests(unittest.TestCase):
    """旧metadata投影が根拠と件数を保持し、欠けたURLを推測しないことを検査する。"""

    def setUp(self):
        """秘密や実端末IDを含まない架空の旧実測を用意する。"""
        self.record_hash = "2" * 64
        self.run_hash = "1" * 64
        row = {"id": "P001", "model": "Board One", "runSha256": self.run_hash,
               "state": "UPDATED", "httpStatus": 200, "lastAttemptAt": 1790377200, "error": 0,
               "observedRecords": 1, "storedRecords": 1, "recordFingerprints": [self.record_hash],
               "outcome": "METADATA_SAVED"}
        self.summary = {"schema": "dc-local-feasibility-report-v1", "scopeTargets": 1,
                        "metadataSavedProducts": 1, "currentRecords": 1, "rows": [row]}
        self.plan = {"schema": "drivercrate-collector-evaluation-plan-v1",
                     "products": [{"id": "P001", "maker": "ASUS", "model": "Board One"}]}
        target = {"source": "ASUS_CATALOG", "publicModel": "Board One",
                  "operatingSystem": "Windows 11 64-bit", "category": "LAN", "state": "UPDATED",
                  "lastHttpStatus": 200, "lastAttemptAt": row["lastAttemptAt"], "error": 0,
                  "observedRecordCount": 1,
                  "keySha256": cr.digest(b"ASUS_CATALOG\nBoard One\nWindows 11 64-bit\nLAN\n"),
                  "records": [{"fingerprint": self.record_hash, "displayTitle": "LAN  driver",
                               "driverCategory": "LAN", "operatingSystem": "Windows 11 64-bit",
                               "packageVersion": "1.2", "publishedDate": "2026/01/01"}]}
        self.runs = {self.run_hash: {"schema": "dc-collector-run-v4", "complete": True, "targets": [target]}}

    def test_projection_preserves_unknown_link_and_normalizes_spaces(self):
        """旧表示名の空白だけを正規化し、不明URLと版の根拠を保持する。"""
        value = legacy.project(self.summary, self.plan, self.runs, "test-legacy", "2026-10-03T00:00:00Z")
        self.assertEqual(value["records"][0]["title"], "LAN driver")
        self.assertIsNone(value["records"][0]["downloadUrl"])
        self.assertEqual(value["observations"][0]["evidenceSha256"], self.run_hash)

    def test_summary_and_target_contradictions(self):
        """旧報告と本文の異なる件数・fingerprint・製品を拒否する。"""
        for name, value in (("storedRecords", 2), ("recordFingerprints", ["3" * 64]),
                            ("model", "Other Board"), ("observedRecords", 2)):
            summary = copy.deepcopy(self.summary)
            summary["rows"][0][name] = value
            with self.subTest(field=name), self.assertRaises(cr.RegistryError):
                legacy.project(summary, self.plan, self.runs, "test-legacy", "2026-10-03T00:00:00Z")

    def test_envelope_hash_and_run_file_hash(self):
        """実fileのhashとenvelope内本文hashをそれぞれ確認する。"""
        with tempfile.TemporaryDirectory(prefix="dc-legacy-test-") as directory:
            root = Path(directory)
            body = cr.json_bytes(self.runs[self.run_hash]).decode("utf-8")
            envelope = {"schema": "dc-collector-envelope-v1", "body": body,
                        "sha256": cr.digest(body.encode("utf-8"))}
            raw = cr.json_bytes(envelope)
            path = root / "run.json"
            path.write_bytes(raw)
            self.assertEqual(len(legacy.read_runs(root, {cr.digest(raw)})), 1)
            envelope["sha256"] = "0" * 64
            raw = cr.json_bytes(envelope)
            path.write_bytes(raw)
            with self.assertRaises(cr.RegistryError):
                legacy.read_runs(root, {cr.digest(raw)})


if __name__ == "__main__":
    unittest.main(verbosity=2)
