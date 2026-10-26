"""ADR0344の非通信fake試験。実保護鍵/Task登録/HTTP/GitHub writeを行わない。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
"""
import base64
import gzip
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import timedelta
import io
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import daily_index_pipeline as pipeline
from test_project_collected_native_index import ProjectionTests


def workspace_approval(repository: Path, state: Path, manifest_sha256: str | None = None) -> dict:
    """実承認ではない人工recordを、閉fieldと明示kindの試験用に構築する。"""
    return {"schema": "dc-approved-daily-workspace-v1", "approvalKind": "EXPLICIT_EXISTING_DAILY_WORKSPACE",
        "taskName": pipeline.TASK_NAME, "collectorManifestSha256": manifest_sha256 or pipeline.MANIFEST_SHA256,
        "repositoryRoot": str(repository), "stateRoot": str(state)}


@contextmanager
def workspace_fixture():
    """人工directoryとACL snapshotだけを使い、承認helperを実装どおり検査できるfixtureを貸す。"""
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        root = directory / "protected"
        repository = directory / "approved-workspace"
        state = repository / pipeline.STATE_RELATIVE
        state.mkdir(parents=True)
        (root / "control").mkdir(parents=True)
        path = root / "control/approved-workspace.json"
        approval = workspace_approval(repository, state)
        path.write_bytes(pipeline.canonical(approval))
        safe = ("S-1-5-32-544", True, [(0, 0, 0x1f01ff, "S-1-5-18"),
                                    (0, 0, 0x1f01ff, "S-1-5-32-544")])
        with patch.object(pipeline, "protected_root", return_value=root), \
                patch.object(pipeline, "acl_snapshot", return_value=safe), \
                patch.object(pipeline, "_APPROVED_WORKSPACE", None):
            yield SimpleNamespace(directory=directory, root=root, repository=repository, state=state,
                                  approval=approval, path=path, safe=safe)


def envelope(raw: bytes, key_id="distribution-index-" + "a" * 32) -> bytes:
    return pipeline.canonical({"schema": "driver-index-envelope-v1", "keyId": key_id,
        "manifestBytesBase64": base64.b64encode(raw).decode("ascii"),
        "signatureBase64": base64.b64encode(b"X" * 384).decode("ascii")})


def publisher_anonymous_fixture(bundle, commit, tag):
    """旧identity試験だけのcallback注入。完全wire/journalの受入は新A条件で別検査する。"""
    manifest, _ = pipeline.unpack_envelope(bundle["manifest.json"])
    return pipeline.PublicAnonymousObservation(pipeline._PUBLIC_ANONYMOUS_AUTHORITY, {
        "status": "VERIFIED", "generation": manifest["generation"], "commit": commit, "tag": tag,
        "envelopeSha256": pipeline.sha(bundle["manifest.json"]), "gzipSha256": pipeline.sha(bundle["index.json.gz"])})


def anonymous_stdout_fixture(bundle, now, behavior="success"):
    """三resourceの完全fake stdoutを原byteから作り、実HTTP/native起動を行わない。"""
    resources = []
    roles = ("CURRENT_ENVELOPE", "IMMUTABLE_ENVELOPE", "IMMUTABLE_GZIP")
    failure_index = {"timeout": 0, "partial": 1, "304": 2, "401": 0, "byte-mismatch": 1, "current-whitespace": 0,
                     "signature": 1}.get(behavior)
    for index, role in enumerate(roles):
        expected = bundle["index.json.gz" if index == 2 else "manifest.json"]
        failed = failure_index is not None and index == failure_index
        not_started = failure_index is not None and index > failure_index
        resources.append({"role": role, "state": "NOT_STARTED" if not_started else "FAILED" if failed else "COMPLETE",
            "httpStatus": 0 if not_started or (failed and behavior == "timeout") else
                304 if failed and behavior == "304" else 401 if failed and behavior == "401" else 200,
            "sends": 0 if not_started else 4 if behavior == "nine" and index != 0 else 1,
            "receivedBytes": 0 if not_started or (failed and behavior in {"timeout", "304", "401"}) else
                20 if failed and behavior == "partial" else len(expected) + (1 if failed and behavior == "current-whitespace" else 0),
            "sha256": None if failed or not_started else pipeline.sha(expected),
            "nativeError": 2147954402 if failed and behavior == "timeout" else 2147942413 if failed else 0})
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return pipeline.canonical({"schema": "dc-public-index-readback-result-v1",
        "outcome": "VERIFIED" if failure_index is None else "UNKNOWN", "startedAtUtc": stamp,
        "completedAtUtc": stamp, "elapsedMilliseconds": 1, "resources": resources,
        "sends": sum(value["sends"] for value in resources),
        "receivedBytes": sum(value["receivedBytes"] for value in resources),
        "nativeError": 0 if failure_index is None else 2147942413,
        "failureStage": "NONE" if failure_index is None else "TRUST" if behavior == "signature" else
            ("CURRENT" if failure_index == 0 else "MANIFEST_ASSET" if failure_index == 1 else "GZIP_ASSET")})


class FakeRemote:
    """GitHub APIのwrite順序/CAS/byte再取得を扱う有限RAM fake。"""
    def __init__(self):
        self.events = []
        self.releases = {}
        self.assets = {}
        self.blobs = {}
        self.trees = {}
        self.commits = {}
        self.head = None
        self.private = True
        self.login = "EnterOgawa"
        self.foreign = False
        self.failure = None
        self.counter = 0
        self.ref_updates = 0
        self.repository_node_id = "R_artificial"

    def identifier(self):
        self.counter += 1
        return f"{self.counter:040x}"

    def api(self, method, path, body=None, *, binary=False, content_type="application/json"):
        self.events.append((method, path, deepcopy(body)))
        if path == "user":
            return {"login": self.login}
        if path == pipeline.API:
            return {"full_name": pipeline.REPOSITORY, "private": self.private,
                    "visibility": "private" if self.private else "public", "node_id": "R_artificial"}
        if path == "graphql":
            self.ref_updates += 1
            update = body["variables"]["input"]["refUpdates"][0]
            assert update["name"] == "refs/heads/driver-index" and update["force"] is False
            assert body["variables"]["input"]["repositoryId"] == self.repository_node_id
            if self.failure == "cas":
                raise ValueError("FAKE_CAS_CONFLICT")
            pipeline.require(update["beforeOid"] == (self.head or "0" * 40), "FAKE_CAS_EXPECTED_HEAD")
            self.head = update["afterOid"]
            return {"data": {"updateRefs": {"clientMutationId": None}}}
        tail = path.removeprefix(pipeline.API + "/")
        if tail == "git/ref/heads/driver-index":
            if self.head is None:
                raise pipeline.Missing()
            return {"object": {"sha": self.head}}
        if tail.startswith("releases/tags/"):
            tag = tail.removeprefix("releases/tags/")
            if tag not in self.releases:
                raise pipeline.Missing()
            return deepcopy(self.releases[tag])
        if tail == "releases" and method == "POST":
            self.assert_release(body)
            self.releases[body["tag_name"]] = dict(body, id=len(self.releases)+1, assets=[])
            return deepcopy(self.releases[body["tag_name"]])
        if tail.startswith("releases/assets/"):
            raw = self.assets[int(tail.split("/")[-1])]
            return raw + b"corrupt" if self.failure == "readback" else raw
        if path.startswith("https://uploads.github.com/"):
            if self.failure == "upload":
                raise ValueError("FAKE_UPLOAD_FAILURE")
            name = path.split("?name=")[1]
            release_id = int(path.split("/releases/")[1].split("/")[0])
            release = next(value for value in self.releases.values() if value["id"] == release_id)
            asset_id = len(self.assets)+1
            self.assets[asset_id] = body
            release["assets"].append({"name": name, "id": asset_id, "state": "uploaded", "size": len(body)})
            return {"id": asset_id}
        if tail.startswith("releases/"):
            identifier = int(tail.split("/")[-1])
            release = next(value for value in self.releases.values() if value["id"] == identifier)
            if method == "PATCH":
                if self.failure == "publish":
                    raise ValueError("FAKE_PUBLISH_FAILURE")
                release.update(body)
            return deepcopy(release)
        if tail == "git/blobs" and method == "POST":
            identifier = self.identifier()
            self.blobs[identifier] = base64.b64decode(body["content"], validate=True)
            return {"sha": identifier}
        if tail.startswith("git/blobs/"):
            raw = self.blobs[tail.split("/")[-1]]
            return {"encoding": "base64", "size": len(raw), "content": base64.b64encode(raw).decode("ascii")}
        if tail == "git/trees" and method == "POST":
            identifier = self.identifier()
            self.trees[identifier] = deepcopy(body["tree"])
            return {"sha": identifier}
        if tail.startswith("git/trees/"):
            result = deepcopy(self.trees[tail.split("/")[-1].split("?")[0]])
            if self.foreign:
                result.append({"path": "private.log", "type": "blob", "mode": "100644", "sha": "f" * 40})
            return {"truncated": False, "tree": result}
        if tail == "git/commits" and method == "POST":
            identifier = self.identifier()
            self.commits[identifier] = deepcopy(body)
            return {"sha": identifier}
        if tail.startswith("git/commits/"):
            return {"tree": {"sha": self.commits[tail.split("/")[-1]]["tree"]}}
        if tail in {"git/refs", "git/refs/heads/driver-index"}:
            self.ref_updates += 1
            if self.failure == "cas":
                raise ValueError("FAKE_CAS_CONFLICT")
            if method == "POST":
                pipeline.require(self.head is None, "FAKE_REF_ALREADY_EXISTS")
            else:
                pipeline.require(body["force"] is False and self.commits[body["sha"]]["parents"] == [self.head],
                                 "FAKE_NOT_FAST_FORWARD")
            self.head = body["sha"]
            return {"object": {"sha": self.head}}
        raise AssertionError((method, path))

    @staticmethod
    def assert_release(body):
        assert body["draft"] is True and body["prerelease"] is True and body["make_latest"] == "false"
        assert body["target_commitish"] == "main"


class PublicIdentityRemote(FakeRemote):
    """既存RAM fakeのREST/二asset/CASを再利用し、公開identityだけ明示する。"""

    def __init__(self):
        """fixture値は公開identity契約だけで、credentialや実端末情報を含まない。"""
        super().__init__()
        self.repository_node_id = "R_kgDOVPPbAw"
        self.user = {"login": "EnterOgawa", "id": 113655398}
        self.repository = {"full_name": "EnterOgawa/drivercrate", "id": 1425267459,
            "node_id": self.repository_node_id, "owner": {"login": "EnterOgawa", "id": 113655398},
            "private": False, "visibility": "public"}
        self.identity_error = None
        self.change_after_write = None

    def api(self, method, path, body=None, **kwargs):
        """identity応答と途中変更をRAMへ閉じ、既存remote作用は同じfakeへ渡す。"""
        if path in {"user", pipeline.API}:
            self.events.append((method, path, deepcopy(body)))
            if path == pipeline.API and self.identity_error is not None:
                raise self.identity_error
            return deepcopy(self.user if path == "user" else self.repository)
        result = super().api(method, path, body, **kwargs)
        if path == "graphql" and self.failure == "cas-response":
            raise ValueError("ARTIFICIAL_CAS_RESPONSE_UNKNOWN")
        if path == pipeline.API + "/git/ref/heads/driver-index" and self.failure == "confirm" and self.ref_updates:
            return {"object": {"sha": "f" * 40}}
        if method != "GET" and self.change_after_write is not None:
            self.change_after_write(self)
        return result


class PublicPublisherIdentityTests(unittest.TestCase):
    """ADR0381の固定13test。取得用人工束とRAM remoteだけを内部境界へ渡す。"""

    def setUp(self):
        """既存の取得用六入力fixtureを借用し、metadata-only検証へfallbackしない。"""
        fixture = DailyDistributionAcquisitionAuditTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        self.bundle = deepcopy(fixture.bundle)
        self.record = {"schema": "dc-approved-public-index-publisher-v1",
            "approvalKind": "EXPLICIT_PUBLIC_SIGNED_INDEX", "mode": "PUBLIC_SIGNED_INDEX_V1",
            "purpose": "DISTRIBUTION_ACQUISITION", "repository": "EnterOgawa/drivercrate",
            "repositoryId": 1425267459, "repositoryNodeId": "R_kgDOVPPbAw",
            "ownerLogin": "EnterOgawa", "ownerId": 113655398, "actorLogin": "EnterOgawa",
            "actorId": 113655398, "visibility": "public",
            "publicFingerprint": "0ac4d0ce9873c82b3c7bb7bd3fb3f5d2a57044bf968c5c6e2af02176cee39d3f"}
        self.raw = pipeline.canonical(self.record)
        self.remote = PublicIdentityRemote()
        self.verifications = []

    def verify(self, bundle, *, historical):
        """署名の実処理を行わず、取得用hash/原六入力/schema監査を実装へ接続する。"""
        self.verifications.append(historical)
        self.fixture.audit(bundle=bundle)

    def publisher(self, **kwargs):
        """明示原byte以外の運用入口を使わず、毎回独立したPublisherを構築する。"""
        args = dict(purpose=pipeline.ACQUISITION_PURPOSE, public_target=self.raw, anonymous=publisher_anonymous_fixture)
        args.update(kwargs)
        return pipeline.Publisher(self.remote, self.verify, **args)

    def writes(self):
        """GETを除く呼出し試行を作用分母として返す。"""
        return [event for event in self.remote.events if event[0] != "GET"]

    def test_public_success_two_assets_and_exact_node_cas(self):
        """正規公開identityと取得用検証から固定二asset、一回CASだけへ進む。"""
        result = self.publisher().publish(self.bundle)
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual(len(self.writes()), 8)
        uploads = [event for event in self.writes() if event[1].startswith("https://uploads.github.com/")]
        self.assertEqual({event[1].split("?name=")[1] for event in uploads}, pipeline.ASSETS)
        self.assertEqual({event[1].split("?name=")[1]: event[2] for event in uploads}, self.bundle)
        cas = self.writes()[-1][2]["variables"]["input"]
        self.assertEqual(cas["repositoryId"], "R_kgDOVPPbAw")
        self.assertEqual(cas["refUpdates"][0]["beforeOid"], "0" * 40)
        self.assertIs(cas["refUpdates"][0]["force"], False)
        self.assertEqual(self.remote.ref_updates, 1)
        self.assertEqual(self.verifications, [False, False])

    def test_default_private_and_public_refusal(self):
        """targetなしの人工Private成功と実Public状態拒否を従来条件で維持する。"""
        self.remote = FakeRemote()
        result = pipeline.Publisher(self.remote, self.verify).publish(self.bundle)
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual(len(self.writes()), 8)
        self.remote = PublicIdentityRemote()
        with self.assertRaisesRegex(ValueError, "^PRIVATE_IDENTITY$"):
            pipeline.Publisher(self.remote, self.verify).publish(self.bundle)
        self.assertEqual(len(self.writes()), 0)

    def test_record_closed_fields_and_exact_types(self):
        """全fieldの欠損/型/値と数値別名、旧repo/任意入力を解析時に拒否する。"""
        variants = []
        for name, value in self.record.items():
            missing = dict(self.record)
            del missing[name]
            variants.append((name + "-missing", missing, "PUBLIC_APPROVAL_FIELDS"))
            for suffix, changed in (("type", []), ("value", value + 1 if type(value) is int else value + "x")):
                variants.append((name + "-" + suffix, dict(self.record, **{name: changed}), "PUBLIC_APPROVAL_VALUE"))
        for name in ("repositoryId", "ownerId", "actorId"):
            for label, value in (("bool", True), ("zero", 0), ("float", float(self.record[name])),
                                 ("string", str(self.record[name]))):
                variants.append((name + "-" + label, dict(self.record, **{name: value}), "PUBLIC_APPROVAL_VALUE"))
        for label, changes, code in (("old-private", {"repositoryId": 1353134843}, "PUBLIC_APPROVAL_VALUE"),
                ("alias", {"repository": "EnterOgawa/drivercrate-development-private"}, "PUBLIC_APPROVAL_VALUE"),
                ("extra", {"extra": 1}, "PUBLIC_APPROVAL_FIELDS"),
                ("private-field", {"private": False}, "PUBLIC_APPROVAL_FIELDS"),
                ("false-fingerprint", {"publicFingerprint": "0" * 64}, "PUBLIC_APPROVAL_VALUE")):
            variants.append((label, dict(self.record, **changes), code))
        self.assertEqual(len(variants), 56)
        for label, record, code in variants:
            with self.subTest(variant=label), self.assertRaisesRegex(ValueError, "^" + code + "$"):
                self.publisher(public_target=pipeline.canonical(record))
        self.assertEqual(self.remote.events, [])

    def test_record_bytes_duplicate_and_bounds(self):
        """非byte/境界/重複JSONをremote呼出し前に拒否し、通常JSONエラーも保持する。"""
        for label, raw in (("none", None), ("dict", self.record), ("string", self.raw.decode()),
                           ("mutable", bytearray(self.raw)), ("empty", b""), ("oversize", b" " * 65537)):
            with self.subTest(variant=label), self.assertRaisesRegex(ValueError, "^PUBLIC_APPROVAL_BYTES$"):
                pipeline.public_publisher_approval(raw)
        duplicate = self.raw[:-1] + b',"repositoryId":1425267459}'
        nested = b'{"nested":{"duplicate":1,"duplicate":2}}'
        for label, raw in (("duplicate-root", duplicate), ("duplicate-nested", nested)):
            with self.subTest(variant=label), self.assertRaisesRegex(ValueError, "^DUPLICATE_JSON_KEY$"):
                pipeline.public_publisher_approval(raw)
        for label, raw in (("utf8", b"\xff"), ("syntax", b"{")):
            with self.subTest(variant=label), self.assertRaisesRegex(ValueError, "^JSON_ENCODING_OR_SYNTAX$"):
                pipeline.public_publisher_approval(raw)
        self.assertEqual(self.remote.events, [])

    def test_public_purpose_and_no_unvalidated_target(self):
        """Publicは取得用途だけとし、構築済み値の注入でもbyte検証を省略しない。"""
        with self.subTest(variant="default"), self.assertRaisesRegex(ValueError, "^PUBLIC_PUBLISHER_PURPOSE$"):
            pipeline.Publisher(self.remote, self.verify, public_target=self.raw)
        for purpose in ("METADATA_ONLY", "OTHER", None):
            with self.subTest(variant=str(purpose)), self.assertRaisesRegex(ValueError, "^PUBLIC_PUBLISHER_PURPOSE$"):
                self.publisher(purpose=purpose)
        with self.subTest(variant="parsed-target"), self.assertRaisesRegex(ValueError, "^PUBLIC_APPROVAL_BYTES$"):
            self.publisher(public_target=pipeline.public_publisher_approval(self.raw))
        self.assertEqual(self.remote.events, [])

    def test_remote_identity_refusals_before_writes(self):
        """名前の再利用、数値別名、所有者/actor差と公開状態の矛盾を厳密拒否する。"""
        variants = []
        for location, fields in (("user", ("id", "login")),
                ("repository", ("id", "node_id", "full_name", "private", "visibility")),
                ("owner", ("id", "login"))):
            for field in fields:
                for label, value in (("missing", None), ("type", []), ("wrong", "Other")):
                    variants.append((location, field, label, value))
            for field in ("id",):
                for label, value in (("bool", True), ("zero", 0), ("float", 113655398.0), ("string", "113655398")):
                    variants.append((location, field, label, value))
        variants.extend([("repository", "id", "old-private", 1353134843),
                         ("repository", "id", "other-positive", 1425267460),
                         ("repository", "private", "true", True), ("repository", "private", "zero", 0),
                         ("repository", "owner", "not-dict", []), ("repository", "owner", "missing", None)])
        self.assertEqual(len(variants), 45)
        for location, field, label, value in variants:
            self.remote = PublicIdentityRemote()
            target = self.remote.user if location == "user" else self.remote.repository
            if location == "owner":
                target = target["owner"]
            if label == "missing":
                del target[field]
            else:
                target[field] = value
            with self.subTest(variant=location + "-" + field + "-" + label), \
                    self.assertRaisesRegex(ValueError, "^PUBLIC_IDENTITY$"):
                self.publisher().publish(self.bundle)
            self.assertEqual(len(self.writes()), 0)
        for label in ("user", "repository"):
            self.remote = PublicIdentityRemote()
            setattr(self.remote, label, [])
            with self.subTest(variant=label + "-container"), self.assertRaisesRegex(ValueError, "^PUBLIC_IDENTITY$"):
                self.publisher().publish(self.bundle)
            self.assertEqual(len(self.writes()), 0)

    def test_identity_unknown_and_rename_are_not_authority(self):
        """404/不明は原例外、renameとaliasは不一致とし、移行許可へ変換しない。"""
        for failure in (pipeline.Missing(), ValueError("ARTIFICIAL_IDENTITY_UNKNOWN")):
            self.remote = PublicIdentityRemote()
            self.remote.identity_error = failure
            with self.subTest(variant=type(failure).__name__), self.assertRaises(type(failure)) as caught:
                self.publisher().publish(self.bundle)
            self.assertIs(caught.exception, failure)
            self.assertEqual(len(self.writes()), 0)
        for name in ("EnterOgawa/renamed", "EnterOgawa/drivercrate-development-private"):
            self.remote = PublicIdentityRemote()
            self.remote.repository["full_name"] = name
            with self.subTest(variant=name), self.assertRaisesRegex(ValueError, "^PUBLIC_IDENTITY$"):
                self.publisher().publish(self.bundle)
            self.assertEqual(len(self.writes()), 0)

    def test_identity_change_stops_each_next_write(self):
        """部分作用1..7を保持し、次のwriteとcallback後CASを不一致で止める。"""
        changes = (("repository", "id", 1353134843), ("owner", "id", 1), ("user", "id", 1),
                   ("repository", "node_id", "R_other"), ("repository", "visibility", "private"),
                   ("repository", "full_name", "EnterOgawa/renamed"), ("repository", "private", True))
        for ordinal, (location, field, value) in enumerate(changes, 1):
            self.remote = PublicIdentityRemote()
            def change(remote):
                """指定writeの完了後だけidentityを変更し、作成済み部分作用を保持する。"""
                if len([event for event in remote.events if event[0] != "GET"]) == ordinal:
                    target = remote.user if location == "user" else remote.repository
                    if location == "owner":
                        target = target["owner"]
                    target[field] = value
            self.remote.change_after_write = change
            with self.subTest(variant="after-write-" + str(ordinal)), self.assertRaisesRegex(ValueError, "^PUBLIC_IDENTITY$"):
                self.publisher().publish(self.bundle)
            self.assertEqual(len(self.writes()), ordinal)
            self.assertEqual(self.remote.ref_updates, 0)
            self.assertIsNone(self.remote.head)
        self.remote = PublicIdentityRemote()
        def before_cas():
            """最後のcaller callbackでもidentityが変わり得る条件を再現する。"""
            self.remote.repository["node_id"] = "R_other"
        with self.subTest(variant="before-cas"), self.assertRaisesRegex(ValueError, "^PUBLIC_IDENTITY$"):
            self.publisher(before_cas=before_cas).publish(self.bundle)
        self.assertEqual(len(self.writes()), 7)
        self.assertEqual(self.remote.ref_updates, 0)
        self.remote = PublicIdentityRemote()
        publisher = self.publisher()
        def tamper_cas_node():
            """remoteが正規でもcallerがCAS引数だけを差し替える境界を再現する。"""
            publisher.repository_id = "R_other"
        publisher.before_cas = tamper_cas_node
        with self.subTest(variant="cas-node-argument"), self.assertRaisesRegex(ValueError, "^PUBLIC_IDENTITY$"):
            publisher.publish(self.bundle)
        self.assertEqual(len(self.writes()), 7)
        self.assertEqual(self.remote.ref_updates, 0)

    def test_public_readback_only_is_zero_write(self):
        """元byteだけの再開に限定し、未公開状態のreadback-onlyで追加作用を許可しない。"""
        self.publisher().publish(self.bundle)
        before = len(self.writes())
        with self.subTest(variant="same-bytes"):
            self.assertTrue(self.publisher().publish(self.bundle, readback_only=True)["resumed"])
            self.assertEqual(len(self.writes()), before)
            self.assertEqual(self.verifications[-3:], [False, True, False])
        self.remote = PublicIdentityRemote()
        with self.subTest(variant="no-current"), self.assertRaisesRegex(ValueError, "^CURRENT_CAS_OUTCOME_UNKNOWN$"):
            self.publisher().publish(self.bundle, readback_only=True)
        self.assertEqual(len(self.writes()), 0)
        for failure, code in (("cas-response", "ARTIFICIAL_CAS_RESPONSE_UNKNOWN"),
                              ("confirm", "CURRENT_CONFIRMATION_UNKNOWN")):
            self.remote = PublicIdentityRemote()
            self.remote.failure = failure
            with self.subTest(variant=failure):
                with self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    self.publisher().publish(self.bundle)
                self.assertEqual(len(self.writes()), 8)
                self.assertIsNotNone(self.remote.head)
                self.remote.failure = None
                before = len(self.writes())
                self.assertTrue(self.publisher().publish(self.bundle, readback_only=True)["resumed"])
                self.assertEqual(len(self.writes()), before)
                self.assertEqual(self.remote.ref_updates, 1)

    def test_public_assets_and_verifier_cannot_be_skipped(self):
        """二assetとfresh/readback/resumeのcallback失敗を無視しない。"""
        with self.subTest(variant="extra"), self.assertRaisesRegex(ValueError, "^ASSET_ALLOWLIST$"):
            self.publisher().publish(dict(self.bundle, **{"driver.zip": b"artificial"}))
        self.assertEqual(self.remote.events, [])
        for fail_at, expected_writes in ((1, 0), (2, 3)):
            self.remote = PublicIdentityRemote()
            calls = []
            def reject(bundle, *, historical):
                """指定された検証段階だけ拒否し、他段階は取得用実監査へ渡す。"""
                calls.append(historical)
                if len(calls) == fail_at:
                    raise ValueError("ARTIFICIAL_SIGNATURE_REJECTED")
                self.verify(bundle, historical=historical)
            publisher = pipeline.Publisher(self.remote, reject, purpose=pipeline.ACQUISITION_PURPOSE,
                                           public_target=self.raw, anonymous=publisher_anonymous_fixture)
            with self.subTest(variant="verify-" + str(fail_at)), \
                    self.assertRaisesRegex(ValueError, "^ARTIFICIAL_SIGNATURE_REJECTED$"):
                publisher.publish(self.bundle)
            self.assertEqual(len(self.writes()), expected_writes)
        self.remote = PublicIdentityRemote()
        self.publisher().publish(self.bundle)
        before = len(self.writes())
        def rejected(bundle, *, historical):
            """再開でもfresh署名検証を省略できない人工拒否を返す。"""
            raise ValueError("ARTIFICIAL_SIGNATURE_REJECTED")
        with self.subTest(variant="resume-verifier"), self.assertRaisesRegex(ValueError, "^ARTIFICIAL_SIGNATURE_REJECTED$"):
            pipeline.Publisher(self.remote, rejected, purpose=pipeline.ACQUISITION_PURPOSE,
                public_target=self.raw, anonymous=publisher_anonymous_fixture).publish(self.bundle, readback_only=True)
        self.assertEqual(len(self.writes()), before)

    def test_public_partial_failures_preserve_current(self):
        """実作用の試行数と旧headを保持し、自動再試行やrollbackを行わない。"""
        for failure, code, writes in (("upload", "FAKE_UPLOAD_FAILURE", 2),
                ("readback", "REMOTE_ASSET_SIZE", 3), ("publish", "FAKE_PUBLISH_FAILURE", 4),
                ("cas", "FAKE_CAS_CONFLICT", 8)):
            self.remote = PublicIdentityRemote()
            self.remote.failure = failure
            with self.subTest(variant=failure), self.assertRaisesRegex(ValueError, "^" + code + "$"):
                self.publisher().publish(self.bundle)
            self.assertEqual(len(self.writes()), writes)
            self.assertIsNone(self.remote.head)
            self.assertEqual(self.remote.ref_updates, 1 if failure == "cas" else 0)

    def test_target_owns_immutable_original_bytes(self):
        """検証原byte/hashを凍結し、元辞書の後変更をtargetへ反映しない。"""
        from dataclasses import FrozenInstanceError
        target = pipeline.public_publisher_approval(self.raw)
        self.record["repositoryId"] = 1353134843
        self.assertEqual(target.approval_bytes, self.raw)
        self.assertEqual(target.approval_sha256, pipeline.sha(self.raw))
        with self.assertRaises(FrozenInstanceError):
            target.approval_bytes = b"changed"
        publisher = self.publisher()
        publisher.identity()
        self.assertEqual(publisher.repository_id, "R_kgDOVPPbAw")
        self.assertEqual(len(self.writes()), 0)

    def test_v1_v2_closed_field_sets_are_unchanged(self):
        """運用schemaへPublic fieldを混入せず、従来の閉field集合をliteral照合する。"""
        v1 = {"schema", "repositoryRoot", "stateRoot", "manifestFile", "manifestSha256", "scopeFile",
            "scopeSha256", "collectorExe", "collectorSha256", "signerExe", "signerSha256", "publicKeyFile",
            "fingerprint", "pythonExe", "ghExe", "outputRoot", "smokeLocal", "firstDailyLocal",
            "pipelineSha256", "producerSha256"}
        v2 = v1 | {"purpose", "termsReviewMode", "modulePins", "originalInputs", "archiveFile", "archiveSha256",
            "archiveBytes", "selectedInf", "legacyMetadata", "legacyReservationFence"}
        self.assertEqual(pipeline.CONFIG_FIELDS, v1)
        self.assertEqual(pipeline.V2_CONFIG_FIELDS, v2)
        for label, fields in (("v1", v1), ("v2", v2)):
            config = {name: None for name in fields}
            config["publicTarget"] = self.record
            with self.subTest(variant=label), self.assertRaisesRegex(ValueError, "^ARTIFICIAL_CONFIG_FIELDS$"):
                pipeline.cr.fields(config, fields, "ARTIFICIAL_CONFIG_FIELDS")


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.workspace_fixture = self.enterContext(workspace_fixture())
        self.workspace = pipeline.approved_workspace()
        # These RAM pipeline fakes isolate OS ACL work; actual policy and placement have separate tests.
        self.operation_mock = patch.object(pipeline, "operation_root", side_effect=lambda path, **kw: path)
        self.tree_mock = patch.object(pipeline, "protected_tree")
        self.operation_mock.start()
        self.tree_mock.start()
        self.addCleanup(self.operation_mock.stop)
        self.addCleanup(self.tree_mock.stop)
        fixture = ProjectionTests()
        fixture.setUp()
        self.fixture = fixture
        self.now = fixture.now
        self.scope = dict(fixture.scope, keyId="distribution-index-" + "a" * 32)
        self.receipt = fixture.daily_receipt()
        self.remote = FakeRemote()
        self.verifications = []

    def bundle(self, generation=4, receipt=None):
        receipt = deepcopy(receipt or self.receipt)
        receipt.update(generation=generation, previousReceiptSha256="" if generation == 4 else "9" * 64)
        raw, packed, manifest, _ = pipeline.projection.project_daily(self.scope, receipt, self.now)
        return {"index.json.gz": packed, "manifest.json": envelope(manifest, self.scope["keyId"])}, receipt

    def verify(self, bundle, *, historical):
        self.verifications.append(historical)
        manifest, _ = pipeline.unpack_envelope(bundle["manifest.json"])
        pipeline.require(manifest["keyId"] == self.scope["keyId"], "FAKE_WRONG_KEY")
        if not historical:
            receipt = dict(self.receipt, generation=manifest["generation"],
                           previousReceiptSha256="" if manifest["generation"] == 4 else "9" * 64)
            pipeline.audit_bundle(bundle, self.scope, receipt, self.now)

    def publisher(self):
        return pipeline.Publisher(self.remote, self.verify)

    def test_exact_index_only_success_and_immutable_resume(self):
        bundle, _ = self.bundle()
        result = self.publisher().publish(bundle)
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual(self.remote.ref_updates, 1)
        self.assertEqual(self.remote.commits[self.remote.head]["parents"], [])
        self.assertEqual(set(next(iter(self.remote.releases.values()))["assets"][i]["name"] for i in range(2)), pipeline.ASSETS)
        writes = len([event for event in self.remote.events if event[0] != "GET"])
        resumed = self.publisher().publish(bundle)
        self.assertTrue(resumed["resumed"])
        self.assertEqual(writes, len([event for event in self.remote.events if event[0] != "GET"]))
        self.assertTrue(self.verifications[-1])

    def test_reject_extra_assets_and_schema_before_any_remote_call(self):
        for extra in ("payload.zip", "receipt.json", "key.blob", "worktree.zip", "inventory.json", "log.txt"):
            bundle, _ = self.bundle()
            bundle[extra] = b"private"
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "ASSET_ALLOWLIST"):
                self.publisher().publish(bundle)
        self.assertEqual(self.remote.events, [])
        bundle, _ = self.bundle()
        value = json.loads(bundle["manifest.json"])
        value["token"] = "private"
        bundle["manifest.json"] = pipeline.canonical(value)
        with self.assertRaisesRegex(ValueError, "ENVELOPE_FIELDS"):
            self.publisher().publish(bundle)
        self.assertEqual(self.remote.events, [])

    def test_public_projection_rejects_hash_body_schema_and_privacy(self):
        for name in pipeline.ASSETS:
            bundle, receipt = self.bundle()
            bundle[name] += b"x"
            with self.subTest(name=name), self.assertRaises((ValueError, json.JSONDecodeError)):
                pipeline.audit_bundle(bundle, self.scope, receipt, self.now)
        receipt = deepcopy(self.receipt)
        receipt["records"][0]["displayTitle"] = "password=artificial-private-value"
        projected = {key: receipt[key] for key in ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")}
        receipt.update(projectionBytesBase64=base64.b64encode(pipeline.canonical(projected)).decode("ascii"),
                       projectionSha256=pipeline.sha(pipeline.canonical(projected)))
        bundle, _ = self.bundle(receipt=receipt)
        with self.assertRaisesRegex(ValueError, "PUBLIC_PRIVACY"):
            pipeline.audit_bundle(bundle, self.scope, receipt, self.now)

    def test_private_and_identity_refusal_before_writes(self):
        for field, value in (("private", False), ("login", "OtherUser")):
            self.remote = FakeRemote()
            setattr(self.remote, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "PRIVATE_IDENTITY"):
                self.publisher().publish(self.bundle()[0])
            self.assertFalse(any(event[0] != "GET" for event in self.remote.events))

    def test_upload_readback_publish_failure_leave_current(self):
        for failure in ("upload", "readback", "publish"):
            self.remote = FakeRemote()
            self.remote.failure = failure
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.publisher().publish(self.bundle()[0])
            self.assertIsNone(self.remote.head)
            self.assertEqual(self.remote.ref_updates, 0)

    def test_existing_branch_foreign_file_rejected_and_no_force_cas(self):
        self.publisher().publish(self.bundle()[0])
        original = self.remote.head
        self.remote.foreign = True
        with self.assertRaisesRegex(ValueError, "BRANCH_FOREIGN_CONTENT"):
            self.publisher().publish(self.bundle(5)[0])
        self.assertEqual(self.remote.head, original)
        self.remote.foreign = False
        self.remote.failure = "cas"
        before = self.remote.ref_updates
        with self.assertRaisesRegex(ValueError, "FAKE_CAS_CONFLICT"):
            self.publisher().publish(self.bundle(5)[0])
        self.assertEqual(self.remote.ref_updates, before+1)
        self.assertEqual(self.remote.head, original)
        update = self.remote.events[-1][2]["variables"]["input"]["refUpdates"][0]
        self.assertFalse(update["force"])
        self.assertEqual(update["beforeOid"], original)

    def test_immutable_asset_conflict_and_generation_rollback(self):
        self.publisher().publish(self.bundle(5)[0])
        original = self.remote.head
        with self.assertRaisesRegex(ValueError, "REMOTE_GENERATION"):
            self.publisher().publish(self.bundle(4)[0])
        self.assertEqual(self.remote.head, original)
        self.remote = FakeRemote()
        bundle, _ = self.bundle()
        manifest, _ = pipeline.unpack_envelope(bundle["manifest.json"])
        self.remote.releases[manifest["asset"]["tag"]] = {"tag_name": manifest["asset"]["tag"], "id": 1,
            "draft": True, "prerelease": True, "assets": [{"id": 1, "name": "index.json.gz", "state": "uploaded", "size": 3}]}
        self.remote.assets[1] = b"bad"
        with self.assertRaisesRegex(ValueError, "IMMUTABLE_ASSET_CONFLICT"):
            self.publisher().publish(bundle)
        self.assertIsNone(self.remote.head)

    def test_hold_is_only_preflight_and_bounded(self):
        held = {"schema": "dc-collector-daily-receipt-v1", "outcome": "HOLD", "httpStatus": 0,
                "generation": 0, "notBefore": self.now.timestamp()+10, "error": 0, "stateError": 0}
        self.assertEqual(pipeline.hold_seconds(held, self.now, 100), 11)
        self.assertIsNone(pipeline.hold_seconds(dict(held, notBefore=self.now.timestamp()+300), self.now, 600))
        self.assertIsNone(pipeline.hold_seconds(held, self.now, 20))
        for field, value in (("outcome", "FAILED"), ("httpStatus", 304), ("generation", 4), ("stateError", 13)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                pipeline.hold_seconds(dict(held, **{field: value}), self.now, 600)

    def config(self, directory):
        return {"outputRoot": str(directory), "firstDailyLocal": "2026-10-13T12:00:00+00:00",
            "smokeLocal": "2026-10-12T12:00:00+00:00", "collectorExe": "fake-collector", "signerExe": "fake-signer",
            "manifestFile": "fake-manifest", "stateRoot": "fake-state", "fingerprint": "a" * 64,
            "publicKeyFile": "fake-public", "ghExe": "fake-gh",
            "repositoryRoot": str(self.workspace.repositoryRoot)}

    def budget(self, receipts, *, sign_failure=False, verify_stdout=b"", verify_fail_mode=None):
        test = self

        class FakeBudget:
            def __init__(self):
                self.calls = []
                self.sign_failure = sign_failure
                self.verify_stdout = verify_stdout
                self.verify_fail_mode = verify_fail_mode

            def remaining(self, maximum=600):
                return maximum

            def run(self, argv):
                self.calls.append(argv)
                if argv[0] == "fake-collector":
                    code, receipt = receipts.pop(0)
                    pipeline.write_new(Path(argv[-1]), pipeline.canonical(receipt))
                    return code, b"", b""
                if argv[1] == "--distribution-sign":
                    if self.sign_failure:
                        return 2, b"", b""
                    pipeline.write_new(Path(argv[4]), envelope(pipeline.read(Path(argv[2])), test.scope["keyId"]))
                if argv[1] in {"--distribution-verify", "--distribution-verify-history"}:
                    return (2 if argv[1] == self.verify_fail_mode else 0), self.verify_stdout, b""
                return 0, b"", b""
        return FakeBudget()

    def test_public_verify_stdout_ignored_for_current_and_history(self):
        """実consumerは新しい公開factsのstdoutを解析せず、両modeを終了値で判定する。"""
        self.publisher().publish(self.bundle()[0])
        receipt = dict(self.receipt, generation=5, previousReceiptSha256="9" * 64)
        public_facts = (b"LOCAL_INDEX_RESULT code=0x00000000 stage=0 observed=0x00000000 created=0 protected=0\n"
                        b"LOCAL_INDEX_PUBLIC fingerprint=" + b"a" * 64 +
                        b" keyId=distribution-index-" + b"a" * 32 +
                        b" bytes=411 publicOnly=1 privateKeyQueried=0\n")
        for stdout in (public_facts, b"arbitrary stdout is not an authorization\n"):
            with self.subTest(stdout=stdout), tempfile.TemporaryDirectory() as directory:
                budget = self.budget([(0, receipt)], verify_stdout=stdout)
                with patch.object(pipeline, "utc", return_value=self.now):
                    result = pipeline.run_pipeline(self.config(Path(directory)), self.scope, "f" * 64,
                                                   budget=budget, remote=self.remote)
                self.assertEqual(result["status"], "PUBLISHED")
                verifies = [argv for argv in budget.calls if argv[1].startswith("--distribution-verify")]
                self.assertEqual({argv[1] for argv in verifies},
                                 {"--distribution-verify", "--distribution-verify-history"})
                for argv in verifies:
                    self.assertEqual(argv[4:6], ["fake-public", "a" * 64])
                    if argv[1] == "--distribution-verify-history":
                        self.assertEqual(argv[6], str(int(self.now.timestamp())))
                    else:
                        self.assertEqual(len(argv), 6)

    def test_public_verify_nonzero_rejected_for_current_and_history(self):
        """成功らしいstdoutでもnonzeroの実consumer判定を通さない。"""
        for mode in ("--distribution-verify", "--distribution-verify-history"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                self.remote = FakeRemote()
                self.publisher().publish(self.bundle()[0])
                original_head = self.remote.head
                receipt = dict(self.receipt, generation=5, previousReceiptSha256="9" * 64)
                budget = self.budget([(0, receipt)], verify_stdout=b"LOCAL_INDEX_PUBLIC publicOnly=1 privateKeyQueried=0\n",
                                     verify_fail_mode=mode)
                with patch.object(pipeline, "utc", return_value=self.now), self.assertRaisesRegex(
                        ValueError, "NATIVE_DISTRIBUTION_VERIFY_FAILED"):
                    pipeline.run_pipeline(self.config(Path(directory)), self.scope, "f" * 64,
                                          budget=budget, remote=self.remote)
                self.assertFalse(any(Path(directory).glob("*.success.json")))
                self.assertEqual(self.remote.head, original_head)
                self.assertTrue(any(argv[1] == mode for argv in budget.calls))

    def test_pipeline_real_code_fake_boundaries_resume_same_day(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            budget = self.budget([(0, self.receipt)], sign_failure=True)
            with patch.object(pipeline, "utc", return_value=self.now), self.assertRaisesRegex(ValueError, "SIGNATURE_FAILED"):
                pipeline.run_pipeline(config, self.scope, "f" * 64, budget=budget, remote=self.remote)
            self.assertFalse(any(Path(directory).glob("*.success.json")))
            budget.sign_failure = False
            with patch.object(pipeline, "utc", return_value=self.now + timedelta(seconds=60)):
                result = pipeline.run_pipeline(config, self.scope, "f" * 64, budget=budget, remote=self.remote)
                calls = len(budget.calls)
                second = pipeline.run_pipeline(config, self.scope, "f" * 64, budget=budget, remote=self.remote)
            self.assertEqual(result, second)
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(len(budget.calls), calls)
            self.assertEqual(len([argv for argv in budget.calls if argv[0] == "fake-collector"]), 1)

    def test_no_network_hold_failed_are_not_new_publications(self):
        cases = [(0, {"outcome": "NO_NETWORK"}), (2, {"outcome": "FAILED", "httpStatus": 304, "error": 13}),
                 (3, {"schema": "dc-collector-daily-receipt-v1", "outcome": "HOLD", "httpStatus": 0,
                      "generation": 0, "notBefore": self.now.timestamp()+86400, "error": 0, "stateError": 0})]
        for code, receipt in cases:
            with self.subTest(outcome=receipt["outcome"]), tempfile.TemporaryDirectory() as directory:
                config, budget = self.config(Path(directory)), self.budget([(code, receipt)])
                with patch.object(pipeline, "utc", return_value=self.now):
                    if code == 2:
                        with self.assertRaisesRegex(ValueError, "COLLECTION_FAILED"):
                            pipeline.run_pipeline(config, self.scope, "f" * 64, budget=budget, remote=self.remote)
                    else:
                        result = pipeline.run_pipeline(config, self.scope, "f" * 64, budget=budget, remote=self.remote)
                        self.assertEqual(result["status"], receipt["outcome"])
                self.assertEqual(self.remote.events, [])
                self.assertEqual(len(budget.calls), 1)

    def test_hold_wait_only_once_and_no_state_reset(self):
        held = {"schema": "dc-collector-daily-receipt-v1", "outcome": "HOLD", "httpStatus": 0,
                "generation": 0, "notBefore": self.now.timestamp()+10, "error": 0, "stateError": 0}
        with tempfile.TemporaryDirectory() as directory:
            budget = self.budget([(3, held), (3, held)])
            with patch.object(pipeline, "utc", return_value=self.now), patch.object(pipeline.time, "sleep") as sleep:
                result = pipeline.run_pipeline(self.config(Path(directory)), self.scope, "f" * 64,
                                               budget=budget, remote=self.remote)
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(sleep.call_args_list, [unittest.mock.call(11)])
            self.assertEqual(len(list(Path(directory).glob("*.collection-*.json"))), 2)
            with pipeline.exclusive(Path(directory) / "pipeline.lock"):
                with self.assertRaisesRegex(ValueError, "ALREADY_RUNNING"):
                    with pipeline.exclusive(Path(directory) / "pipeline.lock"):
                        self.fail("lock conflict accepted")
            with pipeline.exclusive(Path(directory) / "pipeline.lock"):
                pass

    def test_task_xml_finite_hidden_interactive_no_password_or_retry(self):
        config = self.config(self.workspace.repositoryRoot / "work/analysis/artificial-task229")
        config["stateRoot"] = str(self.workspace.stateRoot)
        config["pythonExe"] = __import__("sys").executable
        config_path = self.workspace_fixture.root / "control/artificial-task229/config.json"
        raw = pipeline.task_xml(config, config_path, "S-1-5-21-111-222-333-1001")
        tree = ET.fromstring(raw)
        ns = {"t": pipeline.TASK_NS}
        get = lambda path: tree.find(path, ns).text
        self.assertEqual(get("t:Principals/t:Principal/t:LogonType"), "InteractiveToken")
        self.assertEqual(get("t:Principals/t:Principal/t:RunLevel"), "HighestAvailable")
        self.assertEqual(get("t:Settings/t:MultipleInstancesPolicy"), "IgnoreNew")
        self.assertEqual(get("t:Settings/t:ExecutionTimeLimit"), "PT30M")
        self.assertEqual(get("t:Settings/t:StartWhenAvailable"), "true")
        self.assertEqual(get("t:Settings/t:Hidden"), "true")
        self.assertTrue(get("t:Actions/t:Exec/t:Command").endswith("pythonw.exe"))
        self.assertTrue(get("t:Actions/t:Exec/t:Arguments").startswith("-I "))
        self.assertEqual(get("t:Actions/t:Exec/t:WorkingDirectory"), str(self.workspace.repositoryRoot))
        start = pipeline.parse_time(get("t:Triggers/t:CalendarTrigger/t:StartBoundary"))
        end = pipeline.parse_time(get("t:Triggers/t:CalendarTrigger/t:EndBoundary"))
        self.assertEqual(end-start, timedelta(days=6, minutes=31))
        self.assertNotIn(b"RestartOnFailure", raw)
        self.assertNotIn(b"Password", raw)
        with self.assertRaisesRegex(ValueError, "CURRENT_USER_SID"):
            pipeline.task_xml(config, config_path, "S-1-5-18")
        smoke = pipeline.task_xml(config, config_path, "S-1-5-21-111-222-333-1001", smoke=True)
        self.assertIn(b"TimeTrigger", smoke)
        self.assertNotIn(b"CalendarTrigger", smoke)

    def test_report_keeps_fixed_denominator_and_missed_days(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(pipeline, "utc", return_value=self.now + timedelta(days=9)):
                result = pipeline.report(self.config(Path(directory)))
            self.assertEqual(result["denominator"], 7)
            self.assertEqual(len(result["days"]), 7)
            self.assertTrue(all(row["status"] == "NOT_RUN" for row in result["days"]))
            self.assertTrue(result["smokeExcluded"])
            self.assertIsNone(result["lockExecutionObserved"])


class ProtectedPolicyTests(unittest.TestCase):
    """低権限主体が署名入力/receiptを改変できるACLを許可しない。OS変更なし。"""
    def test_exact_owner_dacl_and_write_rights(self):
        safe = ("S-1-5-32-544", True, [(0, 0, 0x1f01ff, "S-1-5-18"),
                                    (0, 0, 0x1f01ff, "S-1-5-32-544"),
                                    (0, 0, 0x1200a9, "S-1-5-32-545")])
        pipeline.check_acl(safe, require_protected=True)
        for rights in (2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000):
            with self.subTest(rights=rights), self.assertRaisesRegex(ValueError, "GENERAL_USER_WRITE"):
                pipeline.check_acl((safe[0], True, safe[2] + [(0, 0, rights, "S-1-5-32-545")]))
        with self.assertRaisesRegex(ValueError, "PROTECTED_OWNER"):
            pipeline.check_acl(("S-1-5-21-111-222-333-1001", True, safe[2]))
        with self.assertRaisesRegex(ValueError, "DACL_REQUIRED"):
            pipeline.check_acl((safe[0], False, safe[2]), require_protected=True)
        pipeline.check_acl((safe[0], True, safe[2] + [(0, 0, 4, "S-1-5-32-545")]), ancestor=True)
        with self.assertRaisesRegex(ValueError, "GENERAL_USER_WRITE"):
            pipeline.check_acl((safe[0], True, safe[2] + [(0, 0, 0x40, "S-1-5-32-545")]), ancestor=True)
        with self.assertRaisesRegex(ValueError, "ACE_KIND"):
            pipeline.check_acl((safe[0], True, safe[2] + [(5, 0, 0, "")]))

    def test_unprotected_operation_and_reparse_rejected(self):
        with self.assertRaisesRegex(ValueError, "PROTECTED_OPERATION_ROOT"):
            pipeline.operation_root(Path(tempfile.gettempdir()))
        with patch.object(Path, "is_junction", return_value=True), self.assertRaisesRegex(ValueError, "REPARSE"):
            pipeline.normal_path(tempfile.gettempdir())

    def test_same_byte_resume_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            pipeline.keep_exact(path, b"artificial")
            pipeline.keep_exact(path, b"artificial")
            with self.assertRaisesRegex(ValueError, "RESUME_BYTES_CONFLICT"):
                pipeline.keep_exact(path, b"tampered")
            with self.assertRaises(FileExistsError):
                pipeline.write_new(path, b"replacement")


class DiagnosticBudget:
    """人工の有限戻り値/例外だけを順に返す。argvはRAM内の順序確認に限る。"""

    def __init__(self, outcomes):
        """借用した人工結果列を複製し、実processを起動しない境界を初期化する。"""
        self.outcomes = list(outcomes)
        self.calls = []

    def run(self, argv, data=None, maximum=pipeline.MAX_FILE, seconds=600):
        """一つの人工結果を消費し、失敗例外も同じobjectのまま伝播する。"""
        self.calls.append((list(argv), data, maximum, seconds))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class GitHubFailureTests(unittest.TestCase):
    """ADR0359の固定E01–E08。秘密は人工markerだけを使い、通信と実Task操作を行わない。"""

    def setUp(self):
        """Budgetのcwdに必要な明示承認を人工fileとACLだけで用意する。"""
        self.workspace_fixture = self.enterContext(workspace_fixture())

    def failed_call(self, outcome, method="GET", path="user", **kwargs):
        """実GitHub共通境界へfake Budgetを渡し、捕捉した元例外と呼出しを返す。"""
        budget = DiagnosticBudget([outcome])
        remote = pipeline.GitHub("fake-gh", budget)
        with self.assertRaises(Exception) as caught:
            remote.api(method, path, **kwargs)
        return caught.exception, budget

    def main_failure(self, directory, failure, *, ordinal=1):
        """実mainの保存と終了値を人工config/worker例外で確認し、stdoutとterminalを返す。"""
        config = {"outputRoot": str(directory), "firstDailyLocal": "2026-10-13T12:00:00+00:00"}
        output = io.StringIO()
        with patch.object(pipeline, "load_config", return_value=(config, {}, "f" * 64)), \
                patch.object(pipeline, "run_pipeline", side_effect=failure), \
                patch.object(pipeline, "utc", return_value=pipeline.parse_time("2026-10-13T12:30:00Z")), \
                patch.object(pipeline.time, "time_ns", return_value=ordinal), \
                patch.object(pipeline.sys, "argv", ["daily_index_pipeline.py", "run", str(directory / "config.json")]), \
                redirect_stdout(output):
            code = pipeline.main()
        raw = pipeline.read(directory / f"20261013.terminal-{ordinal}.json")
        self.assertEqual(json.loads(output.getvalue()), json.loads(raw))
        return code, raw

    def test_e01_success_binary_and_legacy_404_compatibility(self):
        """既存JSON/binary成功とASCII404分岐を保ち、ordinalだけを順に進める。"""
        budget = DiagnosticBudget([(0, b'{"ok":true}', b""),
            (1, b"not json", b"gh: artificial missing (HTTP 404) (HTTP 500)"),
            (0, b"\x00binary", b"")])
        remote = pipeline.GitHub("fake-gh", budget)
        self.assertEqual(remote.api("GET", "user"), {"ok": True})
        with self.assertRaises(pipeline.Missing):
            remote.api("GET", pipeline.API + "/git/ref/heads/driver-index")
        self.assertEqual(remote.api("GET", pipeline.API + "/releases/assets/3", binary=True), b"\x00binary")
        self.assertEqual(remote.ordinal, 3)
        self.assertEqual(len(budget.calls), 3)
        self.assertTrue(all(call[3] == 30 for call in budget.calls))
        self.assertFalse(budget.outcomes)

    def test_e02_nonzero_cli_reported_status_and_null(self):
        """子非0と限定CLI整数を保持し、競合/未認識/過大出力からHTTP応答を推定しない。"""
        cases = [(b"gh: forbidden (HTTP 403)", 403), (b"(HTTP 429)\n(HTTP 429)", 429),
                 (b"(HTTP 401) (HTTP 503)", None), (b"(HTTP 403) (HTTP 700)", None),
                 (b"(HTTP 099)", None), (b"(HTTP 600)", None), (b"HTTP 403", None),
                 (b"local cli failure", None), (b"", None),
                 (b"x" * 65537 + b"(HTTP 403)", None)]
        for stderr, status in cases:
            with self.subTest(length=len(stderr), status=status):
                failure, budget = self.failed_call((17, b"ignored", stderr))
                self.assertIs(type(failure), ValueError)
                self.assertEqual(str(failure), "GITHUB_REQUEST_FAILED")
                detail = pipeline.safe_github_failure(failure.github_failure)
                self.assertEqual(detail["stage"], "CLI_EXIT")
                self.assertEqual(detail["childExitCode"], 17)
                self.assertEqual(detail["cliReportedHttpStatus"], status)
                self.assertEqual(detail["httpStatusSource"], "UNKNOWN" if status is None else "CLI_REPORTED")
                self.assertEqual(detail["remoteWriteOutcome"], "UNKNOWN")
                self.assertFalse(detail["outerTimeout"])
                self.assertEqual(len(budget.calls), 1)

    def test_e03_budget_timeout_output_limit_and_oserror_observation(self):
        """実Budgetの有限監視をprocess fakeで通し、起動前FS例外をspawnと断定しない。"""
        class Process:
            """外側監視を一回で止める人工process。実子PIDを持たない。"""

            def __init__(self):
                """終了処理の呼出し数だけを初期化する。"""
                self.killed = 0
                self.waited = 0

            def poll(self):
                """監視対象が未終了である人工値を返す。"""
                return None

            def kill(self):
                """人工終了の要求回数を保持する。"""
                self.killed += 1

            def wait(self, timeout):
                """人工終了待ちの有限値を確認して戻る。"""
                assert timeout == 10
                self.waited += 1
                return -9

        for reason, expected_stage in (("PROCESS_TIMEOUT", "BUDGET_TIMEOUT"),
                                       ("PROCESS_OUTPUT_LIMIT", "BUDGET_OUTPUT_LIMIT")):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as name:
                budget = pipeline.Budget()
                budget.directory = Path(name)
                process = Process()
                times = [0, 2] if reason == "PROCESS_TIMEOUT" else [0, 0]
                oversized = type("Stat", (), {"st_size": pipeline.MAX_FILE + 1})()
                with patch.object(pipeline, "operation_root"), \
                        patch.object(budget, "remaining", return_value=1), \
                        patch.object(pipeline.time, "monotonic", side_effect=times), \
                        patch.object(pipeline.subprocess, "Popen", return_value=process), \
                        patch.object(pipeline.os, "fstat", return_value=oversized):
                    with self.assertRaisesRegex(ValueError, reason) as caught:
                        pipeline.GitHub("fake-gh", budget).api("POST", "graphql", {"fake": True})
                detail = caught.exception.github_failure
                self.assertEqual(detail["stage"], expected_stage)
                self.assertEqual(detail["outerTimeout"], reason == "PROCESS_TIMEOUT")
                self.assertIsNone(detail["childExitCode"])
                self.assertIsNone(detail["cliReportedHttpStatus"])
                self.assertEqual(detail["remoteWriteOutcome"], "UNKNOWN")
                self.assertEqual((process.killed, process.waited), (1, 1))
        with tempfile.TemporaryDirectory() as name:
            budget = pipeline.Budget()
            budget.directory = Path(name)
            failure = OSError("ArtificialFsSecret231=not-spawn")
            with patch.object(pipeline, "operation_root"), \
                    patch.object(pipeline.tempfile, "TemporaryFile", side_effect=failure), \
                    patch.object(pipeline.subprocess, "Popen") as spawn:
                with self.assertRaises(OSError) as caught:
                    pipeline.GitHub("fake-gh", budget).api("GET", "user")
            self.assertIs(caught.exception, failure)
            self.assertEqual(failure.github_failure["stage"], "BUDGET_EXCEPTION")
            self.assertIsNone(failure.github_failure["childExitCode"])
            self.assertFalse(failure.github_failure["outerTimeout"])
            spawn.assert_not_called()

    def test_e04_parse_failure_and_write_outcome_unknown(self):
        """GET/POST/PATCH/CASのparse拒否で元例外を保ち、書込み成否をUNKNOWNに残す。"""
        for method, path in (("GET", "user"), ("POST", pipeline.API + "/releases"),
                             ("PATCH", pipeline.API + "/releases/7"), ("POST", "graphql")):
            with self.subTest(method=method, path=path):
                failure, _ = self.failed_call((0, b"ArtificialRawSecret231=bad-json", b""), method, path)
                self.assertIs(type(failure), pipeline.cr.RegistryError)
                self.assertEqual(str(failure), "JSON_ENCODING_OR_SYNTAX")
                self.assertEqual(failure.github_failure["stage"], "RESPONSE_PARSE")
                self.assertEqual(failure.github_failure["childExitCode"], 0)
                self.assertEqual(failure.github_failure["remoteWriteOutcome"], "UNKNOWN")
                self.assertIsNone(failure.github_failure["cliReportedHttpStatus"])
        budget = DiagnosticBudget([(0, b"{}", b""), (5, b"", b"response lost")])
        remote = pipeline.GitHub("fake-gh", budget)
        remote.api("POST", pipeline.API + "/releases", {"artificial": True})
        with self.assertRaisesRegex(ValueError, "GITHUB_REQUEST_FAILED") as caught:
            remote.api("GET", pipeline.API + "/releases/7")
        self.assertEqual(caught.exception.github_failure["ordinal"], 2)
        self.assertEqual(caught.exception.github_failure["remoteWriteOutcome"], "UNKNOWN")

    def test_e05_fixed_api_and_strict_schema_type_ranges(self):
        """全既存routeを有限用途へ写し、不正な診断型/範囲/未知fieldを保存入口で落とす。"""
        routes = [("GET", "user", "USER_READ"), ("GET", pipeline.API, "REPOSITORY_READ"),
            ("GET", pipeline.API + "/git/ref/heads/driver-index", "INDEX_REF_READ"),
            ("GET", pipeline.API + "/releases/tags/index-v1-20261013-" + "a" * 64, "RELEASE_LOOKUP"),
            ("GET", pipeline.API + "/releases/assets/7", "ASSET_READ"),
            ("POST", pipeline.API + "/releases", "RELEASE_CREATE"),
            ("POST", "https://uploads.github.com/" + pipeline.API + "/releases/7/assets?name=index.json.gz", "ASSET_UPLOAD"),
            ("POST", "https://uploads.github.com/" + pipeline.API + "/releases/7/assets?name=manifest.json", "ASSET_UPLOAD"),
            ("GET", pipeline.API + "/releases/7", "RELEASE_READ"),
            ("PATCH", pipeline.API + "/releases/7", "RELEASE_UPDATE"),
            ("GET", pipeline.API + "/git/commits/" + "a" * 40, "INDEX_COMMIT_READ"),
            ("GET", pipeline.API + "/git/trees/" + "a" * 40 + "?recursive=1", "INDEX_TREE_READ"),
            ("GET", pipeline.API + "/git/blobs/" + "a" * 40, "INDEX_BLOB_READ"),
            ("POST", pipeline.API + "/git/blobs", "INDEX_BLOB_CREATE"),
            ("POST", pipeline.API + "/git/trees", "INDEX_TREE_CREATE"),
            ("POST", pipeline.API + "/git/commits", "INDEX_COMMIT_CREATE"),
            ("POST", "graphql", "INDEX_REF_CAS"),
            ("DELETE", pipeline.API + "/artificial-unknown", "UNKNOWN")]
        budget = DiagnosticBudget([(2, b"", b"")] * len(routes))
        remote = pipeline.GitHub("fake-gh", budget)
        for ordinal, (method, path, purpose) in enumerate(routes, 1):
            with self.subTest(purpose=purpose), self.assertRaises(ValueError) as caught:
                remote.api(method, path, b"artificial-route" if purpose == "ASSET_UPLOAD" else None,
                    content_type="application/gzip" if purpose == "ASSET_UPLOAD" and path.endswith("index.json.gz")
                    else "application/json")
            detail = pipeline.safe_github_failure(caught.exception.github_failure)
            self.assertEqual((detail["api"], detail["ordinal"]), (purpose, ordinal))
            self.assertEqual(detail["method"], "UNKNOWN" if method == "DELETE" else method)
        valid = pipeline.github_failure("GET", "user", 1, "CLI_EXIT", code=1, stderr=b"(HTTP 403)")
        class Text(str):
            """厳密なstr検証を確認する人工subclass。"""
        invalid = [dict(valid, extra="ArtificialSchemaSecret231=value")]
        changes = {"schema": ["ArtificialSchemaSecret231=value", Text(valid["schema"])],
            "api": ["https://artificial.invalid/private", "RELEASE_CREATE"], "method": ["secret", "POST"],
            "ordinal": [True, False, 0, 97, 1.0, "1", None], "stage": ["SPAWN", "RESPONSE_PARSE"],
            "childExitCode": [True, 0, -2147483649, 4294967296, "1"], "outerTimeout": [1, None, True],
            "cliReportedHttpStatus": [True, 99, 600, "403", None],
            "httpStatusSource": ["WIRE", "UNKNOWN", Text("CLI_REPORTED")],
            "remoteWriteOutcome": ["SUCCEEDED", "NOT_STARTED", None]}
        for key, values in changes.items():
            invalid.extend(dict(valid, **{key: value}) for value in values)
        invalid.extend([None, [], "ArtificialSchemaSecret231=value", {key: value for key, value in valid.items() if key != "api"}])
        for position, value in enumerate(invalid):
            with self.subTest(position=position):
                self.assertIsNone(pipeline.safe_github_failure(value))
                saved = pipeline.result_with_safe_github_failure({"status": "FAILED", "githubFailure": value})
                self.assertEqual(saved, {"status": "FAILED"})
        for code in (-2147483648, 4294967295):
            self.assertEqual(pipeline.github_failure("GET", "user", 96, "CLI_EXIT", code=code)["childExitCode"], code)
        filtered = pipeline.safe_github_failure(valid)
        filtered["api"] = "UNKNOWN"
        self.assertEqual(valid["api"], "USER_READ")

    def test_e06_free_text_and_hostile_metadata_never_persist(self):
        """raw出力/自由文/任意属性と悪意診断を実main/reportの保存へ混入させない。"""
        marker = "ArtificialSecret231=token-cookie-url-output"
        failure, _ = self.failed_call((3, marker.encode(), (marker + " (HTTP 403)").encode()),
                                     "POST", pipeline.API + "/" + marker, body={"token": marker})
        failure.extra = {"secret": marker}
        self.assertNotIn(marker.encode(), pipeline.canonical(failure.github_failure))
        for hostile in (False, True):
            with self.subTest(hostile=hostile), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                candidate = OSError(marker) if hostile else failure
                candidate.extra = {"secret": marker}
                if hostile:
                    candidate.github_failure = dict(failure.github_failure, unknown={"secret": marker})
                code, raw = self.main_failure(directory, candidate)
                self.assertEqual(code, 2)
                self.assertNotIn(marker.encode(), raw)
                result = json.loads(raw)
                self.assertEqual(result["reason"], "PIPELINE_EXCEPTION" if hostile else "GITHUB_REQUEST_FAILED")
                self.assertEqual("githubFailure" in result, not hostile)
                config = {"outputRoot": str(directory), "firstDailyLocal": "2026-10-13T12:00:00+00:00"}
                with patch.object(pipeline, "operation_root"), patch.object(pipeline, "utc", return_value=pipeline.parse_time("2026-10-14T00:00:00Z")):
                    reported = pipeline.report(config)
                self.assertNotIn(marker.encode(), pipeline.canonical(reported))
                self.assertEqual(reported["days"][0]["status"], "FAILED")
                if hostile:
                    # 既存file内の不正診断もreport入口で省略し、原byteを変更しない。
                    bad = directory / "20261013.terminal-2.json"
                    bad_raw = pipeline.canonical(dict(result, githubFailure=candidate.github_failure))
                    pipeline.write_new(bad, bad_raw)
                    with patch.object(pipeline, "operation_root"), patch.object(pipeline, "utc", return_value=pipeline.parse_time("2026-10-14T00:00:00Z")):
                        cleaned = pipeline.report(config)
                    self.assertNotIn(marker.encode(), pipeline.canonical(cleaned))
                    self.assertEqual(pipeline.read(bad), bad_raw)

    def test_e07_real_main_pipeline_report_and_old_failed_preserved(self):
        """実main→pipeline→GitHub境界→七日reportを非通信fakeで通し、原失敗attemptを保つ。"""
        fixture = PipelineTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            config = fixture.config(directory)
            native = fixture.budget([(0, fixture.receipt)])
            gh_calls = []
            def dispatch(budget, argv, data=None, **kwargs):
                """nativeとGitHub両境界を人工結果に限定し、実coordinatorの呼出しを通す。"""
                if argv[0] == "fake-gh":
                    gh_calls.append((argv, data, kwargs))
                    return 4, b"ArtificialMainRaw231=not-retained", b"gh: artificial authentication (HTTP 401)"
                return native.run(argv)
            prefix = directory / fixture.now.strftime("%Y%m%d")
            original = Path(str(prefix) + ".terminal-000.json")
            old_raw = pipeline.canonical({"status": "FAILED", "reason": "GITHUB_REQUEST_FAILED", "configSha256": "e" * 64})
            pipeline.write_new(original, old_raw)
            output = io.StringIO()
            with patch.object(pipeline, "load_config", return_value=(config, fixture.scope, "f" * 64)), \
                    patch.object(pipeline, "utc", return_value=fixture.now), \
                    patch.object(pipeline.Budget, "run", autospec=True, side_effect=dispatch), \
                    patch.object(pipeline.time, "time_ns", return_value=999), \
                    patch.object(pipeline.sys, "argv", ["daily_index_pipeline.py", "run", str(directory / "config.json")]), \
                    redirect_stdout(output):
                code = pipeline.main()
                observed = pipeline.report(config)
            self.assertEqual(code, 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["reason"], "GITHUB_REQUEST_FAILED")
            self.assertEqual(result["githubFailure"]["api"], "USER_READ")
            self.assertEqual(result["githubFailure"]["ordinal"], 1)
            self.assertEqual(result["githubFailure"]["childExitCode"], 4)
            self.assertEqual(result["githubFailure"]["httpStatusSource"], "CLI_REPORTED")
            self.assertEqual(result["githubFailure"]["remoteWriteOutcome"], "UNKNOWN")
            self.assertEqual(observed["denominator"], 7)
            self.assertEqual(len(observed["days"]), 7)
            self.assertEqual(observed["days"][0]["status"], "FAILED")
            self.assertEqual(len(observed["days"][0]["attempts"]), 2)
            self.assertEqual(observed["days"][0]["attempts"][0], json.loads(old_raw))
            self.assertEqual(observed["days"][0]["attempts"][1], result)
            self.assertEqual(observed["days"][0]["githubFailure"], result["githubFailure"])
            self.assertEqual(pipeline.read(original), old_raw)
            self.assertFalse(list(directory.glob("*.success.json")))
            self.assertEqual(len(gh_calls), 1)
            self.assertEqual(gh_calls[0][2], {"seconds": 30})
            self.assertNotIn(b"ArtificialMainRaw231", pipeline.canonical(observed))

    def test_e08_budget_rejections_keep_original_reason_and_limits(self):
        """実Budgetの回数/期限拒否を元reasonで伝播し、新しいprocessやretryを始めない。"""
        for reason in ("PROCESS_COUNT", "TOTAL_TIMEOUT"):
            budget = pipeline.Budget()
            if reason == "PROCESS_COUNT":
                budget.calls = 96
            else:
                budget.end = 0
            with self.subTest(reason=reason), patch.object(pipeline.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(ValueError, reason) as caught:
                    pipeline.GitHub("fake-gh", budget).api("GET", "user")
            self.assertEqual(str(caught.exception), reason)
            self.assertEqual(caught.exception.github_failure["stage"],
                             "BUDGET_TIMEOUT" if reason == "TOTAL_TIMEOUT" else "BUDGET_EXCEPTION")
            self.assertIsNone(caught.exception.github_failure["childExitCode"])
            self.assertEqual(budget.calls, 97 if reason == "PROCESS_COUNT" else 1)
            spawn.assert_not_called()


class DistributionAcquisitionAuditTests(unittest.TestCase):
    """ADR0363の固定A01〜A22を人工束で検査し、旧test分母を変更しない。"""

    def setUp(self):
        """既存fixtureをmodule経由で借用し、TestCaseの新たな再発見を避ける。"""
        import test_project_collected_native_index as fixture_module
        fixture = fixture_module.DistributionProjectionTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.now = fixture.now
        self.documents = {name: deepcopy(getattr(fixture, name)) for name in
                          ("scope", "evidence", "release", "inspection", "review", "script")}
        self.inputs = self.encode(self.documents)
        self.pins = {name: pipeline.sha(raw) for name, raw in self.inputs.items()}
        self.raw_index, self.packed, self.raw_manifest, self.projection_report = self.project()
        self.bundle = {"index.json.gz": self.packed,
                       "manifest.json": envelope(self.raw_manifest, pipeline.projection.DISTRIBUTION_KEY_ID)}

    @staticmethod
    def encode(documents):
        """人工JSONを原byteへ一度変換し、caller側のpin計算と分離する。"""
        return {name: pipeline.canonical(value) for name, value in documents.items()}

    def project(self, documents=None, generation=9):
        """既存P1だけで人工出力を作り、producerの処理を複製しない。"""
        values = self.documents if documents is None else documents
        return pipeline.projection.project_distribution_acquisition(
            **values, generation=generation, now=self.now)

    def audit(self, **changes):
        """変更指定以外は固定人工入力を渡し、実serviceを注入しない。"""
        args = dict(bundle=self.bundle, inputs=self.inputs, input_pins=self.pins,
                    generation=9, published_at=self.now, now=self.now)
        args.update(changes)
        return pipeline.audit_distribution_acquisition_bundle(**args)

    def reject(self, label, code, **changes):
        """有限subcaseの実拒否reasonを固定期待値と完全一致で照合する。"""
        with self.subTest(variant=label, expected=code):
            with self.assertRaises(ValueError) as caught:
                self.audit(**changes)
            self.assertEqual(str(caught.exception), code)

    def changed_projection(self, documents):
        """negativeにも整合するP1 byteとcaller pinを作り、privacyまで到達させる。"""
        inputs = self.encode(documents)
        _, packed, manifest, _ = self.project(documents)
        return dict(bundle={"index.json.gz": packed, "manifest.json": envelope(
            manifest, pipeline.projection.DISTRIBUTION_KEY_ID)}, inputs=inputs,
            input_pins={name: pipeline.sha(raw) for name, raw in inputs.items()})

    def modified_index(self, record):
        """出力だけを改変し、record hashとgzipを揃えても原投影と相違させる。"""
        import gzip
        index = json.loads(self.raw_index)
        record_raw = pipeline.canonical(record)
        index["records"][0].update(recordBytesBase64=base64.b64encode(record_raw).decode("ascii"),
                                   recordSha256=pipeline.sha(record_raw))
        packed = gzip.compress(pipeline.canonical(index), mtime=0)
        manifest = json.loads(self.raw_manifest)
        manifest["asset"].update(sizeBytes=len(packed), sha256=pipeline.sha(packed))
        return {"index.json.gz": packed, "manifest.json": envelope(
            b"\n" + pipeline.canonical(manifest), pipeline.projection.DISTRIBUTION_KEY_ID)}

    def test_a01_exact_public_leaf_and_caps(self):
        """A01。原byte/quality/入力不変と六入力の厳密な上限値での正例を保つ。"""
        before = deepcopy((self.bundle, self.inputs, self.pins))
        result = self.audit()
        self.assertEqual(result, json.loads(self.raw_manifest))
        self.assertEqual(result["quality"], dict(sourceCount=1, recordCount=1, metadataOnlyCount=0,
                                               contentInspectedCount=1, unconfirmedCount=0))
        self.assertEqual(before, (self.bundle, self.inputs, self.pins))
        self.assertIsNone(self.projection_report["actualDeviceCandidates"])
        # 空白も原byteの一部とし、各入力の最大値を一つずつ検証する。
        for name in self.inputs:
            maximum = 65536 if name in {"scope", "review"} else 1048576
            inputs = dict(self.inputs)
            inputs[name] += b" " * (maximum - len(inputs[name]))
            with self.subTest(boundary=name):
                self.assertEqual(self.audit(inputs=inputs, input_pins={key: pipeline.sha(raw)
                                 for key, raw in inputs.items()}), result)

    def test_a02_later_now_keeps_original_expiry(self):
        """A02。再確認の現在時刻だけを進め、原発行秒と元期限を動かさない。"""
        expected = self.audit()
        expiry = pipeline.parse_time(expected["expiresAtUtc"])
        for later in (self.now + timedelta(seconds=60), expiry - timedelta(seconds=1)):
            with self.subTest(now=later.isoformat()):
                self.assertEqual(self.audit(now=later), expected)
                self.assertEqual(self.bundle["index.json.gz"], self.packed)

    def test_a03_original_metadata_audit(self):
        """A03。元metadata専用入口は新helperを呼ばず、元byteのまま成功する。"""
        fixture = ProjectionTests()
        fixture.setUp()
        scope = dict(fixture.scope, keyId=pipeline.projection.DISTRIBUTION_KEY_ID)
        receipt = fixture.daily_receipt()
        _, packed, manifest, _ = pipeline.projection.project_daily(scope, receipt, fixture.now)
        bundle = {"index.json.gz": packed, "manifest.json": envelope(manifest, scope["keyId"])}
        with patch.object(pipeline, "audit_distribution_acquisition_bundle", side_effect=AssertionError("UNEXPECTED_NEW_CALL")):
            result = pipeline.audit_bundle(bundle, scope, receipt, fixture.now)
        self.assertEqual(result, json.loads(manifest))
        self.assertEqual(bundle["index.json.gz"], packed)

    def test_a04_asset_allowlist_and_byte_shape(self):
        """A04。第三asset、欠損、型違い、空、既存asset上限超過を拒否する。"""
        self.reject("extra", "ASSET_ALLOWLIST", bundle=dict(self.bundle, extra=b"any content"))
        for value in (None, [], "bundle"):
            self.reject("mapping-" + type(value).__name__, "ASSET_ALLOWLIST", bundle=value)
        for name in self.bundle:
            self.reject("missing-" + name, "ASSET_ALLOWLIST",
                        bundle={key: raw for key, raw in self.bundle.items() if key != name})
            maximum = pipeline.MAX_FILE if name.endswith(".gz") else 96 * 1024
            for label, raw in (("none", None), ("text", "bytes"), ("mutable", bytearray(b"x")),
                               ("view", memoryview(b"x")), ("empty", b""), ("oversize", b"x" * (maximum+1))):
                self.reject(name + "-" + label, "ACQUISITION_ASSET_BYTES", bundle=dict(self.bundle, **{name: raw}))

    def test_a05_raw_manifest_byte_and_envelope_shape(self):
        """A05。原manifest一byte差と外側schema/型/重複/長さの不整合を拒否する。"""
        changed = b" " + self.raw_manifest[1:]
        self.reject("raw-byte", "PUBLIC_PROJECTION_BYTES", bundle=dict(self.bundle,
                    **{"manifest.json": envelope(changed, pipeline.projection.DISTRIBUTION_KEY_ID)}))
        outer = json.loads(self.bundle["manifest.json"])
        for label, value, code in (("key", dict(outer, keyId="other"), "ACQUISITION_ENVELOPE_KEY"),
                                   ("unknown", dict(outer, extra="x"), "ENVELOPE_FIELDS"),
                                   ("schema", dict(outer, schema="other"), "ENVELOPE_SCHEMA"),
                                   ("type", dict(outer, signatureBase64=None), "ACQUISITION_ENVELOPE_TYPE"),
                                   ("signature", dict(outer, signatureBase64="AA=="), "ENVELOPE_SHAPE")):
            self.reject(label, code, bundle=dict(self.bundle, **{"manifest.json": pipeline.canonical(value)}))
        raw = self.bundle["manifest.json"][:-1] + b',"schema":"driver-index-envelope-v1"}'
        self.reject("duplicate", "DUPLICATE_JSON_KEY", bundle=dict(self.bundle, **{"manifest.json": raw}))

    def test_a06_gzip_byte(self):
        """A06。一gzip byte差を展開や署名の成功扱いにせず拒否する。"""
        packed = self.packed[:-1] + bytes([self.packed[-1] ^ 1])
        self.reject("gzip-byte", "PUBLIC_PROJECTION_BYTES", bundle=dict(self.bundle, **{"index.json.gz": packed}))

    def test_a07_scope_and_six_input_shape(self):
        """A07。pin済み未知scopeと六入力の有限な型/JSON/容量境界を拒否する。"""
        documents = deepcopy(self.documents)
        documents["scope"]["unknown"] = 1
        inputs = self.encode(documents)
        self.reject("unknown-scope", "DISTRIBUTION_SCOPE_FIELDS", inputs=inputs,
                    input_pins={name: pipeline.sha(raw) for name, raw in inputs.items()})
        for value in (None, [], "inputs"):
            self.reject("mapping-" + type(value).__name__, "ACQUISITION_INPUT_FIELDS", inputs=value)
        self.reject("extra-input", "ACQUISITION_INPUT_FIELDS", inputs=dict(self.inputs, extra=b"{}"))
        # 各原JSONについて同じ有限集合を回し、入力ごとの上限と重複拒否を保持する。
        for name in self.inputs:
            self.reject("missing-" + name, "ACQUISITION_INPUT_FIELDS",
                        inputs={key: raw for key, raw in self.inputs.items() if key != name})
            maximum = 65536 if name in {"scope", "review"} else 1048576
            variants = (("none", None, "ACQUISITION_INPUT_BYTES"),
                        ("text", "{}", "ACQUISITION_INPUT_BYTES"),
                        ("mutable", bytearray(b"{}"), "ACQUISITION_INPUT_BYTES"),
                        ("empty", b"", "ACQUISITION_INPUT_BYTES"),
                        ("oversize", b" " * (maximum+1), "ACQUISITION_INPUT_BYTES"),
                        ("list", b"[]", "ACQUISITION_INPUT_OBJECT"),
                        ("null", b"null", "ACQUISITION_INPUT_OBJECT"),
                        ("number", b"1", "ACQUISITION_INPUT_OBJECT"),
                        ("boolean", b"true", "ACQUISITION_INPUT_OBJECT"),
                        ("string", b'"text"', "ACQUISITION_INPUT_OBJECT"),
                        ("duplicate", b'{"x":1,"x":2}', "DUPLICATE_JSON_KEY"),
                        ("utf8", b"\xff", "JSON_ENCODING_OR_SYNTAX"),
                        ("syntax", b"{", "JSON_ENCODING_OR_SYNTAX"),
                        ("constant", b'{"x":NaN}', "JSON_CONSTANT"))
            for label, raw, code in variants:
                pins = dict(self.pins)
                if type(raw) is bytes:
                    pins[name] = pipeline.sha(raw)
                self.reject(name + "-" + label, code, inputs=dict(self.inputs, **{name: raw}), input_pins=pins)

    def test_a08_exact_six_pins(self):
        """A08。六pinの型/集合/全64桁と各原byteへの完全一致を要求する。"""
        for value in (None, [], "pins"):
            self.reject("mapping-" + type(value).__name__, "ACQUISITION_PIN_FIELDS", input_pins=value)
        self.reject("extra-pin", "ACQUISITION_PIN_FIELDS", input_pins=dict(self.pins, extra="0" * 64))
        for name in self.pins:
            self.reject("missing-" + name, "ACQUISITION_PIN_FIELDS",
                        input_pins={key: value for key, value in self.pins.items() if key != name})
            for label, value in (("bool", True), ("none", None), ("integer", 1), ("uppercase", "A" * 64),
                                 ("short", "a" * 63), ("long", "a" * 65), ("nonhex", "g" * 64),
                                 ("mismatch", "0" * 64)):
                self.reject(name + "-" + label, "ACQUISITION_INPUT_PIN", input_pins=dict(self.pins, **{name: value}))

    def test_a09_consistent_changed_output_cannot_replace_inspection_pin(self):
        """A09。選択公開IDと出力を同時に変えても元inspection pinを通さない。"""
        documents = deepcopy(self.documents)
        documents["inspection"]["infs"][0]["models"][0]["pnpIds"][0]["value"] = r"PCI\VEN_8086&DEV_0002"
        changed = self.changed_projection(documents)
        changed["input_pins"] = self.pins
        self.reject("changed-id-original-pin", "ACQUISITION_INPUT_PIN", **changed)

    def test_a10_public_id_outside_leaf(self):
        """A10。原投影と一致する製品名でも別fieldのPCI/USB/HIDを例外にしない。"""
        for value in (r"PCI\VEN_FA01&DEV_0001", r"USB\VID_FA01&PID_0001", r"HID\VID_FA01&PID_0001"):
            documents = deepcopy(self.documents)
            documents["evidence"]["records"][0]["displayTitle"] = value
            self.reject(value[:3], "PUBLIC_PRIVACY", **self.changed_projection(documents))

    def test_a11_secrets_before_public_id_neutralization(self):
        """A11。publisherと公開ID値にある人工secret/token/credentialを元dataで拒否する。"""
        values = ("password=artificial", "github_pat_artificial", "ghp_artificial", "Bearer artificial",
                  "cookie=artificial", "access_token=artificial", "credential=artificial",
                  "secret=artificial", "token=artificial", "-----BEGIN ARTIFICIAL")
        for value in values:
            for target in ("publisher", "public-id"):
                documents = deepcopy(self.documents)
                inf = documents["inspection"]["infs"][0]
                if target == "publisher":
                    inf["verifiedPublisher"] = value
                else:
                    inf["models"][0]["pnpIds"][0]["value"] = r"PCI\VEN_FA01&DEV_0001&" + value
                self.reject(target + "-" + value.split("=")[0], "PUBLIC_PRIVACY_SECRET",
                            **self.changed_projection(documents))

    def test_a12_local_absolute_and_unc_paths(self):
        """A12。公開IDのJSON escapeを理由にpublisherの絶対path/UNCを許可しない。"""
        for value in (r"C:\Artificial\local", "D:/Artificial/local", r"\\artificial\share\local"):
            documents = deepcopy(self.documents)
            documents["inspection"]["infs"][0]["verifiedPublisher"] = value
            self.reject(value[:2], "PUBLIC_PRIVACY", **self.changed_projection(documents))

    def test_a13_instance_and_serial_outside_leaf(self):
        """A13。元byteと一致しても製品名のinstance/serial情報を拒否する。"""
        for value in ("instanceId=artificial", "instance_id=artificial", "serialNumber=artificial", "serial_number=artificial"):
            documents = deepcopy(self.documents)
            documents["evidence"]["records"][0]["displayTitle"] = value
            self.reject(value.split("=")[0], "PUBLIC_PRIVACY", **self.changed_projection(documents))

    def test_a14_generation_exact_integer(self):
        """A14。Trueを含む非exact整数、ゼロ、負値、2^53以上を拒否する。"""
        for value in (True, False, 0, -1, 1.0, 4.5, "9", None, 9007199254740992):
            self.reject(repr(value), "ACQUISITION_GENERATION", generation=value)

    def test_a15_generation_bound_to_original_manifest(self):
        """A15。範囲内の別generationも原manifest/gzipの一致なしでは通さない。"""
        for value in (1, 3, 4, 8, 10, 9007199254740991):
            self.reject(str(value), "PUBLIC_PROJECTION_BYTES", generation=value)

    def test_a16_expiry_exclusive(self):
        """A16。元期限ちょうどと期限後を排他的に拒否する。"""
        expiry = pipeline.parse_time(json.loads(self.raw_manifest)["expiresAtUtc"])
        for value in (expiry, expiry + timedelta(seconds=1)):
            self.reject(value.isoformat(), "EXPIRY", now=value)

    def test_a17_publication_and_utc_seconds(self):
        """A17。未来発行と両時刻のtimezone欠損/非UTC/秒未満を拒否する。"""
        self.reject("future-publication", "ACQUISITION_PUBLICATION_TIME", published_at=self.now + timedelta(seconds=1))
        for field in ("published_at", "now"):
            for label, value in (("naive", self.now.replace(tzinfo=None)),
                                 ("offset", self.now.astimezone(pipeline.timezone(timedelta(hours=1)))),
                                 ("fraction", self.now.replace(microsecond=1)),
                                 ("none", None), ("string", self.now.isoformat())):
                self.reject(field + "-" + label, "ACQUISITION_UTC_SECONDS", **{field: value})

    def test_a18_old_content_time_not_rewritten(self):
        """A18。新観測より古い内容検査を再利用して期限を更新しない。"""
        documents = deepcopy(self.documents)
        observed = documents["evidence"]["lastSuccessfulValidationAt"]
        documents["evidence"]["lastSuccessfulValidationAt"] = observed + 16
        documents["release"]["observedUtcSeconds"] = str(observed + 16)
        documents["script"].update(pageObservedUtcSeconds=str(observed + 16), scriptObservedUtcSeconds=str(observed + 18))
        inputs = self.encode(documents)
        self.reject("old-content", "NATIVE_CONTENT_TIME", inputs=inputs,
                    input_pins={name: pipeline.sha(raw) for name, raw in inputs.items()})

    def test_a19_unprojected_section_and_leaf_position_kind_order(self):
        """A19。別節IDの追加と元leafのkind/位置/順序改変を完全byte比較で拒否する。"""
        record = json.loads(base64.b64decode(json.loads(self.raw_index)["records"][0]["recordBytesBase64"]))
        documents = deepcopy(self.documents)
        second_id = {"kind": "HARDWARE", "value": r"PCI\VEN_FA02&DEV_0002"}
        documents["inspection"]["infs"][0]["models"][1]["pnpIds"] = [second_id]
        inputs = self.encode(documents)
        changed = deepcopy(record)
        changed["publishedIdentityEvidence"]["pnpIds"].append(second_id)
        self.reject("unprojected-section", "PUBLIC_PROJECTION_BYTES", bundle=self.modified_index(changed),
                    inputs=inputs, input_pins={name: pipeline.sha(value) for name, value in inputs.items()})
        changed = deepcopy(record)
        changed["publishedIdentityEvidence"]["pnpIds"][0]["kind"] = "COMPATIBLE"
        self.reject("kind", "PUBLIC_PROJECTION_BYTES", bundle=self.modified_index(changed))
        changed = deepcopy(record)
        changed["otherIds"] = changed["publishedIdentityEvidence"].pop("pnpIds")
        self.reject("position", "PUBLIC_PROJECTION_BYTES", bundle=self.modified_index(changed))
        documents = deepcopy(self.documents)
        documents["inspection"]["infs"][0]["models"][0]["pnpIds"].append(
            {"kind": "COMPATIBLE", "value": r"PCI\VEN_FA01&DEV_0002"})
        inputs = self.encode(documents)
        raw, packed, manifest, _ = self.project(documents)
        index = json.loads(raw)
        changed = json.loads(base64.b64decode(index["records"][0]["recordBytesBase64"]))
        changed["publishedIdentityEvidence"]["pnpIds"].reverse()
        entry = pipeline.canonical(changed)
        index["records"][0].update(recordBytesBase64=base64.b64encode(entry).decode("ascii"), recordSha256=pipeline.sha(entry))
        import gzip
        packed = gzip.compress(pipeline.canonical(index), mtime=0)
        parsed_manifest = json.loads(manifest)
        parsed_manifest["asset"].update(sizeBytes=len(packed), sha256=pipeline.sha(packed))
        self.reject("order", "PUBLIC_PROJECTION_BYTES", inputs=inputs,
                    input_pins={name: pipeline.sha(value) for name, value in inputs.items()},
                    bundle={"index.json.gz": packed, "manifest.json": envelope(b"\n" + pipeline.canonical(parsed_manifest),
                            pipeline.projection.DISTRIBUTION_KEY_ID)})
        self.assertEqual(self.projection_report["unprojectedModelSections"], 1)

    def test_a20_output_record_and_hash_not_provenance(self):
        """A20。record/hash一致を作り直しても六原入力の完全投影を置換しない。"""
        record = json.loads(base64.b64decode(json.loads(self.raw_index)["records"][0]["recordBytesBase64"]))
        record["product"] = "Artificial changed record"
        self.reject("record-and-hash", "PUBLIC_PROJECTION_BYTES", bundle=self.modified_index(record))

    def test_a21_original_audit_still_refuses_acquisition(self):
        """A21。取得bundleを元metadata入口へ渡しても新helperへfallbackしない。"""
        fixture = ProjectionTests()
        fixture.setUp()
        scope = dict(fixture.scope, keyId=pipeline.projection.DISTRIBUTION_KEY_ID)
        with patch.object(pipeline, "audit_distribution_acquisition_bundle", side_effect=AssertionError("UNEXPECTED_NEW_CALL")):
            with self.assertRaises(ValueError) as caught:
                pipeline.audit_bundle(self.bundle, scope, fixture.daily_receipt(), fixture.now)
        self.assertEqual(str(caught.exception), "PUBLIC_PROJECTION_BYTES")

    def test_a22_caller_pins_and_shape_issue_no_authority(self):
        """A22。自己pinとzero署名形は整合dataだけを返し、権限serviceを使わない。"""
        outer = json.loads(self.bundle["manifest.json"])
        outer["signatureBase64"] = base64.b64encode(bytes(384)).decode("ascii")
        bundle = dict(self.bundle, **{"manifest.json": pipeline.canonical(outer)})
        before = deepcopy((bundle, self.inputs, self.pins))
        with patch.object(pipeline, "read", side_effect=AssertionError("IO_DENIED")) as read, \
                patch.object(pipeline.Budget, "run", side_effect=AssertionError("SERVICE_DENIED")) as run, \
                patch.object(pipeline, "protected_root", side_effect=AssertionError("STATE_DENIED")) as state, \
                patch.object(pipeline, "utc", side_effect=AssertionError("CLOCK_DENIED")) as clock:
            result = self.audit(bundle=bundle)
        self.assertIs(type(result), dict)
        self.assertEqual(result, json.loads(self.raw_manifest))
        self.assertEqual(before, (bundle, self.inputs, self.pins))
        self.assertTrue(all(name not in result for name in
                        ("authorityIssued", "reservation", "signatureVerified", "snapshot", "grant", "consent")))
        for service in (read, run, state, clock):
            service.assert_not_called()


class DailyDistributionAcquisitionAuditTests(unittest.TestCase):
    """ADR0364のD05/06/D25〜32だけを明示日次監査へ接続する。"""

    def setUp(self):
        """人工fixtureをmodule経由で借用し、新しいTestCase再exportを作らない。"""
        import test_project_collected_native_index as fixture_module
        self.fixture = fixture_module.DailyDistributionProjectionTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.now = self.fixture.now
        self.documents = {name: deepcopy(getattr(self.fixture, name)) for name in
                          ("scope", "release", "inspection", "review", "script")}
        self.documents["evidence"] = deepcopy(self.fixture.receipt)
        self.inputs = self.encode(self.documents)
        self.pins = {name: pipeline.sha(raw) for name, raw in self.inputs.items()}
        self.raw_index, self.packed, self.raw_manifest, self.projection_report = self.project()
        self.bundle = {"index.json.gz": self.packed, "manifest.json": envelope(
            self.raw_manifest, pipeline.projection.DISTRIBUTION_KEY_ID)}

    @staticmethod
    def encode(documents):
        """各人工文書を原byte化し、audit側のpin照合から分離する。"""
        return {name: pipeline.canonical(value) for name, value in documents.items()}

    def project(self, documents=None):
        """原receiptだけから世代を導出する新producerを使用する。"""
        values = self.documents if documents is None else documents
        return pipeline.projection.project_daily_distribution_acquisition(
            values["scope"], values["evidence"], values["release"], values["inspection"],
            values["review"], values["script"], self.now)

    def audit(self, **changes):
        """元publicationを固定し、明示入口以外へfallbackしない。"""
        args = dict(bundle=self.bundle, inputs=self.inputs, input_pins=self.pins,
                    generation=4, published_at=self.now, now=self.now)
        args.update(changes)
        return pipeline.audit_daily_distribution_acquisition_bundle(**args)

    def reject(self, label, code, **changes):
        """実拒否reasonを固定期待値と完全一致で保存する。"""
        with self.subTest(variant=label, expected=code):
            with self.assertRaises(ValueError) as caught:
                self.audit(**changes)
            self.assertEqual(str(caught.exception), code)

    def changed_projection(self, documents):
        """privacy負例の原投影とpinを揃え、内容検査後まで到達させる。"""
        inputs = self.encode(documents)
        _, packed, manifest, _ = self.project(documents)
        return dict(bundle={"index.json.gz": packed, "manifest.json": envelope(
            manifest, pipeline.projection.DISTRIBUTION_KEY_ID)}, inputs=inputs,
            input_pins={name: pipeline.sha(raw) for name, raw in inputs.items()})

    def test_d05_daily_200_exact_audit(self):
        """D05。監査時刻だけを進めても原byte/quality/期限を維持する。"""
        expected = json.loads(self.raw_manifest)
        original = deepcopy((self.bundle, self.inputs, self.pins))
        expiry = pipeline.parse_time(expected["expiresAtUtc"])
        for now in (self.now, self.now+timedelta(seconds=60), expiry-timedelta(seconds=1)):
            with self.subTest(now=now.isoformat()):
                with patch.object(pipeline, "read", side_effect=AssertionError("IO_DENIED")), \
                        patch.object(pipeline.Budget, "run", side_effect=AssertionError("SERVICE_DENIED")), \
                        patch.object(pipeline, "protected_root", side_effect=AssertionError("STATE_DENIED")):
                    result = self.audit(now=now)
                self.assertEqual(result, expected)
                self.assertEqual((self.bundle, self.inputs, self.pins), original)
                self.assertIs(type(result), dict)
                self.assertEqual(result["quality"]["contentInspectedCount"], 1)
                self.assertFalse(any(name in result for name in
                                 ("authorityIssued", "reservation", "signatureVerified", "snapshot", "grant", "consent")))

    def test_d06_daily_304_exact_audit(self):
        """D06。304の元取得・再検証・世代・元期限を監査後も保持する。"""
        for generation in (5, 9007199254740991):
            documents = deepcopy(self.documents)
            documents["evidence"] = self.fixture.make_receipt(304, generation)
            original = deepcopy(documents)
            changes = self.changed_projection(documents)
            with self.subTest(generation=generation):
                result = self.audit(**changes, generation=generation)
                self.assertEqual(result["generation"], generation)
                self.assertEqual(result["expiresAtUtc"], "2026-10-21T12:59:30Z")
                self.assertEqual(documents, original)
                self.assertLess(documents["evidence"]["lastFetchedAt"], documents["evidence"]["lastAttemptAt"])

    def test_d25_raw_input_pins(self):
        """D25。evidence欄も原byte/厳密pin/六入力型の例外にしない。"""
        self.reject("stale-pin", "ACQUISITION_INPUT_PIN", inputs=dict(
            self.inputs, evidence=self.inputs["evidence"]+b"\n"))
        self.reject("uppercase", "ACQUISITION_INPUT_PIN", input_pins=dict(
            self.pins, evidence=self.pins["evidence"].upper()))
        self.reject("missing-pin", "ACQUISITION_PIN_FIELDS", input_pins={
            name: raw for name, raw in self.pins.items() if name != "evidence"})
        self.reject("missing-evidence", "ACQUISITION_INPUT_FIELDS", inputs={
            name: raw for name, raw in self.inputs.items() if name != "evidence"})
        self.reject("mutable", "ACQUISITION_INPUT_BYTES", inputs=dict(
            self.inputs, evidence=bytearray(self.inputs["evidence"])))
        self.reject("extra", "ACQUISITION_INPUT_FIELDS", inputs=dict(self.inputs, extra=b"{}"))

    def test_d26_explicit_generation(self):
        """D26。明示世代を原receiptの代用や新予約へ変換しない。"""
        self.reject("mismatch", "DAILY_ACQUISITION_GENERATION_BINDING", generation=5)
        for value in (True, 4.0, 0, 9007199254740992):
            self.reject(repr(value), "ACQUISITION_GENERATION", generation=value)

    def test_d27_explicit_utc(self):
        """D27。監査と原発行は明示UTC秒だけを受け付ける。"""
        self.reject("naive", "ACQUISITION_UTC_SECONDS", now=self.now.replace(tzinfo=None))
        self.reject("subsecond", "ACQUISITION_UTC_SECONDS", now=self.now.replace(microsecond=1))
        self.reject("nonutc", "ACQUISITION_UTC_SECONDS", published_at=self.now.astimezone(
            pipeline.timezone(timedelta(hours=1))))
        self.reject("future", "ACQUISITION_PUBLICATION_TIME", published_at=self.now+timedelta(seconds=1))

    def test_d28_original_assets(self):
        """D28。manifest/gzipの一byte差と外側key差を拒否する。"""
        self.reject("manifest", "PUBLIC_PROJECTION_BYTES", bundle=dict(self.bundle, **{
            "manifest.json": envelope(b" "+self.raw_manifest[1:], pipeline.projection.DISTRIBUTION_KEY_ID)}))
        self.reject("gzip", "PUBLIC_PROJECTION_BYTES", bundle=dict(self.bundle, **{
            "index.json.gz": self.packed[:-1]+bytes([self.packed[-1] ^ 1])}))
        self.reject("key", "ACQUISITION_ENVELOPE_KEY", bundle=dict(self.bundle, **{
            "manifest.json": envelope(self.raw_manifest, "other")}))

    def test_d29_public_privacy(self):
        """D29。完全投影とpinが揃ってもsecret/端末識別表記を公開しない。"""
        documents = deepcopy(self.documents)
        documents["inspection"]["infs"][0]["verifiedPublisher"] = "Artificial github_pat_example"
        self.reject("secret", "PUBLIC_PRIVACY_SECRET", **self.changed_projection(documents))
        documents = deepcopy(self.documents)
        documents["evidence"]["records"][0]["displayTitle"] = "Artificial instanceId marker"
        self.fixture.rebind(documents["evidence"])
        self.reject("private", "PUBLIC_PRIVACY", **self.changed_projection(documents))

    def test_d30_original_expiry(self):
        """D30。発行byteを更新せず、元期限で失効させる。"""
        expiry = pipeline.parse_time(json.loads(self.raw_manifest)["expiresAtUtc"])
        self.reject("expiry", "EXPIRY", now=expiry)

    def test_d31_receipt_not_fallback(self):
        """D31。自己pin一致のHOLD/前hash/投影不整合もそのまま拒否する。"""
        for field, value, code in (("outcome", "HOLD", "DAILY_NOT_A_NEW_OBSERVATION"),
                                   ("previousReceiptSha256", "invalid", "DAILY_PREVIOUS_RECEIPT"),
                                   ("requestBindingSha256", "0"*64, "DAILY_PROJECTION_BINDING")):
            inputs = dict(self.inputs, evidence=pipeline.canonical(dict(self.documents["evidence"], **{field: value})))
            self.reject(field, code, inputs=inputs, input_pins={name: pipeline.sha(raw) for name, raw in inputs.items()})

    def test_d32_old_entries_and_no_callback(self):
        """D32。旧二監査は自動切替せず、日次監査も外部callbackを受け付けない。"""
        with self.subTest(variant="old-h3", expected="COLLECTED_FIELDS"):
            with self.assertRaises(ValueError) as caught:
                pipeline.audit_distribution_acquisition_bundle(self.bundle, self.inputs, self.pins,
                    generation=4, published_at=self.now, now=self.now)
            self.assertEqual(str(caught.exception), "COLLECTED_FIELDS")
        with self.subTest(variant="old-metadata", expected="PUBLIC_PROJECTION_BYTES"):
            with self.assertRaises(ValueError) as caught:
                pipeline.audit_bundle(self.bundle, self.fixture.legacy_scope,
                                      self.documents["evidence"], self.now)
            self.assertEqual(str(caught.exception), "PUBLIC_PROJECTION_BYTES")
        code = "audit_daily_distribution_acquisition_bundle() got an unexpected keyword argument 'callback'"
        with self.subTest(variant="callback", expected=code):
            with self.assertRaises(TypeError) as caught:
                self.audit(callback=lambda: None)
            self.assertEqual(str(caught.exception), code)


class DailyAcquisitionPreparationTests(unittest.TestCase):
    """C01〜C11の監視側入力接続をfake Budgetだけで有限確認する。"""

    def setUp(self):
        """独立fixtureと人工archive metadataを作り、実process/networkは開始しない。"""
        import test_project_collected_native_index as fixtures
        self.fixture = fixtures.PinnedStaticRevalidationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.now = self.fixture.now
        self.config = {"collectorExe": "ARTIFICIAL_COLLECTOR", "signerExe": "ARTIFICIAL_SIGNER",
                       "manifestFile": "ARTIFICIAL_MANIFEST", "stateRoot": "ARTIFICIAL_STATE"}
        for target, value in (("operation_root", lambda path, **kwargs: path),
                              ("protected_tree", lambda path: None),
                              ("protected_path", lambda path, **kwargs: None), ("utc", lambda: self.now)):
            patcher = patch.object(pipeline, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def prepare(self, directory, *, status=200, failure=None, archive_size=40477087,
                changed_release=None, changed_script=None, changed_inspection=None,
                changed_receipt=None, archive_missing=False):
        """三native argvと原body/receiptを記録し、巨大archiveをPythonで読まない。"""
        from types import SimpleNamespace
        fixture = self.fixture
        receipt = changed_receipt or (fixture.receipt if status == 200 else ProjectionTests.daily_receipt(fixture, 304, 9))
        receipt_path = directory / "artificial.collection-00.json"
        receipt_path.write_bytes(pipeline.canonical(receipt))
        archive = directory / "artificial.archive.zip"
        if not archive_missing:
            archive.write_bytes(b"ARTIFICIAL_ONLY_NO_REAL_ARCHIVE")
        events = []
        documents = {"--parse-collected-release": changed_release or fixture.release,
                     "--inspect-collected-package": changed_inspection or fixture.inspection,
                     "--collect-terms-link-script": changed_script or fixture.script}
        class FakeBudget:
            """許可argvだけを処理するRAM fake。実processをfallbackしない。"""
            def run(inner, argv, **kwargs):
                """新規人工文書と公開予約factsだけを保存する。"""
                events.append((list(argv), kwargs))
                command = argv[1]
                if failure == command:
                    return 2, b"", b"ARTIFICIAL_ERROR"
                if command == "--verify-daily-reservation":
                    raw = receipt_path.read_bytes()
                    return 0, (f"COLLECTOR_RESERVATION error=0 mode=FRESH_INPUT generation=9 "
                               f"receipt_sha256={pipeline.sha(raw)}\n").encode(), b""
                if command not in documents:
                    raise AssertionError("UNREGISTERED_NATIVE_COMMAND")
                output = Path(argv[-2] if command == "--inspect-collected-package" else argv[-1])
                output.write_bytes(pipeline.canonical(documents[command]))
                return 0, b"ARTIFICIAL_NATIVE_ONLY", b""
        original_stat = Path.stat
        def stat(path, *args, **kwargs):
            """File metadataだけを人工化し、40MBの実配布物を作成・読取しない。"""
            value = original_stat(path, *args, **kwargs)
            if path == archive:
                return SimpleNamespace(st_mode=value.st_mode, st_size=archive_size,
                                       st_file_attributes=value.st_file_attributes)
            return value
        original_read = pipeline.read
        def read(path, maximum=pipeline.MAX_FILE):
            """archiveを16MiB readerへ渡した場合はfixtureそのものを失敗にする。"""
            self.assertNotEqual(path, archive)
            return original_read(path, maximum)
        self.events = events
        self.receipt_path = receipt_path
        with patch.object(Path, "stat", stat), patch.object(pipeline, "read", read):
            result = pipeline.prepare_daily_acquisition_inputs(self.config, pipeline.canonical(fixture.scope),
                receipt_path, fixture.originals, fixture.original_pins, archive,
                "PRO2500/Winx64/W11/e2fn.inf", FakeBudget(),
                terms_review_mode=pipeline.projection.PINNED_STATIC_REVALIDATION_V1)
        return result

    def test_c01_c02_connected_native_commands_raw_pins_and_audit(self):
        """200/304で新入力束から明示producer/auditまで接続し、原JSONを保つ。"""
        for status in (200, 304):
            with self.subTest(case="C01" if status == 200 else "C02", status=status), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result = self.prepare(directory, status=status)
                self.assertEqual([row[0][1] for row in self.events], ["--verify-daily-reservation",
                    "--parse-collected-release", "--inspect-collected-package", "--collect-terms-link-script"])
                self.assertEqual(result["inputs"]["evidence"], self.receipt_path.read_bytes())
                self.assertEqual(result["inputPins"], {key: pipeline.sha(raw) for key, raw in result["inputs"].items()})
                self.assertEqual(self.events[-1][1]["seconds"], 120)
                _, packed, manifest_raw, report = result["projection"]
                bundle = {"index.json.gz": packed, "manifest.json": envelope(manifest_raw, self.fixture.scope["keyId"])}
                checked = pipeline.audit_daily_distribution_acquisition_bundle(bundle, result["inputs"],
                    result["inputPins"], generation=9, published_at=self.now, now=self.now,
                    terms_review_mode=pipeline.projection.PINNED_STATIC_REVALIDATION_V1)
                self.assertEqual(checked["generation"], 9)
                self.assertEqual(report["httpStatus"], status)
                self.assertFalse(result["authorityIssued"])
                self.assertEqual(set(result["inputs"]), {"scope", "evidence", "release", "inspection", "review", "script"})
                with self.assertRaisesRegex(ValueError, "TERMS_REVIEW_BINDING"):
                    pipeline.audit_daily_distribution_acquisition_bundle(bundle, result["inputs"],
                        result["inputPins"], generation=9, published_at=self.now, now=self.now)

    def test_fractional_utc_cold_preparation_200_and_304(self):
        """非0小数秒の実clockを保ち、200/304の投影境界だけを整数UTC秒へ接続する。"""
        self.now = self.now.replace(microsecond=654321)
        originals, original_pins = deepcopy(self.fixture.originals), deepcopy(self.fixture.original_pins)
        for status in (200, 304):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                with patch.object(pipeline.projection, "make_pinned_static_terms_revalidation",
                        wraps=pipeline.projection.make_pinned_static_terms_revalidation) as review_call, \
                     patch.object(pipeline.projection, "project_daily_distribution_acquisition",
                        wraps=pipeline.projection.project_daily_distribution_acquisition) as projection_call:
                    result = self.prepare(Path(temporary), status=status)
                self.assertEqual(review_call.call_args.args[-1], self.now)
                self.assertEqual(review_call.call_args.args[-2], int(self.now.timestamp()))
                self.assertEqual(projection_call.call_args.args[6], self.now.replace(microsecond=0))
                self.assertEqual(pipeline.utc(), self.now)
                self.assertEqual(result["inputs"]["evidence"], self.receipt_path.read_bytes())
                self.assertEqual(result["inputPins"], {name: pipeline.sha(raw)
                    for name, raw in result["inputs"].items()})
                review = json.loads(result["inputs"]["review"])
                self.assertEqual(review["revalidatedCheckedAtUtcSeconds"], int(self.now.timestamp()))
                self.assertEqual(review["originalManualCheckedAtUtcSeconds"],
                    json.loads(originals["review"])["checkedAtUtcSeconds"])
                manifest = json.loads(result["projection"][2])
                self.assertEqual(pipeline.parse_time(manifest["publishedAtUtc"]), self.now.replace(microsecond=0))
                self.assertEqual(result["projection"][3]["httpStatus"], status)
                self.assertEqual(len(self.events), 4)
                self.assertEqual(self.fixture.originals, originals)
                self.assertEqual(self.fixture.original_pins, original_pins)

    def test_native_inspection_uppercase_hash_argv_preserves_raw_inputs(self):
        """公開hashの大文字原JSON/pinを保ち、記録したnative argvだけを小文字にする。"""
        published = self.fixture.release["publishedSha256"].upper()
        self.fixture.release["publishedSha256"] = published
        original_release = json.loads(self.fixture.originals["release"])
        original_release["publishedSha256"] = published
        self.fixture.originals["release"] = pipeline.canonical(original_release)
        self.fixture.original_pins["release"] = pipeline.sha(self.fixture.originals["release"])
        originals = dict(self.fixture.originals)
        original_pins = dict(self.fixture.original_pins)
        for status in (200, 304):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result = self.prepare(directory, status=status)
                self.assertEqual(self.events[2][0][3], published.lower())
                self.assertEqual(self.events[2][0], ["ARTIFICIAL_SIGNER", "--inspect-collected-package",
                    str(directory / "artificial.archive.zip"), published.lower(),
                    str(directory / "acquisition-artificial.collection-00.inspection.json"),
                    "PRO2500\\Winx64\\W11\\e2fn.inf"])
                self.assertEqual(result["inputs"]["release"], pipeline.canonical(self.fixture.release))
                self.assertEqual(json.loads(result["inputs"]["release"])["publishedSha256"], published)
                self.assertEqual(self.fixture.originals, originals)
                self.assertEqual(self.fixture.original_pins, original_pins)
                self.assertFalse(result["authorityIssued"])

    def test_native_inspection_windows_inf_argv_preserves_logical_target(self):
        """検証済み論理INFの選択とscope原byteを保ち、native argvの区切りを固定する。"""
        scope_raw = pipeline.canonical(self.fixture.scope)
        originals = dict(self.fixture.originals)
        for status in (200, 304):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result = self.prepare(directory, status=status)
                self.assertEqual(self.events[2][0], ["ARTIFICIAL_SIGNER", "--inspect-collected-package",
                    str(directory / "artificial.archive.zip"), self.fixture.release["publishedSha256"],
                    str(directory / "acquisition-artificial.collection-00.inspection.json"),
                    "PRO2500\\Winx64\\W11\\e2fn.inf"])
                self.assertEqual(result["inputs"]["scope"], scope_raw)
                self.assertEqual(pipeline.canonical(self.fixture.scope), scope_raw)
                self.assertEqual(self.fixture.originals, originals)
                self.assertEqual(len(self.events), 4)
                self.assertFalse(result["authorityIssued"])

    def test_c04_c07_c10_native_rejections_have_no_fallback(self):
        """予約/解析/内容/scriptの元非0から別経路や二回目nativeへ進まない。"""
        cases = (("--verify-daily-reservation", "DAILY_RESERVATION_HEAD", 1),
                 ("--parse-collected-release", "FRESH_RELEASE_FAILED", 2),
                 ("--inspect-collected-package", "FRESH_INSPECTION_FAILED", 3),
                 ("--collect-terms-link-script", "FRESH_SCRIPT_FAILED", 4))
        for command, reason, count in cases:
            with self.subTest(command=command, expected=reason), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    self.prepare(Path(temporary), failure=command)
                self.assertEqual(len(self.events), count)
                self.assertEqual(len({tuple(row[0]) for row in self.events}), count)

    def test_c07_changed_script_and_template_require_review(self):
        """native成功申告でも原template/script全byteが異なれば取得束を作らない。"""
        script = dict(self.fixture.script, scriptSha256="0"*64)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED"):
            self.prepare(Path(temporary), changed_script=script)

    def test_c09_v2_and_legacy_review_capacity(self):
        """v2 1MiB超過と非明示旧64KiB超過を別reasonで拒否する。"""
        with tempfile.TemporaryDirectory() as temporary:
            result = self.prepare(Path(temporary))
            _, packed, manifest, _ = result["projection"]
            bundle = {"index.json.gz": packed, "manifest.json": envelope(manifest, self.fixture.scope["keyId"])}
            for size, mode in ((65537, None), (1048577, pipeline.projection.PINNED_STATIC_REVALIDATION_V1)):
                inputs = dict(result["inputs"], review=b" "*size)
                pins = {key: pipeline.sha(raw) for key, raw in inputs.items()}
                with self.subTest(size=size, mode=mode), self.assertRaisesRegex(ValueError, "^ACQUISITION_INPUT_BYTES$"):
                    pipeline.audit_daily_distribution_acquisition_bundle(bundle, inputs, pins,
                        generation=9, published_at=self.now, now=self.now, terms_review_mode=mode)
            inputs = dict(result["inputs"], release=result["inputs"]["release"]+b"\n")
            pins = {key: pipeline.sha(raw) for key, raw in inputs.items()}
            with self.assertRaisesRegex(ValueError, "^TERMS_REVALIDATION_PIN$"):
                pipeline.audit_daily_distribution_acquisition_bundle(bundle, inputs, pins,
                    generation=9, published_at=self.now, now=self.now,
                    terms_review_mode=pipeline.projection.PINNED_STATIC_REVALIDATION_V1)

    def test_c10_archive_size_and_inspection_bindings(self):
        """人工archive metadataの上限/固定size差とINF/Models失敗を拒否する。"""
        for size in (1, 134217729):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError, "^ACQUISITION_ARCHIVE_SIZE$"):
                    self.prepare(Path(temporary), archive_size=size)
                self.assertEqual(self.events, [])
        inspection = dict(self.fixture.inspection, inspectionError=13)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, "^NATIVE_PACKAGE_BINDING$"):
            self.prepare(Path(temporary), changed_inspection=inspection)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, "^ACQUISITION_ARCHIVE_MISSING$"):
            self.prepare(Path(temporary), archive_missing=True)

    def test_c05_c09_nonobservations_and_common_body_cap(self):
        """非観測と共通本文上限・不正UTF-8を三native操作より前に拒否する。"""
        for outcome in ("HOLD", "NO_NETWORK", "FAILED"):
            receipt = dict(self.fixture.receipt, outcome=outcome)
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ValueError, "^DAILY_NOT_A_NEW_OBSERVATION$"):
                    self.prepare(Path(temporary), changed_receipt=receipt)
        for label, body, error in (("body-over256KiB", b"x"*262145, ValueError),
                                    ("invalid-utf8", b"\xff", UnicodeError)):
            receipt = deepcopy(self.fixture.receipt)
            receipt.update(bodySha256=pipeline.sha(body), bodyBytesBase64=base64.b64encode(body).decode())
            projected = {field: receipt[field] for field in ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")}
            raw = pipeline.canonical(projected)
            receipt.update(projectionSha256=pipeline.sha(raw), projectionBytesBase64=base64.b64encode(raw).decode())
            with self.subTest(body=label), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(error) as caught:
                    self.prepare(Path(temporary), changed_receipt=receipt)
                if label == "body-over256KiB":
                    self.assertEqual(str(caught.exception), "DAILY_PREPARATION_BODY_SIZE")

    def test_c01_c05_wait_once_terminal_preservation_and_due_resume(self):
        """15:00より数秒遅いdue、300秒/残60秒/二回目HOLDと明示再開を確認する。"""
        from datetime import datetime
        beginning = self.now.replace(hour=6, minute=0, second=0)
        original_manual_bytes = dict(self.fixture.originals)
        original_manual_checked = json.loads(original_manual_bytes["review"])["checkedAtUtcSeconds"]
        self.c01_due_facts = []
        for label, delta, remaining, sequence, expected_waits in (
                ("normal-seconds-after1500", 3, 1800, ["HOLD", "OBSERVED"], 1),
                ("above-cap", 300, 1800, ["HOLD"], 0),
                ("budget-short", 3, 64, ["HOLD"], 0),
                ("second-hold", 3, 1800, ["HOLD", "HOLD"], 1)):
            with self.subTest(variant=label), tempfile.TemporaryDirectory() as temporary:
                self.now = beginning
                directory = Path(temporary)
                prefix = directory / "20261015"
                calls, waits, hold_originals = [], [], {}
                class FakeBudget:
                    """元の予算残量を持つ有限fake。"""
                    def remaining(inner, maximum):
                        """固定残量だけを返す。"""
                        return remaining
                    def run(inner, argv):
                        """各原HOLD/観測を新規fileへ残す。"""
                        calls.append(argv)
                        selected = sequence[min(len(calls)-1, len(sequence)-1)]
                        value = deepcopy(self.fixture.receipt)
                        if selected == "HOLD":
                            value.update(outcome="HOLD", generation=0, httpStatus=0, error=0, stateError=0,
                                         notBefore=int(self.now.timestamp())+delta)
                        else:
                            observed = int(self.now.timestamp())
                            value.update(lastFetchedAt=observed, lastSuccessfulValidationAt=observed,
                                         lastAttemptAt=observed, notBefore=observed+86400,
                                         day=self.now.strftime("%Y%m%d"))
                            projected = {field: value[field] for field in
                                         ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")}
                            raw = pipeline.canonical(projected)
                            value.update(projectionSha256=pipeline.sha(raw),
                                         projectionBytesBase64=base64.b64encode(raw).decode())
                        raw_receipt = pipeline.canonical(value)
                        Path(argv[-1]).write_bytes(raw_receipt)
                        if selected == "HOLD":
                            hold_originals[Path(argv[-1]).name] = raw_receipt
                        return (3 if selected == "HOLD" else 0), b"", b""
                def sleep(delay):
                    """実待機せず、同じ時計をdue後へ一度だけ進める。"""
                    waits.append(delay)
                    self.now += timedelta(seconds=delay)
                with patch.object(pipeline.time, "sleep", sleep):
                    result = pipeline.collect_daily_acquisition_receipt(self.config, prefix, FakeBudget())
                self.assertEqual(len(waits), expected_waits)
                originals = {path.name: path.read_bytes() for path in directory.glob("*.collection-*.json")}
                self.assertEqual(len(originals), len(calls))
                first_hold_raw = hold_originals[Path(calls[0][-1]).name]
                original_due = json.loads(first_hold_raw)["notBefore"]
                latest_due = max(json.loads(raw)["notBefore"] for raw in hold_originals.values())
                self.assertTrue(all(originals[name] == raw for name, raw in hold_originals.items()))
                facts = {"variant": label, "beginning": int(beginning.timestamp()),
                         "originalHoldNotBefore": original_due, "latestHoldNotBefore": latest_due,
                         "waits": list(waits)}
                if label == "normal-seconds-after1500":
                    self.assertEqual(result["status"], "OBSERVED")
                    self.assertEqual(json.loads(next(iter(originals.values())))["outcome"], "HOLD")
                    self.assertEqual(beginning.hour, 6)
                    self.assertEqual(waits, [4])
                    self.assertEqual(original_due, int(beginning.timestamp())+3)
                    success_now = int(self.now.timestamp())
                    for field in ("lastAttemptAt", "lastFetchedAt", "lastSuccessfulValidationAt"):
                        self.assertLessEqual(original_due, result["receipt"][field])
                        self.assertLessEqual(result["receipt"][field], success_now)
                    observed = result["receipt"]["lastSuccessfulValidationAt"]
                    self.fixture.release["observedUtcSeconds"] = str(observed)
                    self.fixture.script.update(pageObservedUtcSeconds=str(observed),
                                               scriptObservedUtcSeconds=str(observed))
                    self.fixture.inspection["contentCheckedUtcSeconds"] = str(observed)
                    prepared = self.prepare(directory, changed_receipt=result["receipt"])
                    self.assertEqual(prepared["projection"][3]["newHttp200Count"], 1)
                    self.assertEqual(json.loads(next(iter(originals.values())))["outcome"], "HOLD")
                    fresh_release = json.loads(prepared["inputs"]["release"])
                    fresh_script = json.loads(prepared["inputs"]["script"])
                    content_checked = int(json.loads(prepared["inputs"]["inspection"])["contentCheckedUtcSeconds"])
                    review = json.loads(prepared["inputs"]["review"])
                    revalidated = review["revalidatedCheckedAtUtcSeconds"]
                    publication = int(datetime.fromisoformat(json.loads(prepared["projection"][2])[
                        "publishedAtUtc"].replace("Z", "+00:00")).timestamp())
                    script_observed = int(fresh_script["scriptObservedUtcSeconds"])
                    self.assertEqual(int(fresh_release["observedUtcSeconds"]), observed)
                    self.assertEqual(int(fresh_script["pageObservedUtcSeconds"]), observed)
                    self.assertLessEqual(observed, script_observed)
                    self.assertLessEqual(script_observed, revalidated)
                    self.assertLessEqual(observed, content_checked)
                    self.assertLessEqual(content_checked, revalidated)
                    self.assertLessEqual(revalidated, publication)
                    self.assertLessEqual(publication, int(self.now.timestamp()))
                    self.assertLess(int(self.now.timestamp()), observed+86400)
                    self.assertEqual(review["originalManualCheckedAtUtcSeconds"], original_manual_checked)
                    facts.update(attempted=result["receipt"]["lastAttemptAt"],
                        fetched=result["receipt"]["lastFetchedAt"], validated=observed,
                        releaseObserved=int(fresh_release["observedUtcSeconds"]),
                        scriptPageObserved=int(fresh_script["pageObservedUtcSeconds"]),
                        scriptObserved=script_observed, contentChecked=content_checked,
                        revalidated=revalidated, publication=publication, successNow=success_now)
                else:
                    self.assertEqual(result["status"], "HOLD")
                    self.assertFalse(result["newGeneration"])
                    original_terminal = deepcopy(result)
                    # 同じprefix/configの原HOLDを残し、利用者のdue後明示再開だけを模擬する。
                    sequence[:] = ["OBSERVED"]
                    self.now += timedelta(seconds=301)
                    resumed = pipeline.collect_daily_acquisition_receipt(self.config, prefix, FakeBudget())
                    self.assertEqual(resumed["status"], "OBSERVED")
                    self.assertEqual(result, original_terminal)
                    for field in ("lastAttemptAt", "lastFetchedAt", "lastSuccessfulValidationAt"):
                        self.assertLessEqual(latest_due, resumed["receipt"][field])
                        self.assertLessEqual(resumed["receipt"][field], int(self.now.timestamp()))
                    self.assertEqual(len(waits), expected_waits)
                    facts.update(originalTerminal=result["status"], resumeObserved=resumed["receipt"][
                        "lastSuccessfulValidationAt"], resumeNow=int(self.now.timestamp()))
                self.assertTrue(all((directory / name).read_bytes() == raw for name, raw in originals.items()))
                self.assertEqual(self.fixture.originals, original_manual_bytes)
                self.assertFalse((directory / (prefix.name+".success.json")).exists())
                facts.update(originalBytesUnchanged=True, successMarker=False,
                             originalManualChecked=original_manual_checked)
                self.c01_due_facts.append(facts)


class IssuanceWorld:
    """保護配置を人工directoryへ隔離し、実prepare/load/main/Publisherを接続する有限fixture。"""

    def __init__(self, directory, *, status=200, public_blob=b"P" * 411, initial_now=None,
                 manifest_bytes=b'{"artificialCollector":true}'):
        """原v1・原metadata・versioned moduleと公開blobを人工byteで準備する。"""
        from datetime import datetime, timezone
        from types import SimpleNamespace
        import prepare_daily_index_config as prepare
        import test_project_collected_native_index as fixtures
        self.stack = ExitStack()
        self.fixture = fixtures.PinnedStaticRevalidationTests()
        self.fixture.setUp()
        self.stack.callback(self.fixture.doCleanups)
        self.now = initial_now or datetime(2026, 10, 17, 6, tzinfo=timezone.utc)
        self.root = directory / "protected"
        self.out = self.root / "operations" / "same-original-job"
        self.control = self.root / "control" / "acquisition"
        old_control = self.root / "control" / "legacy"
        self.version = self.root / "scripts" / "v2-artificial"
        binary = self.root / "bin" / self.version.name
        runtime = self.root / "runtime"
        repository = self.root / "workspace"
        state = repository / pipeline.STATE_RELATIVE
        for path in (self.out, old_control, self.version, binary, runtime, repository, state):
            path.mkdir(parents=True, exist_ok=True)
        for name in pipeline.MODULE_NAMES:
            (self.version / name).write_bytes(("ARTIFICIAL_NEW_" + name).encode())
            (self.root / "scripts" / name).write_bytes(("ARTIFICIAL_OLD_" + name).encode())
        self.collector, self.signer = binary / "DriverCrateCollector.exe", binary / "DriverCrateLocalIndexSigner.exe"
        for path in (self.collector, self.signer, runtime / "python.exe", runtime / "pythonw.exe"):
            path.write_bytes(b"ARTIFICIAL_NONEXECUTABLE")
        public = old_control / "public.blob"
        public.write_bytes(public_blob)
        self.fingerprint = pipeline.sha(public.read_bytes())
        key_id = "distribution-index-" + self.fingerprint[:32]
        manifest = old_control / "collector.json"
        manifest.write_bytes(manifest_bytes)
        manifest_hash = pipeline.sha(manifest.read_bytes())
        original_normal = pipeline.normal_path
        gh = Path("C:/Program Files/GitHub CLI/gh.exe")
        patches = ((pipeline, "protected_root", lambda: self.root),
            (pipeline, "protected_path", lambda *a, **kw: None),
            (pipeline, "protected_tree", lambda *a, **kw: None),
            (pipeline, "operation_root", lambda path, **kw: path),
            (pipeline, "normal_path", lambda value, **kw: gh if Path(value) == gh else original_normal(value, **kw)),
            (pipeline, "_APPROVED_WORKSPACE", None),
            (pipeline, "MANIFEST_SHA256", manifest_hash), (pipeline, "utc", lambda: self.now),
            (pipeline, "__file__", str(self.version / "daily_index_pipeline.py")),
            (pipeline.projection, "__file__", str(self.version / "project_collected_native_index.py")),
            (pipeline.cr, "__file__", str(self.version / "collector_registry.py")),
            (prepare, "__file__", str(self.version / "prepare_daily_index_config.py")),
            (pipeline.projection, "DISTRIBUTION_PUBLIC_FINGERPRINT", self.fingerprint),
            (pipeline.projection, "DISTRIBUTION_KEY_ID", key_id))
        for owner, name, value in patches:
            self.stack.enter_context(patch.object(owner, name, value))
        (self.root / "control/approved-workspace.json").write_bytes(
            pipeline.canonical(workspace_approval(repository, state, manifest_hash)))
        self.fixture.scope.update(publicFingerprint=self.fingerprint, keyId=key_id,
                                  collectorManifestSha256=manifest_hash)
        self.fixture.evidence["manifestSha256"] = manifest_hash
        self.refresh(status=status)
        self.archive = old_control / "artificial.archive.zip"
        self.archive.write_bytes(b"ARTIFICIAL_ONLY_NOT_DRIVER_BYTES")
        original_stat = Path.stat
        def stat(path, *args, **kwargs):
            """小さな人工fileのsize metadataだけを固定archive契約に合わせる。"""
            value = original_stat(path, *args, **kwargs)
            if path == self.archive:
                return SimpleNamespace(st_mode=value.st_mode, st_size=40477087,
                                       st_file_attributes=value.st_file_attributes, st_nlink=value.st_nlink)
            return value
        self.stack.enter_context(patch.object(Path, "stat", stat))
        original_read = pipeline.read
        def read(path, maximum=pipeline.MAX_FILE):
            """archiveのPython読取は常に失敗させ、native偽装へも実byteを渡さない。"""
            assert path != self.archive, "ARCHIVE_READ_FORBIDDEN"
            return original_read(path, maximum)
        self.stack.enter_context(patch.object(pipeline, "read", read))
        old_scope = {name: value for name, value in self.fixture.scope.items()
                     if name not in {"publicFingerprint", "projectionPolicyRevision"}}
        old_scope["schema"] = "dc-fixed-collector-native-index-scope-v1"
        (old_control / "scope.json").write_bytes(pipeline.canonical(old_scope))
        old_config = {"schema": "dc-private-daily-index-config-v1", "repositoryRoot": str(repository),
            "stateRoot": str(state), "manifestFile": str(manifest), "manifestSha256": manifest_hash,
            "scopeFile": str(old_control / "scope.json"), "scopeSha256": pipeline.sha(pipeline.canonical(old_scope)),
            "collectorExe": str(self.collector), "collectorSha256": pipeline.sha(self.collector.read_bytes()),
            "signerExe": str(self.signer), "signerSha256": pipeline.sha(self.signer.read_bytes()),
            "publicKeyFile": str(public), "fingerprint": self.fingerprint, "pythonExe": str(runtime / "python.exe"),
            "ghExe": str(gh), "outputRoot": str(self.out), "smokeLocal": "2026-10-15T15:00:00+09:00",
            "firstDailyLocal": "2026-10-16T15:00:00+09:00",
            "pipelineSha256": pipeline.sha((self.root / "scripts/daily_index_pipeline.py").read_bytes()),
            "producerSha256": pipeline.sha((self.root / "scripts/project_collected_native_index.py").read_bytes())}
        old_path = old_control / "config.json"
        old_path.write_bytes(pipeline.canonical(old_config))
        legacy_receipt = self.make_receipt(self.now - timedelta(days=2), 4, 200)
        legacy_receipt_path = self.out / "legacy.collection-00.json"
        legacy_receipt_path.write_bytes(pipeline.canonical(legacy_receipt))
        _, packed, raw, _ = pipeline.projection.project_daily(old_scope, legacy_receipt, self.now - timedelta(days=2))
        self.legacy_bundle = {"index.json.gz": packed, "manifest.json": envelope(raw, key_id)}
        legacy_raw, legacy_gzip, legacy_envelope = (self.out / name for name in
            ("legacy.manifest.raw.json", "legacy.index.json.gz", "legacy.manifest.json"))
        for path, data in ((legacy_raw, raw), (legacy_gzip, packed), (legacy_envelope, self.legacy_bundle["manifest.json"])):
            path.write_bytes(data)
        original_paths = {}
        for name, data in self.fixture.originals.items():
            original_paths[name] = old_control / ("original." + name + ".json")
            original_paths[name].write_bytes(data)
        self.args = SimpleNamespace(inherit_config=old_path, public_key=None, fingerprint=None, smoke_local=None,
            first_daily_local=None, new_output_root=None, control_directory=self.control,
            original_release=original_paths["release"], original_review=original_paths["review"],
            original_script=original_paths["script"], archive=self.archive, legacy_receipt=legacy_receipt_path,
            legacy_raw_manifest=legacy_raw, legacy_gzip=legacy_gzip, legacy_envelope=legacy_envelope,
            fence_receipt=legacy_receipt_path, collector_exe=self.collector, signer_exe=self.signer,
            selected_inf="PRO2500/Winx64/W11/e2fn.inf")
        self.calls, self.sign_behavior, self.fail_verify, self.head_generation = [], None, None, None
        self.config_path = prepare.inherit_config(self.args, budget=self)
        self.config, self.scope, self.config_hash = pipeline.load_config(self.config_path)
        self.preparation_calls = list(self.calls)
        self.calls.clear()
        self.remote = FakeRemote()
        pipeline.Publisher(self.remote, lambda *a, **kw: None).publish(self.legacy_bundle)
        self.remote.events.clear()
        self.old_head = self.remote.head

    def close(self):
        """全patchとfixtureの所有するmockを逆順に解除する。"""
        self.stack.close()

    def make_receipt(self, now, generation, status):
        """status・fetch・projectionを原形で保つ人工native receiptを作る。"""
        receipt = ProjectionTests.daily_receipt(self.fixture, status, generation)
        observed = int(now.timestamp()) - 30
        receipt.update(day=pipeline.public_jst_day(now), lastSuccessfulValidationAt=observed,
            lastAttemptAt=observed-1, notBefore=observed+86400,
            lastFetchedAt=observed if status == 200 else observed-86400)
        raw = pipeline.canonical({field: receipt[field] for field in
            ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")})
        receipt.update(projectionBytesBase64=base64.b64encode(raw).decode(), projectionSha256=pipeline.sha(raw))
        return receipt

    def refresh(self, *, status=200, generation=9):
        """新観測の時刻だけを新文書へ設定し、原manualの全byteは変更しない。"""
        observed = int(self.now.timestamp()) - 30
        self.fixture.release["observedUtcSeconds"] = str(observed)
        self.fixture.script.update(pageObservedUtcSeconds=str(observed), scriptObservedUtcSeconds=str(observed+10))
        self.fixture.inspection["contentCheckedUtcSeconds"] = str(observed+15)
        self.receipt = self.make_receipt(self.now, generation, status)

    def remaining(self, maximum=600):
        """実時間を待たず、既存の有限child上限を返す。"""
        return min(maximum, 1800)

    def run(self, argv, data=None, maximum=pipeline.MAX_FILE, seconds=600):
        """固定native CLIだけを人工byteで実行し、秘密鍵や実processへfallbackしない。"""
        self.calls.append((list(argv), seconds, maximum))
        command = argv[1]
        if command == "--public-index-readback":
            assert len(argv) == 5 and 1 <= int(argv[4]) <= 90000
            behavior = getattr(self, "anonymous_behavior", "success")
            if behavior == "hard-crash":
                raise RuntimeError("ARTIFICIAL_WORKER_UNFINISHED")
            if behavior == "crash-exit":
                return 3221225477, b"", b""
            bundle = {"manifest.json": pipeline.read(Path(argv[2]), 98304),
                      "index.json.gz": pipeline.read(Path(argv[3]))}
            if behavior == "verifier-failure":
                self.fail_verify = "--distribution-acquisition-verify"
            raw = anonymous_stdout_fixture(bundle, self.now, behavior)
            if behavior == "noncanonical":
                raw += b"\n"
            return 0 if json.loads(raw)["outcome"] == "VERIFIED" else 2, raw, b""
        elif command == "--daily-evidence":
            pipeline.write_new(Path(argv[-1]), pipeline.canonical(self.receipt))
        elif command == "--verify-daily-reservation":
            raw = pipeline.read(Path(argv[-2]), 1048576)
            generation = json.loads(raw)["generation"]
            if argv[-1] == "FRESH_INPUT" and self.head_generation is not None:
                generation = self.head_generation
            return 0, (f"COLLECTOR_RESERVATION error=0 mode={argv[-1]} generation={generation} "
                       f"receipt_sha256={pipeline.sha(raw)}").encode(), b""
        elif command in {"--parse-collected-release", "--inspect-collected-package", "--collect-terms-link-script"}:
            document = {"--parse-collected-release": self.fixture.release,
                        "--inspect-collected-package": self.fixture.inspection,
                        "--collect-terms-link-script": self.fixture.script}[command]
            output = Path(argv[-2] if command == "--inspect-collected-package" else argv[-1])
            pipeline.write_new(output, pipeline.canonical(document))
        elif command == "--distribution-acquisition-sign":
            if self.sign_behavior in {"nonzero", "timeout", "result-before-record-crash"}:
                pipeline.write_new(Path(argv[4]), envelope(pipeline.read(Path(argv[2])), self.scope["keyId"]))
            if self.sign_behavior == "result-before-record-crash":
                raise SystemExit("ARTIFICIAL_RESULT_RECORD_CRASH")
            if self.sign_behavior == "timeout":
                raise ValueError("PROCESS_TIMEOUT")
            if self.sign_behavior == "before-invoke":
                raise RuntimeError("ARTIFICIAL_BEFORE_KEY")
            if self.sign_behavior in {"nonzero", "missing"}:
                return 2, b"", b"ARTIFICIAL_FAILURE"
            if self.sign_behavior == "partial":
                pipeline.write_new(Path(argv[4]), b"{")
                return 2, b"", b"ARTIFICIAL_FAILURE"
            pipeline.write_new(Path(argv[4]), envelope(pipeline.read(Path(argv[2])), self.scope["keyId"]))
        elif command in {"--distribution-verify", "--distribution-verify-history", "--distribution-verify-floor-history",
                         "--distribution-acquisition-verify", "--distribution-acquisition-verify-history"}:
            if self.fail_verify == command:
                return 2, b"", b"ARTIFICIAL_VERIFY_REJECTION"
            value = pipeline.read(Path(argv[2]), 98304)
            manifest, _ = pipeline.unpack_envelope(value)
            assert base64.b64decode(json.loads(value)["signatureBase64"]) == b"X" * 384
            assert pipeline.parse_time(manifest["publishedAtUtc"]) <= self.now
            if not command.endswith("-history"):
                assert self.now < pipeline.parse_time(manifest["expiresAtUtc"])
            if "acquisition" in command:
                assert manifest["quality"]["contentInspectedCount"] == 1
            else:
                assert manifest["quality"]["metadataOnlyCount"] == 1
            return 0, b"LOCAL_INDEX_HISTORY_VERIFIED freshness=0" if command.endswith("-history") else b"VERIFIED", b""
        else:
            raise AssertionError("UNREGISTERED_NATIVE_COMMAND: " + command)
        return 0, b"ARTIFICIAL_ONLY", b""

    def execute(self, *, main=False):
        """実run_pipelineを同じoperation lockで呼び、任意に実mainのterminal保存も通す。"""
        if not main:
            return pipeline.run_pipeline(self.config, self.scope, self.config_hash, budget=self, remote=self.remote)
        real_run = pipeline.run_pipeline
        def injected(config, scope, digest):
            """mainの依存だけにfake Budget/Remoteを注入する。"""
            return real_run(config, scope, digest, budget=self, remote=self.remote)
        output = io.StringIO()
        with patch.object(pipeline, "run_pipeline", injected), patch("sys.argv", ["daily_index_pipeline.py", "run", str(self.config_path)]), redirect_stdout(output):
            code = pipeline.main()
        return code, json.loads(output.getvalue())

    def command_count(self, command):
        """実fixtureが記録した明示native command回数を返す。"""
        return sum(argv[1] == command for argv, _, _ in self.calls)

    def artifact(self, suffix):
        """共有日次receipt/terminalと、ADR0373の用途別公開成果物名を返す。"""
        if suffix in {".manifest.raw.json", ".index.json.gz", ".manifest.json", ".success.json"}:
            suffix = ".acquisition" + suffix
        return self.out / (self.now.strftime("%Y%m%d") + suffix)

    def claim_path(self):
        """実receipt世代から一つのclaim pathを返す。"""
        return self.out / f"issuance-v1-{self.receipt['generation']:016d}.claim.json"


class DailyAcquisitionIssuanceTests(unittest.TestCase):
    """固定C12〜C35を実運用I/Oなしで接続確認する。"""

    @contextmanager
    def world(self, **kwargs):
        """variantごとに独立した人工保護rootを所有し、例外時もpatchを解除する。"""
        with tempfile.TemporaryDirectory() as temporary:
            value = IssuanceWorld.__new__(IssuanceWorld)
            try:
                value.__init__(Path(temporary), **kwargs)
                yield value
            finally:
                if hasattr(value, "stack"):
                    value.close()

    def stop_before_publication(self, world):
        """署名済み・未公開の境界で一回だけ停止し、原envelopeを保持する。"""
        with patch.object(pipeline.Publisher, "publish", side_effect=ValueError("ARTIFICIAL_BEFORE_PUBLICATION")):
            with self.assertRaisesRegex(ValueError, "^ARTIFICIAL_BEFORE_PUBLICATION$"):
                world.execute()

    def test_c12_prepare_main_claim_sign_verify_publish(self):
        """200/304とも継承準備から実main・署名・readback/CAS・purpose報告へ通す。"""
        for status in (200, 304):
            with self.subTest(status=status), self.world(status=status) as world:
                code, result = world.execute(main=True)
                self.assertEqual((code, result["status"]), (0, "PUBLISHED"))
                self.assertEqual(result["purpose"], pipeline.ACQUISITION_PURPOSE)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assertEqual(world.command_count("--distribution-acquisition-verify"), 3)
                self.assertEqual(world.command_count("--distribution-verify-floor-history"), 1)
                self.assertEqual(world.command_count("--verify-daily-reservation"), 2)
                self.assertEqual(world.command_count("--daily-evidence"), 1)
                for command in ("--parse-collected-release", "--inspect-collected-package", "--collect-terms-link-script"):
                    self.assertEqual(world.command_count(command), 1)
                self.assertEqual(world.remote.ref_updates, 2)  # 原legacyの一回と今回の一回。
                claim = json.loads(world.claim_path().read_bytes())
                self.assertEqual(claim["state"], "SIGNING_INTENT")
                self.assertEqual(claim["generation"], claim["assetGeneration"])
                self.assertEqual(set(claim["inputPins"]), {"scope", "evidence", "release", "inspection", "review", "script"})
                self.assertLessEqual(world.claim_path().stat().st_size, 65536)
                self.assertNotRegex(world.claim_path().read_text(), r"https://|ARTIFICIAL_STATE|payloadUrl|password")
                self.assertEqual(json.loads(world.artifact(".collection-00.json").read_bytes())["httpStatus"], status)
                self.assertTrue(all(seconds <= 600 for _, seconds, _ in world.calls))
                self.assertEqual(pipeline.report(world.config)["purpose"], pipeline.ACQUISITION_PURPOSE)

    def test_fractional_utc_issuance_publication_audits_and_exact_reuse(self):
        """実production関数の200/304発行・公開・再利用を小数秒clockと人工I/Oで通す。"""
        for status in (200, 304):
            with self.subTest(status=status), self.world(status=status) as world:
                world.now = world.now.replace(microsecond=123456)
                world.refresh(status=status)
                originals = deepcopy(world.fixture.originals)
                with patch.object(pipeline.projection, "project_daily_distribution_acquisition",
                        wraps=pipeline.projection.project_daily_distribution_acquisition) as projection_calls, \
                     patch.object(pipeline, "audit_daily_distribution_acquisition_bundle",
                        wraps=pipeline.audit_daily_distribution_acquisition_bundle) as audit_calls:
                    code, result = world.execute(main=True)
                    self.assertEqual((code, result["status"]), (0, "PUBLISHED"))
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                    self.assertEqual(world.command_count("--distribution-acquisition-verify"), 3)
                    self.assertEqual(audit_calls.call_count, 4)
                    publication = world.now.replace(microsecond=0)
                    self.assertTrue(all(call.kwargs["now"] == publication for call in audit_calls.call_args_list))
                    artifacts = {suffix: world.artifact(suffix).read_bytes() for suffix in
                        (".manifest.raw.json", ".index.json.gz", ".manifest.json")}
                    claim_raw = world.claim_path().read_bytes()
                    manifest = json.loads(artifacts[".manifest.raw.json"])
                    expiry = pipeline.parse_time(manifest["expiresAtUtc"])
                    self.assertEqual(pipeline.parse_time(manifest["publishedAtUtc"]), publication)
                    self.assertEqual(expiry.timestamp(), world.receipt["lastSuccessfulValidationAt"] + 8 * 86400)
                    self.assertEqual(result["originalFetchedAt"], world.receipt["lastFetchedAt"])
                    world.calls.clear()
                    world.remote.events.clear()
                    world.now = (world.now + timedelta(seconds=37)).replace(microsecond=765432)
                    audit_start = audit_calls.call_count
                    reused = pipeline.run_acquisition(world.config, world.scope, world.config_hash,
                        world.out / world.now.strftime("%Y%m%d"), world, world.remote)
                    self.assertEqual((reused["status"], reused["resumed"]), ("PUBLISHED", True))
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                    self.assertEqual(world.command_count("--distribution-acquisition-verify"), 3)
                    self.assertEqual(audit_calls.call_count - audit_start, 4)
                    self.assertTrue(all(call.kwargs["now"] == world.now.replace(microsecond=0)
                        for call in audit_calls.call_args_list[audit_start:]))
                    self.assertTrue(all(call.kwargs["published_at"] == publication
                        for call in audit_calls.call_args_list))
                    self.assertTrue(all(call.args[6].microsecond == 0
                        for call in projection_calls.call_args_list))
                    self.assertTrue(all(event[0] == "GET" for event in world.remote.events))
                    self.assertEqual(world.remote.ref_updates, 2)
                    self.assertEqual(world.claim_path().read_bytes(), claim_raw)
                    self.assertEqual({suffix: world.artifact(suffix).read_bytes() for suffix in artifacts}, artifacts)
                    self.assertEqual(pipeline.utc(), world.now)
                    self.assertEqual(world.fixture.originals, originals)

    def test_c13_legacy_bound_cutover_is_not_reissued(self):
        """原世代4を署名floorと実境界へ結び、準備で署名・収集・配布しない。"""
        from types import SimpleNamespace
        import prepare_daily_index_config as prepare
        with self.world() as world:
            with self.subTest(variant="legacy-gen4-cutover"):
                commands = [argv[1] for argv, _, _ in world.preparation_calls]
                self.assertEqual(commands, ["--verify-daily-reservation", "--distribution-verify-floor-history"])
                self.assertEqual(world.preparation_calls[0][0][-1], "LEGACY_FENCE")
                self.assertEqual(world.config["legacyMetadata"]["kind"], "LEGACY_METADATA_BOUND")
                self.assertEqual(world.config["legacyReservationFence"]["generation"], 4)
                self.assertEqual(set(world.config["modulePins"]), pipeline.MODULE_NAMES)
                self.assertEqual(len(world.config["modulePins"]), 4)
                old = json.loads(world.args.inherit_config.read_bytes())
                for name in ("outputRoot", "smokeLocal", "firstDailyLocal", "stateRoot", "fingerprint"):
                    self.assertEqual(old[name], world.config[name])
                self.assertEqual(world.calls, [])
                self.assertFalse(world.claim_path().exists())
            with self.subTest(variant="bin-path-before-native"):
                untrusted = world.args.inherit_config.parent / "untrusted.exe"
                untrusted.write_bytes(b"ARTIFICIAL_NOT_EXECUTABLE")
                changed = dict(vars(world.args), collector_exe=untrusted,
                               control_directory=world.control.parent / "rejected")
                with self.assertRaisesRegex(ValueError, "^PROTECTED_VERSIONED_BIN$"):
                    prepare.inherit_config(SimpleNamespace(**changed), budget=world)
                self.assertEqual(world.calls, [])
                self.assertFalse(changed["control_directory"].exists())

    def test_c14_only_actual_generation_above_fence(self):
        """旧世代とcaller固定世代のnative head不一致を、鍵呼出し前に拒否する。"""
        for generation, reason in ((4, "LEGACY_GENERATION_NOT_ISSUABLE"),
                                   (3, "LEGACY_GENERATION_NOT_ISSUABLE"), (5, "DAILY_RESERVATION_HEAD")):
            with self.subTest(generation=generation), self.world() as world:
                world.refresh(generation=generation)
                world.head_generation = 9
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertFalse(any(method != "GET" for method, _, _ in world.remote.events))

    def test_c15_claim_fields_are_immutable(self):
        """同世代claimの十二拘束field差を全て保存conflictとして停止する。"""
        fields = ("rawManifestSha256", "gzipSha256", "inputPins", "purpose", "fingerprint", "publishedAtUtc",
                  "expiresAtUtc", "legacyReservationFence", "scopeSha256", "keyId", "generation", "assetGeneration")
        for field in fields:
            with self.subTest(field=field), self.world() as world:
                self.stop_before_publication(world)
                claim = json.loads(world.claim_path().read_bytes())
                claim[field] = "ARTIFICIAL_CONFLICT"
                world.claim_path().write_bytes(pipeline.canonical(claim))
                world.calls.clear()
                with self.assertRaisesRegex(ValueError, "^ISSUANCE_CLAIM_CONFLICT$"):
                    world.execute()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_c16_original_envelope_resumes_without_signing(self):
        """未公開の有効原envelopeを再検査し、再署名せず同じPublisherへ進める。"""
        with self.subTest(variant="original-envelope-before-publisher"), self.world() as world:
            self.stop_before_publication(world)
            original = world.artifact(".manifest.json").read_bytes()
            world.calls.clear()
            result = world.execute()
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
            self.assertEqual(world.command_count("--distribution-acquisition-verify"), 3)
            self.assertEqual(world.artifact(".manifest.json").read_bytes(), original)

    def test_c17_signing_unknown_never_resigns(self):
        """欠損・部分・非0・timeout・起動前crashの全曖昧境界で再PSSを拒否する。"""
        for variant in ("missing", "partial", "nonzero", "timeout", "before-invoke", "result-before-record-crash"):
            with self.subTest(variant=variant), self.world() as world:
                world.sign_behavior = variant
                expected_error = SystemExit if variant == "result-before-record-crash" else ValueError
                expected_reason = "ARTIFICIAL_RESULT_RECORD_CRASH" if variant == "result-before-record-crash" else "SIGNING_OUTCOME_UNKNOWN"
                with self.assertRaisesRegex(expected_error, "^"+expected_reason+"$"):
                    world.execute()
                self.assertTrue(world.claim_path().exists())
                original_claim = world.claim_path().read_bytes()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                old_envelope = world.artifact(".manifest.json").read_bytes() if world.artifact(".manifest.json").exists() else None
                unknown = {path.name: path.read_bytes() for path in world.out.glob("*.terminal-*.json")}
                if variant in {"nonzero", "timeout"}:
                    self.assertTrue(any(json.loads(raw).get("signingOutcome") == "NATIVE_OUTCOME_UNKNOWN" for raw in unknown.values()))
                    pipeline.write_new(world.artifact(".terminal-9999999999999999999.json"), pipeline.canonical({
                        "status": "FAILED", "reason": "PIPELINE_EXCEPTION", "configSha256": world.config_hash}))
                    pipeline.write_new(world.out / "20261018.terminal-9999999999999999999.json", pipeline.canonical({
                        "status": "FAILED", "reason": "PIPELINE_EXCEPTION", "configSha256": world.config_hash}))
                if variant == "result-before-record-crash":
                    self.assertEqual(unknown, {})
                world.calls.clear()
                with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                    world.execute()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.claim_path().read_bytes(), original_claim)
                self.assertTrue(all((world.out / name).read_bytes() == raw for name, raw in unknown.items()))
                if old_envelope is not None:
                    self.assertEqual(world.artifact(".manifest.json").read_bytes(), old_envelope)
                self.assertEqual(world.remote.events, [])

    def test_c18_missing_bindings_are_not_reconstructed_from_remote(self):
        """claimなしenvelopeと旧metadata拘束の欠損・改変を拒否する。"""
        for variant, reason in (("envelope-without-claim", "ISSUANCE_ENVELOPE_WITHOUT_CLAIM"),
                                ("legacy-file-missing", "MISSING_PATH"), ("legacy-byte-mismatch", "LEGACY_METADATA_BINDING")):
            with self.subTest(variant=variant), self.world() as world:
                if variant == "envelope-without-claim":
                    world.artifact(".manifest.json").write_bytes(b"UNBOUND_UNSIGNED_SHAPE_ONLY")
                    action = world.execute
                elif variant == "legacy-file-missing":
                    world.args.legacy_envelope.unlink()
                    action = lambda: pipeline.load_config(world.config_path)
                else:
                    world.args.legacy_envelope.write_bytes(b"UNBOUND")
                    action = lambda: pipeline.load_config(world.config_path)
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    action()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.remote.events, [])

    def test_c19_history_chooses_one_explicit_profile(self):
        """失効metadataと失効取得索引を各専用historyだけで確認し、新currentへ進む。"""
        for variant in ("expired-metadata-history", "expired-acquisition-history"):
            with self.subTest(variant=variant), self.world() as world:
                if variant == "expired-acquisition-history":
                    world.execute()
                    world.now += timedelta(days=1)
                    world.refresh(generation=10)
                world.calls.clear()
                result = world.execute()
                self.assertEqual(result["status"], "PUBLISHED")
                expected = "--distribution-acquisition-verify-history" if "acquisition" in variant else "--distribution-verify-floor-history"
                other = "--distribution-verify-floor-history" if "acquisition" in variant else "--distribution-acquisition-verify-history"
                self.assertEqual(world.command_count(expected), 1)
                self.assertEqual(world.command_count(other), 0)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)

    def test_c20_unknown_profile_future_and_expiry_are_refused(self):
        """未知binding、誤profile、未来発行と失効をnative fallbackなしで拒否する。"""
        cases = (("unknown-history-binding", "SIGNING_PROFILE_UNKNOWN"),
                 ("wrong-native-profile", "NATIVE_DISTRIBUTION_VERIFY_FAILED"),
                 ("future-publication", "ACQUISITION_PUBLICATION_TIME"), ("expired-candidate", "DAILY_OBSERVATION_TIME"))
        for variant, reason in cases:
            with self.subTest(variant=variant), self.world() as world:
                if variant == "unknown-history-binding":
                    manifest, raw = pipeline.unpack_envelope(world.legacy_bundle["manifest.json"])
                    manifest["generation"] = 77
                    changed = envelope(pipeline.canonical(manifest), manifest["keyId"])
                    release = next(iter(world.remote.releases.values()))
                    asset = next(row for row in release["assets"] if row["name"] == "manifest.json")
                    world.remote.assets[asset["id"]] = changed
                    asset["size"] = len(changed)
                    world.remote.blobs[next(iter(world.remote.blobs))] = changed
                elif variant == "wrong-native-profile":
                    world.fail_verify = "--distribution-acquisition-verify"
                else:
                    self.stop_before_publication(world)
                    world.calls.clear()
                    if variant == "future-publication":
                        manifest = json.loads(world.artifact(".manifest.raw.json").read_bytes())
                        manifest["publishedAtUtc"] = (world.now + timedelta(seconds=1)).isoformat()
                        world.artifact(".manifest.raw.json").write_bytes(pipeline.canonical(manifest))
                    else:
                        world.now += timedelta(days=1)
                        # 同じ元prefixを明示再開するため、時計だけexpiry境界を模擬する。
                        with patch.object(pipeline, "utc", return_value=world.now), self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                            pipeline.run_acquisition(world.config, world.scope, world.config_hash,
                                world.out / "20261017", world, world.remote)
                        continue
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    world.execute()
                self.assertFalse(any(method != "GET" for method, _, _ in world.remote.events))
                self.assertEqual(world.command_count("--distribution-verify"), 0)

    def test_c21_remote_failures_keep_old_current(self):
        """upload/readback/publish/余剰asset/foreign branch/CASの原失敗と旧currentを保持する。"""
        cases = (("upload", "FAKE_UPLOAD_FAILURE"), ("readback", "REMOTE_ASSET_SIZE"),
                 ("publish", "FAKE_PUBLISH_FAILURE"), ("extra-asset", "REMOTE_ASSET_COUNT"),
                 ("foreign-branch", "BRANCH_FOREIGN_CONTENT"), ("cas", "FAKE_CAS_CONFLICT"))
        for failure, reason in cases:
            with self.subTest(failure=failure), self.world() as world:
                if failure == "extra-asset":
                    next(iter(world.remote.releases.values()))["assets"].append({"name": "payload.zip"})
                elif failure == "foreign-branch":
                    world.remote.foreign = True
                else:
                    world.remote.failure = failure
                before = world.remote.ref_updates
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    world.execute()
                self.assertEqual(world.remote.head, world.old_head)
                self.assertLessEqual(world.remote.ref_updates - before, 1)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assertFalse(world.artifact(".success.json").exists())

    def test_c22_unknown_cas_exact_readback_only_resume(self):
        """CAS応答喪失・最終確認喪失後は同原byteを確認し、upload/CASを繰り返さない。"""
        for variant in ("cas-reply-lost", "confirmation-lost"):
            with self.subTest(variant=variant), self.world() as world:
                api = world.remote.api
                def lose(method, path, *args, **kwargs):
                    """外部作用した人工CASの後だけ一回の応答を失う。"""
                    result = api(method, path, *args, **kwargs)
                    if ((variant == "cas-reply-lost" and path == "graphql") or
                            (variant == "confirmation-lost" and path.endswith("git/ref/heads/driver-index") and
                             world.remote.head != world.old_head)):
                        raise ValueError("ARTIFICIAL_CAS_REPLY_UNKNOWN")
                    return result
                with patch.object(world.remote, "api", lose), self.assertRaisesRegex(ValueError, "^ARTIFICIAL_CAS_REPLY_UNKNOWN$"):
                    world.execute()
                terminals = list(world.out.glob("20261017.terminal-*.json"))
                self.assertTrue(any(json.loads(path.read_bytes()).get("publicationOutcome") == "CAS_INTENT_UNKNOWN" for path in terminals))
                original_terminals = {path.name: path.read_bytes() for path in terminals}
                writes = sum(method != "GET" for method, _, _ in world.remote.events)
                cas = world.remote.ref_updates
                world.calls.clear()
                result = world.execute()
                self.assertEqual(result["status"], "PUBLISHED")
                self.assertTrue(result["resumed"])
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.remote.ref_updates, cas)
                self.assertEqual(sum(method != "GET" for method, _, _ in world.remote.events), writes)
                self.assertTrue(all((world.out / name).read_bytes() == raw for name, raw in original_terminals.items()))

    def test_c23_unknown_cas_cannot_use_other_bytes_or_expiry(self):
        """不明CASから別current・未知高世代・失効へ進まず、追加remote作用を拒否する。"""
        for variant, reason in (("different-byte", "CURRENT_CAS_OUTCOME_UNKNOWN"),
                                ("higher-unknown-generation", "SIGNING_PROFILE_UNKNOWN"),
                                ("expired-resume", "DAILY_OBSERVATION_TIME")):
            with self.subTest(variant=variant), self.world() as world:
                world.remote.failure = "cas"
                with self.assertRaisesRegex(ValueError, "^FAKE_CAS_CONFLICT$"):
                    world.execute()
                world.remote.failure = None
                world.calls.clear()
                world.remote.events.clear()
                if variant == "higher-unknown-generation":
                    original = world.remote.blobs[next(iter(world.remote.blobs))]
                    manifest, _ = pipeline.unpack_envelope(original)
                    manifest["generation"] = 99
                    changed = envelope(pipeline.canonical(manifest), manifest["keyId"])
                    world.remote.blobs[next(iter(world.remote.blobs))] = changed
                    release = next(iter(world.remote.releases.values()))
                    asset = next(row for row in release["assets"] if row["name"] == "manifest.json")
                    world.remote.assets[asset["id"]] = changed
                    asset["size"] = len(changed)
                if variant == "expired-resume":
                    world.now += timedelta(days=1)
                    with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                        pipeline.run_acquisition(world.config, world.scope, world.config_hash,
                            world.out / "20261017", world, world.remote)
                else:
                    with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                        world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertFalse(any(method != "GET" for method, _, _ in world.remote.events))

    def test_c24_inherited_start_root_channel_and_schedule_are_fixed(self):
        """同日config差と出力root/取得scope/元日程の変更を拒否する。"""
        cases = (("different-start-config", "RESUME_BYTES_CONFLICT"), ("different-output-root", "INHERIT_OUTPUT_ROOT"),
                 ("different-channel", "DISTRIBUTION_SCOPE_BINDING"), ("schedule-reset", "INHERIT_SCHEDULE_IMMUTABLE"))
        for variant, reason in cases:
            with self.subTest(variant=variant), self.world() as world:
                if variant == "different-start-config":
                    world.artifact(".start.json").write_bytes(pipeline.canonical({"schema": "dc-daily-start-v1",
                        "configSha256": "ORIGINAL_FAILED_CONFIG", "day": "20261017"}))
                    action = world.execute
                elif variant == "different-output-root":
                    world.config["outputRoot"] = str(world.out.parent / "other")
                    action = lambda: pipeline.validate_legacy_metadata(world.config)
                elif variant == "different-channel":
                    action = lambda: pipeline.projection._validate_distribution_scope(dict(world.scope, sourceId="other"))
                else:
                    world.config["firstDailyLocal"] = "2026-10-23T15:00:00+09:00"
                    action = lambda: pipeline.validate_legacy_metadata(world.config)
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    action()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_c25_v1_metadata_and_module_contract_are_preserved(self):
        """旧v1の正常mainとroot/scripts限定を、暗黙昇格せず確認する。"""
        for variant in ("old-v1-main", "v1-module-location"):
            with self.subTest(variant=variant), self.world() as world:
                if variant == "v1-module-location":
                    with self.assertRaisesRegex(ValueError, "^SCRIPT_PIN$"):
                        pipeline.load_config(world.args.inherit_config)
                    continue
                with patch.object(pipeline, "__file__", str(world.root / "scripts/daily_index_pipeline.py")), \
                     patch.object(pipeline.projection, "__file__", str(world.root / "scripts/project_collected_native_index.py")), \
                     patch.object(pipeline.cr, "__file__", str(world.root / "scripts/collector_registry.py")):
                    config, scope, digest = pipeline.load_config(world.args.inherit_config)
                    self.assertEqual(config["schema"], "dc-private-daily-index-config-v1")
                    self.assertNotIn("purpose", config)
                    world.receipt = world.make_receipt(world.now, 9, 200)
                    original_run = world.run
                    def legacy_run(argv, *a, **kw):
                        """旧signだけを旧metadata envelope出力へ結ぶ。"""
                        if argv[1] == "--distribution-sign":
                            world.calls.append((list(argv), 600, pipeline.MAX_FILE))
                            pipeline.write_new(Path(argv[4]), envelope(pipeline.read(Path(argv[2])), scope["keyId"]))
                            return 0, b"", b""
                        return original_run(argv, *a, **kw)
                    with patch.object(world, "run", legacy_run):
                        result = pipeline.run_pipeline(config, scope, digest, budget=world, remote=world.remote)
                    self.assertEqual(result["status"], "PUBLISHED")
                    self.assertEqual(world.command_count("--distribution-sign"), 1)
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)

    def test_c26_public_privacy_and_two_assets_before_sign(self):
        """秘密・local path・第三assetを署名前の共通監査またはPublisher入口で拒否する。"""
        cases = (("secret", "PUBLIC_PRIVACY_SECRET"), ("local-path", "PUBLIC_PRIVACY"), ("third-asset", "ASSET_ALLOWLIST"))
        for variant, reason in cases:
            with self.subTest(variant=variant), self.world() as world:
                if variant == "third-asset":
                    action = lambda: pipeline.Publisher(world.remote, lambda *a, **kw: None).publish(
                        dict(world.legacy_bundle, **{"payload.zip": b"ARTIFICIAL"}))
                else:
                    world.fixture.inspection["infs"][0]["verifiedPublisher"] = "password=artificial" if variant == "secret" else "C:\\private\\publisher"
                    action = world.execute
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    action()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertFalse(world.claim_path().exists())
                self.assertEqual(world.remote.events, [])

    def test_c27_existing_finite_limits_are_not_reset(self):
        """process/実時間/収集attempt/terminalの元上限で停止する。"""
        for variant, reason in (("process97", "PROCESS_COUNT"), ("total-timeout", "TOTAL_TIMEOUT"),
                                ("collection33", "DAILY_ATTEMPT_COUNT"), ("terminal65", "REPORT_ATTEMPT_LIMIT")):
            with self.subTest(variant=variant), self.world() as world:
                if variant == "process97":
                    budget = pipeline.Budget()
                    budget.calls = 96
                    action = lambda: budget.run(["NO_PROCESS"])
                elif variant == "total-timeout":
                    budget = pipeline.Budget()
                    budget.end = 0
                    action = budget.remaining
                elif variant == "collection33":
                    for index in range(33):
                        world.artifact(f".collection-{index:02d}.json").write_bytes(b"{}")
                    action = world.execute
                else:
                    for index in range(65):
                        world.artifact(f".terminal-{index:02d}.json").write_bytes(b"{}")
                    action = lambda: pipeline.report(world.config)
                with self.assertRaisesRegex(ValueError, "^"+reason+"$"):
                    action()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_c28_seven_original_days_and_smoke_are_preserved(self):
        """元七日分母と旧FAILED/config hash/未実行を保持し、smokeを分母へ加えない。"""
        for variant in ("seven-original-days", "smoke-excluded"):
            with self.subTest(variant=variant), self.world() as world:
                old = pipeline.canonical({"status": "FAILED", "reason": "ORIGINAL_GITHUB_FAILURE",
                    "configSha256": "ORIGINAL_CONFIG_SHA"})
                old_path = world.out / "20261016.terminal-1.json"
                old_path.write_bytes(old)
                (world.out / "20261015.success.json").write_bytes(pipeline.canonical({"status": "PUBLISHED", "generation": 4}))
                world.execute()
                if variant == "seven-original-days":
                    world.now += timedelta(days=3)
                report = pipeline.report(world.config)
                self.assertEqual(report["denominator"], 7)
                self.assertEqual(len(report["days"]), 7)
                self.assertEqual([row["scheduledLocal"][:10] for row in report["days"]], [f"2026-10-{day}" for day in range(16, 23)])
                self.assertEqual(report["days"][0]["status"], "FAILED")
                self.assertEqual(report["days"][0]["configSha256"], "ORIGINAL_CONFIG_SHA")
                self.assertTrue(report["smokeExcluded"])
                self.assertEqual(old_path.read_bytes(), old)
                self.assertEqual(report["days"][1]["purpose"], pipeline.ACQUISITION_PURPOSE)
                if variant == "seven-original-days":
                    self.assertEqual(report["days"][2]["status"], "NOT_RUN")


    def test_c29_original_digest_case_values_preserve_bytes(self):
        """実失敗した原入力読取とpreparerを通し、hex表記だけを値照合する。"""
        import prepare_daily_index_config as prepare
        expected = "2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5"
        forms = (expected, expected.upper(), "".join(c.upper() if i % 2 else c for i, c in enumerate(expected)))
        for published in forms:
            with self.subTest(published=published), self.world() as world:
                release = json.loads(world.args.original_release.read_bytes())
                release["publishedSha256"] = published
                original = pipeline.canonical(release)
                world.args.original_release.write_bytes(original)
                world.config["originalInputs"]["release"]["sha256"] = pipeline.sha(original)
                before = {name: Path(entry["file"]).read_bytes()
                          for name, entry in world.config["originalInputs"].items()}
                for configured in forms:
                    with self.subTest(configured=configured):
                        config = dict(world.config, archiveSha256=configured)
                        originals, pins = pipeline.acquisition_originals(config)
                        self.assertEqual(originals, before)
                        self.assertEqual(pins, {name: pipeline.sha(raw) for name, raw in before.items()})
                        self.assertEqual(config["archiveSha256"], configured)
                args = SimpleNamespace(**(vars(world.args) | {"control_directory": world.control.parent / "case-check"}))
                prepared = prepare.inherit_config(args, budget=world)
                self.assertTrue(prepared.exists())
                self.assertEqual(world.args.original_release.read_bytes(), original)
                self.assertEqual({name: Path(entry["file"]).read_bytes()
                                  for name, entry in world.config["originalInputs"].items()}, before)
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.remote.events, [])

    def test_c30_original_digest_invalid_values_refused(self):
        """原release/configの別値・型・長さ・非ASCII hex・空白をeffect前に拒否する。"""
        expected = "2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5"
        values = ("0" * 64, None, True, 64, [], {}, "", expected[:-1], expected + "0",
                  "g" + expected[1:], "Ａ" + expected[1:], " " + expected, expected + " ", expected + "\n")
        for field in ("publishedSha256", "archiveSha256"):
            for value in values:
                with self.subTest(field=field, value=value), self.world() as world:
                    config = deepcopy(world.config)
                    if field == "publishedSha256":
                        release = json.loads(world.args.original_release.read_bytes())
                        release[field] = value
                        world.args.original_release.write_bytes(pipeline.canonical(release))
                        config["originalInputs"]["release"]["sha256"] = pipeline.sha(world.args.original_release.read_bytes())
                    else:
                        config[field] = value
                    before = world.args.original_release.read_bytes()
                    reason = "ACQUISITION_ARCHIVE_BINDING" if value == "0" * 64 else "NATIVE_PUBLIC_DIGEST"
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        pipeline.acquisition_originals(config)
                    self.assertEqual(world.args.original_release.read_bytes(), before)
                    self.assertEqual(world.calls, [])
                    self.assertEqual(world.remote.events, [])

    def test_c31_inherited_day_entry_and_shared_artifacts(self):
        """正当な旧startとmetadata出力を不変に保ち、用途別成功と同一byte再開を確認する。"""
        with self.world() as world:
            old_hash = world.config["legacyMetadata"]["configSha256"]
            old_start = pipeline.canonical({"schema": "dc-daily-start-v1", "configSha256": old_hash, "day": "20261017"})
            legacy = {".start.json": old_start, ".manifest.raw.json": b"ARTIFICIAL_LEGACY_RAW",
                      ".index.json.gz": b"ARTIFICIAL_LEGACY_GZIP", ".manifest.json": b"ARTIFICIAL_LEGACY_ENVELOPE",
                      ".success.json": pipeline.canonical({"status": "PUBLISHED", "configSha256": old_hash, "generation": 4}),
                      ".terminal-1.json": pipeline.canonical({"status": "PUBLISHED", "configSha256": old_hash, "generation": 4})}
            for suffix, raw in legacy.items():
                (world.out / ("20261017" + suffix)).write_bytes(raw)
            receipt_path = world.out / "20261017.collection-00.json"
            receipt_path.write_bytes(pipeline.canonical(world.receipt))
            receipt_raw = receipt_path.read_bytes()
            before_report = pipeline.report(world.config)["days"][1]
            result = world.execute()
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertNotEqual(before_report["status"], "PUBLISHED")
            self.assertEqual(before_report["legacyMetadataResult"]["configSha256"], old_hash)
            self.assertEqual(world.command_count("--daily-evidence"), 0)
            marker = world.out / "20261017.acquisition.start.json"
            original_marker = marker.read_bytes()
            binding = json.loads(original_marker)
            self.assertEqual(binding["legacyStartSha256"], pipeline.sha(old_start))
            self.assertEqual(binding["legacyConfigSha256"], old_hash)
            self.assertEqual(binding["configSha256"], world.config_hash)
            self.assertEqual(binding["day"], "20261017")
            self.assertEqual(binding["purpose"], pipeline.ACQUISITION_PURPOSE)
            self.assertTrue((world.out / "20261017.acquisition.success.json").exists())
            world.calls.clear()
            world.remote.events.clear()
            resumed = world.execute()
            self.assertEqual(resumed["status"], "PUBLISHED")
            self.assertEqual(world.command_count("--daily-evidence"), 0)
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
            self.assertFalse(any(method != "GET" for method, _, _ in world.remote.events))
            self.assertEqual(marker.read_bytes(), original_marker)
            self.assertEqual(receipt_path.read_bytes(), receipt_raw)
            for suffix, raw in legacy.items():
                self.assertEqual((world.out / ("20261017" + suffix)).read_bytes(), raw)
            row = pipeline.report(world.config)["days"][1]
            self.assertEqual(row["purpose"], pipeline.ACQUISITION_PURPOSE)
            self.assertEqual(row["legacyMetadataResult"]["generation"], 4)

    def test_c32_foreign_malformed_legacy_entry_precedes_effects(self):
        """旧startのforeign hash・schema・日付・余分field・不正JSONを一律exact拒否する。"""
        for variant in ("foreign", "schema", "day", "extra", "malformed", "spacing"):
            with self.subTest(variant=variant), self.world() as world:
                value = {"schema": "dc-daily-start-v1", "configSha256": world.config["legacyMetadata"]["configSha256"], "day": "20261017"}
                if variant in {"foreign", "schema", "day"}:
                    value[{"foreign": "configSha256", "schema": "schema", "day": "day"}[variant]] = "FOREIGN"
                if variant == "extra":
                    value["extra"] = True
                raw = b"{" if variant == "malformed" else pipeline.canonical(value) + (b" " if variant == "spacing" else b"")
                marker = world.out / "20261017.start.json"
                marker.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, "^RESUME_BYTES_CONFLICT$"):
                    world.execute()
                self.assertEqual(marker.read_bytes(), raw)
                self.assertFalse((world.out / "20261017.acquisition.start.json").exists())
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_c33_changed_acquisition_entry_precedes_effects(self):
        """現在configと取得startの改変、旧startの出現／消失を再開effect前に拒否する。"""
        for variant in ("config", "marker", "malformed", "legacy-appeared", "legacy-disappeared"):
            with self.subTest(variant=variant), self.world() as world:
                legacy = world.out / "20261017.start.json"
                old_start = pipeline.canonical({"schema": "dc-daily-start-v1",
                    "configSha256": world.config["legacyMetadata"]["configSha256"], "day": "20261017"})
                if variant == "legacy-disappeared":
                    legacy.write_bytes(old_start)
                world.execute()
                marker = world.out / "20261017.acquisition.start.json"
                if variant == "config":
                    world.config["archiveSha256"] = world.config["archiveSha256"].upper()
                    world.config_path.write_bytes(pipeline.canonical(world.config))
                    world.config, world.scope, world.config_hash = pipeline.load_config(world.config_path)
                elif variant in {"marker", "malformed"}:
                    changed = json.loads(marker.read_bytes())
                    changed["configSha256"] = "0" * 64
                    marker.write_bytes(b"{" if variant == "malformed" else pipeline.canonical(changed))
                elif variant == "legacy-appeared":
                    legacy.write_bytes(old_start)
                else:
                    legacy.unlink()
                before = marker.read_bytes()
                world.calls.clear()
                world.remote.events.clear()
                with self.assertRaisesRegex(ValueError, "^RESUME_BYTES_CONFLICT$"):
                    world.execute()
                self.assertEqual(marker.read_bytes(), before)
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_c34_v1_entry_resume_and_mismatch(self):
        """v1同configの成功再開と変更config拒否を、新用途へ昇格せず維持する。"""
        with self.world() as world:
            config, scope, digest = pipeline.load_config(world.args.inherit_config, inherited_v1=True)
            marker = world.out / "20261017.start.json"
            raw = pipeline.canonical({"schema": "dc-daily-start-v1", "configSha256": digest, "day": "20261017"})
            marker.write_bytes(raw)
            success = {"status": "PUBLISHED", "configSha256": digest, "generation": 4}
            (world.out / "20261017.success.json").write_bytes(pipeline.canonical(success))
            self.assertEqual(pipeline.run_pipeline(config, scope, digest, budget=world, remote=world.remote), success)
            with self.assertRaisesRegex(ValueError, "^RESUME_BYTES_CONFLICT$"):
                pipeline.run_pipeline(config, scope, "0" * 64, budget=world, remote=world.remote)
            self.assertEqual(marker.read_bytes(), raw)
            self.assertFalse((world.out / "20261017.acquisition.start.json").exists())
            self.assertEqual(world.calls, [])
            self.assertEqual(world.remote.events, [])

    def test_c35_shared_day_limits_and_lock(self):
        """共通lock・旧receipt32枠・元expiryを入口分離で回避できない。"""
        for variant, reason in (("lock", "PIPELINE_ALREADY_RUNNING"), ("attempt32", "DAILY_ATTEMPT_COUNT"),
                                ("expired", "OUTSIDE_OBSERVATION_WINDOW")):
            with self.subTest(variant=variant), self.world() as world:
                if variant == "attempt32":
                    for index in range(32):
                        (world.out / f"20261017.collection-{index:02d}.json").write_bytes(b'{"outcome":"FAILED"}')
                if variant == "expired":
                    world.now = pipeline.parse_time(world.config["firstDailyLocal"]) + timedelta(days=7)
                with ExitStack() as stack:
                    if variant == "lock":
                        stack.enter_context(pipeline.exclusive(world.out / "pipeline.lock"))
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        world.execute()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])
                self.assertEqual(list(world.out.glob("*.acquisition.collection-*.json")), [])
                self.assertEqual(pipeline.MAX_SECONDS, 1800)
                self.assertEqual(pipeline.MAX_WAIT, 300)


class ReceiptAnchorAndRepairTests(unittest.TestCase):
    """ADR0374の実policy接続と一段だけの修復継承を人工fileで検証する。"""

    world = DailyAcquisitionIssuanceTests.world
    real_protected_path = staticmethod(pipeline.protected_path)
    real_protected_tree = staticmethod(pipeline.protected_tree)
    real_operation_root = staticmethod(pipeline.operation_root)

    @contextmanager
    def policy(self, root, *, bad_path=None, bad_kind=None):
        """OS問い合わせだけを人工snapshotへ替え、実path/ACL policyは一切置換しない。"""
        def snapshot(path):
            """専用rootのみ保護済み、operation以下は継承済みの信頼ACLを返す。"""
            owner = "S-1-5-32-544"
            protected = path == root
            entries = [(0, 0, 0x1f01ff, "S-1-5-18"), (0, 0, 0x1f01ff, owner),
                       (0, 0, 0x1200a9, "S-1-5-32-545")]
            if path == bad_path:
                if bad_kind == "owner":
                    owner = "S-1-5-32-545"
                elif bad_kind == "protected":
                    protected = False
                else:
                    entries.append((0, 0, 0x40 if bad_kind == "ancestor" else 0x100, "S-1-5-32-545"))
            return owner, protected, entries
        with patch.object(pipeline, "protected_root", return_value=root), \
                patch.object(pipeline, "acl_snapshot", side_effect=snapshot), \
                patch.object(pipeline, "protected_path", self.real_protected_path), \
                patch.object(pipeline, "protected_tree", self.real_protected_tree), \
                patch.object(pipeline, "operation_root", self.real_operation_root):
            yield

    def transition(self, world):
        """旧config/start/receiptを保持し、新codeと同byte nativeの人工versionを準備する。"""
        import prepare_daily_index_config as prepare
        start = world.artifact(".acquisition.start.json")
        legacy = world.artifact(".start.json")
        legacy.write_bytes(pipeline.canonical({"schema": "dc-daily-start-v1",
            "configSha256": world.config["legacyMetadata"]["configSha256"], "day": world.now.strftime("%Y%m%d")}))
        start.write_bytes(pipeline.canonical({"schema": "dc-daily-acquisition-start-v1",
            "purpose": pipeline.ACQUISITION_PURPOSE, "configSha256": world.config_hash,
            "legacyConfigSha256": world.config["legacyMetadata"]["configSha256"],
            "legacyStartSha256": pipeline.sha(legacy.read_bytes()), "day": world.now.strftime("%Y%m%d")}))
        receipt = world.artifact(".collection-00.json")
        receipt.write_bytes(pipeline.canonical(world.receipt))
        predecessor = world.config_path
        version = world.root / "scripts/v2-artificial-repair"
        binary = world.root / "bin" / version.name
        version.mkdir()
        binary.mkdir(parents=True)
        for name in pipeline.MODULE_NAMES:
            raw = (world.version / name).read_bytes()
            (version / name).write_bytes(raw + (b"_CODE_REPAIR" if name in
                {"daily_index_pipeline.py", "prepare_daily_index_config.py"} else b""))
        for source in (world.collector, world.signer):
            (binary / source.name).write_bytes(source.read_bytes())
        for owner, name, path in ((pipeline, "__file__", version / "daily_index_pipeline.py"),
            (pipeline.projection, "__file__", version / "project_collected_native_index.py"),
            (pipeline.cr, "__file__", version / "collector_registry.py"),
            (prepare, "__file__", version / "prepare_daily_index_config.py")):
            world.stack.enter_context(patch.object(owner, name, str(path)))
        world.predecessor_bytes = {path: path.read_bytes() for path in (predecessor, start, legacy, receipt)}
        world.calls.clear()
        return SimpleNamespace(repair_config=predecessor, predecessor_config_sha256=world.config_hash,
            predecessor_start=start, predecessor_start_sha256=pipeline.sha(start.read_bytes()),
            continuation_receipt=receipt, continuation_receipt_sha256=pipeline.sha(receipt.read_bytes()),
            prior_native_calls=1, prior_elapsed_seconds=0.7296035,
            control_directory=world.root / "control/code-repair", collector_exe=binary / world.collector.name,
            signer_exe=binary / world.signer.name)

    def accept(self, world, args):
        """実preparer/loadを人工Budgetへ接続し、前世代の全byte保持を確認する。"""
        import prepare_daily_index_config as prepare
        world.config_path = prepare.repair_config(args, budget=world)
        world.config, world.scope, world.config_hash = pipeline.load_config(world.config_path)
        self.assertEqual([argv[1] for argv, _, _ in world.calls],
                         ["--verify-daily-reservation", "--distribution-verify-floor-history"])
        self.assertEqual(world.calls[0][0][-1], "FRESH_INPUT")
        self.assertEqual(world.config["legacyReservationFence"]["generation"], 4)
        for path, raw in world.predecessor_bytes.items():
            self.assertEqual(path.read_bytes(), raw)
        world.calls.clear()

    def test_r01_real_policy_anchor_connection(self):
        """旧root指定は実policyで拒否され、修正callから内容準備/署名fakeまで接続する。"""
        with self.world() as world:
            path = world.artifact(".collection-00.json")
            path.write_bytes(pipeline.canonical(world.receipt))
            with self.policy(world.root):
                with self.assertRaisesRegex(ValueError, "^PROTECTED_DACL_REQUIRED$"):
                    pipeline.protected_path(path, root=world.out)
                pipeline.protected_path(path, root=world.root)
                result = world.execute()
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(world.command_count("--daily-evidence"), 0)
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)

    def test_r02_policy_refusals_remain_connected(self):
        """owner/専用保護flag/内外祖先write/hardlink/reparse/包含を実policyで拒否する。"""
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "protected"
            directory = root / "operations/job"
            directory.mkdir(parents=True)
            path = directory / "receipt.json"
            path.write_bytes(b"ARTIFICIAL")
            for target, kind, reason in ((path, "owner", "PROTECTED_OWNER"),
                (root, "protected", "PROTECTED_DACL_REQUIRED"),
                (directory, "write", "PROTECTED_GENERAL_USER_WRITE"),
                (root / "operations", "write", "PROTECTED_GENERAL_USER_WRITE"),
                (root.parent, "ancestor", "PROTECTED_GENERAL_USER_WRITE")):
                with self.subTest(kind=kind, target=target), self.policy(root, bad_path=target, bad_kind=kind):
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        pipeline.protected_path(path, root=root)
            with self.policy(root):
                with self.assertRaisesRegex(ValueError, "^PROTECTED_OPERATION_ROOT$"):
                    pipeline.operation_root(root)
                with patch.object(Path, "is_junction", return_value=True):
                    with self.assertRaisesRegex(ValueError, "^REPARSE_PATH$"):
                        pipeline.protected_path(path, root=root)
                os.link(path, directory / "second-link.json")
                with self.assertRaisesRegex(ValueError, "^PROTECTED_HARDLINK$"):
                    pipeline.protected_path(path, root=root)

    def test_r03_exact_transition_and_same_byte_resume(self):
        """同じreceiptから再収集せず一回だけ署名し、新旧startと原byteを保持する。"""
        with self.world() as world:
            args = self.transition(world)
            self.accept(world, args)
            first = world.execute()
            marker = world.artifact(".acquisition.code-repair.json")
            frozen = marker.read_bytes()
            again = world.execute()
            self.assertEqual((first["status"], again["status"]), ("PUBLISHED", "PUBLISHED"))
            self.assertEqual(marker.read_bytes(), frozen)
            self.assertEqual(world.command_count("--daily-evidence"), 0)
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
            for path, raw in world.predecessor_bytes.items():
                self.assertEqual(path.read_bytes(), raw)

    def test_r04_stale_predecessor_pins_precede_effects(self):
        """明示config/start/receipt hashが異なればnativeも新controlも作らない。"""
        import prepare_daily_index_config as prepare
        for field in ("predecessor_config_sha256", "predecessor_start_sha256", "continuation_receipt_sha256"):
            with self.subTest(field=field), self.world() as world:
                args = self.transition(world)
                setattr(args, field, "0" * 64)
                with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_PIN$"):
                    prepare.repair_config(args, budget=world)
                self.assertEqual(world.calls, [])
                self.assertFalse(args.control_directory.exists())

    def test_r05_foreign_start_and_receipt_denied(self):
        """外来startを正しいhashへ付替えても、別receiptを指定しても許可しない。"""
        import prepare_daily_index_config as prepare
        for variant, reason in (("start", "RESUME_BYTES_CONFLICT"), ("receipt", "CODE_REPAIR_RECEIPT")):
            with self.subTest(variant=variant), self.world() as world:
                args = self.transition(world)
                if variant == "start":
                    changed = json.loads(args.predecessor_start.read_bytes())
                    changed["configSha256"] = "0" * 64
                    args.predecessor_start.write_bytes(pipeline.canonical(changed))
                    args.predecessor_start_sha256 = pipeline.sha(args.predecessor_start.read_bytes())
                else:
                    extra = world.artifact(".collection-01.json")
                    extra.write_bytes(args.continuation_receipt.read_bytes())
                    args.continuation_receipt = extra
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    prepare.repair_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_r06_old_and_current_code_native_pins_denied(self):
        """前codeも現codeも旧pinのまま差替えず、native hash変更を拒否する。"""
        import prepare_daily_index_config as prepare
        for variant, reason in (("old-code", "SCRIPT_PIN"), ("current-code", "MODULE_PIN"),
                                ("native", "CONFIG_PIN_collectorExe")):
            with self.subTest(variant=variant), self.world() as world:
                args = self.transition(world)
                if variant == "old-code":
                    (world.version / "daily_index_pipeline.py").write_bytes(b"FOREIGN_OLD_CODE")
                    action = lambda: prepare.repair_config(args, budget=world)
                elif variant == "native":
                    args.collector_exe.write_bytes(b"FOREIGN_NATIVE")
                    action = lambda: prepare.repair_config(args, budget=world)
                else:
                    self.accept(world, args)
                    Path(pipeline.__file__).write_bytes(b"FOREIGN_CURRENT_CODE")
                    action = world.execute
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    action()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_r07_semantic_changes_and_second_transition_denied(self):
        """code以外の意味入力変更と修復済みconfigの再継承を拒否する。"""
        with self.world() as world:
            args = self.transition(world)
            self.accept(world, args)
            for field in ("stateRoot", "outputRoot", "firstDailyLocal", "fingerprint", "scopeSha256",
                          "termsReviewMode", "originalInputs", "legacyReservationFence", "producerSha256"):
                with self.subTest(field=field):
                    config = deepcopy(world.config)
                    config[field] = "FOREIGN_SEMANTICS"
                    with self.assertRaisesRegex(ValueError, "^(CODE_REPAIR_SEMANTICS|SCRIPT_PIN)$"):
                        pipeline.validate_code_repair(config)
            with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_PREDECESSOR$"):
                pipeline.load_config(world.config_path, predecessor_v2=True)
            self.assertEqual(world.calls, [])
            self.assertEqual(world.remote.events, [])

    def test_r08_unverified_head_and_history_denied(self):
        """FRESH_INPUT現head不一致と旧署名history失敗ではcontrolを保存しない。"""
        import prepare_daily_index_config as prepare
        for variant, reason in (("head", "DAILY_RESERVATION_HEAD"), ("history", "LEGACY_METADATA_HISTORY_FAILED")):
            with self.subTest(variant=variant), self.world() as world:
                args = self.transition(world)
                if variant == "head":
                    world.head_generation = 10
                else:
                    world.fail_verify = "--distribution-verify-floor-history"
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    prepare.repair_config(args, budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)

    def test_r09_runtime_head_and_marker_conflict_denied(self):
        """prepare後のhead変更も新config markerの外来byteも再署名前に拒否する。"""
        for variant, reason in (("head", "DAILY_RESERVATION_HEAD"), ("marker", "RESUME_BYTES_CONFLICT")):
            with self.subTest(variant=variant), self.world() as world:
                args = self.transition(world)
                self.accept(world, args)
                if variant == "head":
                    world.head_generation = 10
                else:
                    world.artifact(".acquisition.code-repair.json").write_bytes(b"FOREIGN_MARKER")
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.remote.events, [])

    def test_r10_partial_unknown_claim_and_day_refused(self):
        """既存部分準備・未知claim・別日・元window終了は継承で回避しない。"""
        for variant, reason in (("partial", "ACQUISITION_PREPARATION_INCOMPLETE"),
            ("claim", "SIGNING_OUTCOME_UNKNOWN"), ("day", "CODE_REPAIR_DAY"),
            ("window", "OUTSIDE_OBSERVATION_WINDOW")):
            with self.subTest(variant=variant), self.world() as world:
                args = self.transition(world)
                self.accept(world, args)
                if variant == "partial":
                    (world.out / ("acquisition-" + args.continuation_receipt.stem + ".release.json")).write_bytes(b"{}")
                elif variant == "claim":
                    world.claim_path().write_bytes(b"{}")
                elif variant == "day":
                    world.now += timedelta(days=1)
                else:
                    world.now = pipeline.parse_time(world.config["firstDailyLocal"]) + timedelta(days=7)
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.remote.events, [])

    def test_r11_shared_lock_attempt_and_budget(self):
        """旧lock/32attemptと既使用call/秒を維持し、無効な持越し値を拒否する。"""
        with self.world() as world:
            args = self.transition(world)
            self.accept(world, args)
            with pipeline.exclusive(world.out / "pipeline.lock"):
                with self.assertRaisesRegex(ValueError, "^PIPELINE_ALREADY_RUNNING$"):
                    world.execute()
            self.assertEqual(world.calls, [])
            for index in range(1, 33):
                world.artifact(f".collection-{index:02d}.json").write_bytes(b'{"outcome":"FAILED"}')
            with self.assertRaisesRegex(ValueError, "^DAILY_ATTEMPT_COUNT$"):
                world.execute()
            self.assertEqual(world.calls, [])
        budget = pipeline.Budget()
        before = budget.end
        pipeline.carry_code_repair_budget(budget, 3, 1.25)
        self.assertEqual((budget.calls, budget.end), (3, before - 1.25))
        with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_BUDGET$"):
            pipeline.carry_code_repair_budget(budget, 3, 1.25)
        for field, value in (("priorNativeCalls", 0), ("priorNativeCalls", True),
                             ("priorElapsedSeconds", float("nan")), ("preparationNativeCalls", 0)):
            with self.subTest(field=field, value=value), self.world() as world:
                args = self.transition(world)
                self.accept(world, args)
                world.config["codeRepair"][field] = value
                with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_BUDGET$"):
                    world.execute()
                self.assertEqual(world.calls, [])

    def test_r12_cli_repair_mode_and_effect_free_rejection(self):
        """実CLIから修復入口へ接続し、専用引数を旧modeへ混入できないことを確認する。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.transition(world)
            argv = ["prepare_daily_index_config.py", "--repair-config", str(args.repair_config),
                "--predecessor-config-sha256", args.predecessor_config_sha256,
                "--predecessor-start", str(args.predecessor_start),
                "--predecessor-start-sha256", args.predecessor_start_sha256,
                "--continuation-receipt", str(args.continuation_receipt),
                "--continuation-receipt-sha256", args.continuation_receipt_sha256,
                "--prior-native-calls", "1", "--prior-elapsed-seconds", "0.7296035",
                "--control-directory", str(args.control_directory),
                "--collector-exe", str(args.collector_exe), "--signer-exe", str(args.signer_exe)]
            real_repair = prepare.repair_config
            def injected(parsed):
                """実preparerのnative境界だけへ人工Budgetを渡す。"""
                return real_repair(parsed, budget=world)
            output = io.StringIO()
            with patch.object(prepare, "repair_config", side_effect=injected), \
                    patch("sys.argv", argv), redirect_stdout(output):
                prepare.main()
            self.assertEqual(output.getvalue().strip(),
                             "CODE_ONLY_REPAIR_CONFIG_PREPARED_NO_COLLECTION_NO_TASK_NO_SIGN_NO_GITHUB")
            config, _, _ = pipeline.load_config(args.control_directory / "config.json")
            self.assertEqual(config["codeRepair"]["configSha256"], args.predecessor_config_sha256)
            world.calls.clear()
            with patch("sys.argv", ["prepare_daily_index_config.py", "--prior-native-calls", "1"]):
                with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_MODE_REQUIRED$"):
                    prepare.main()
            self.assertEqual(world.calls, [])
            self.assertEqual(world.remote.events, [])


class PreSignCheckpointContinuationTests(unittest.TestCase):
    """ADR0375の既知二artifactだけを、実loader/preparer/mainへ接続する人工回帰。"""

    world = DailyAcquisitionIssuanceTests.world
    transition = ReceiptAnchorAndRepairTests.transition
    accept = ReceiptAnchorAndRepairTests.accept

    def checkpoint(self, world):
        """実旧継承を準備後、既知native parse/失敗の原byteと有限process証拠を作る。"""
        import prepare_daily_index_config as prepare
        args = self.transition(world)
        self.accept(world, args)
        old, old_hash, predecessor = deepcopy(world.config), world.config_hash, world.config_path
        day = world.now.strftime("%Y%m%d")
        stem = "acquisition-" + args.continuation_receipt.stem
        body = world.out / (stem + ".body")
        release = world.out / (stem + ".release.json")
        inspection = world.out / (stem + ".inspection.json")
        body.write_bytes(base64.b64decode(world.receipt["bodyBytesBase64"]))
        release.write_bytes(pipeline.canonical(world.fixture.release))
        marker = world.out / (day + ".acquisition.code-repair.json")
        marker.write_bytes(pipeline.canonical({"schema": "dc-daily-code-repair-start-v1", "configSha256": old_hash,
            "predecessorConfigSha256": old["codeRepair"]["configSha256"],
            "startSha256": old["codeRepair"]["startSha256"],
            "receiptSha256": old["codeRepair"]["receiptSha256"], "day": day}))
        failure = world.out / (day + ".terminal-123456789.json")
        failure.write_bytes(pipeline.canonical({"status": "FAILED", "reason": "FRESH_INSPECTION_FAILED",
            "configSha256": old_hash, "purpose": pipeline.ACQUISITION_PURPOSE,
            "signingOutcome": "UNKNOWN_NO_RE_SIGN"}))
        verify = [old["collectorExe"], "--verify-daily-reservation", old["manifestFile"], old["stateRoot"],
                  str(args.continuation_receipt), "FRESH_INPUT"]
        parse = [old["signerExe"], "--parse-collected-release", str(body), world.receipt["bodySha256"],
                 str(int(world.receipt["lastSuccessfulValidationAt"])), str(release)]
        original_release = json.loads(world.fixture.originals["release"])
        inspect = [old["signerExe"], "--inspect-collected-package", old["archiveFile"],
                   original_release["publishedSha256"], str(inspection), old["selectedInf"]]
        native = []
        for index, (mode, argv, code) in enumerate([
            ("prepare", verify, 0), ("prepare", [old["signerExe"], "--distribution-verify-history"], 0),
            ("run", verify, 0), ("run", verify, 0), ("run", parse, 0), ("run", inspect, 2),
            ("diagnostic", inspect, 0)]):
            native.append({"mode": mode, "actualArgv": argv, "exitCode": code, "pid": 100 + index,
                "sameHandleTerminal": True, "actualCwd": old["repositoryRoot"],
                "creationUtc": world.now.isoformat(), "exitUtc": world.now.isoformat()})
        evidence_dir = world.root / "control/presign-evidence"
        evidence_dir.mkdir()
        phase = evidence_dir / "phase.json"
        content = evidence_dir / "content.json"
        phase.write_bytes(pipeline.canonical({"native": native, "nativeProcessesThisStage": 7,
            "priorRunNativeCarry": 1, "totalNativeIncludingCarry": 8}))
        diagnostic = [old["signerExe"], "--inspect-collected-package", old["archiveFile"],
            pipeline.projection.digest(original_release["publishedSha256"]), str(evidence_dir / "inspection.json"),
            old["selectedInf"].replace("/", "\\")]
        content.write_bytes(pipeline.canonical({"totalNativeCalls": 9, "priorNativeCalls": 8,
            "additionalNativeCalls": 1, "totalNativeSeconds": 3.4540565000155405,
            "pipelineComplete": 0, "signaturesIssued": 0, "privateRegistrations": 0,
            "native": {"argv": diagnostic, "sameHandleTerminal": True, "exitCode": 0},
            "artifact": {"inspectionError": 0, "verifiedIdentityInfs": 1}}))
        old_version = Path(pipeline.__file__).parent
        version = world.root / "scripts/v2-artificial-presign"
        binary = world.root / "bin" / version.name
        version.mkdir()
        binary.mkdir(parents=True)
        for name in pipeline.MODULE_NAMES:
            raw = (old_version / name).read_bytes()
            (version / name).write_bytes(raw + (b"_PRESIGN" if name in
                {"daily_index_pipeline.py", "prepare_daily_index_config.py"} else b""))
        for field in ("collectorExe", "signerExe"):
            source = Path(old[field])
            (binary / source.name).write_bytes(source.read_bytes())
        for owner, name, path in ((pipeline, "__file__", version / "daily_index_pipeline.py"),
            (pipeline.projection, "__file__", version / "project_collected_native_index.py"),
            (pipeline.cr, "__file__", version / "collector_registry.py"),
            (prepare, "__file__", version / "prepare_daily_index_config.py")):
            world.stack.enter_context(patch.object(owner, name, str(path)))
        world.retained_checkpoint = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in
            (predecessor, marker, body, release, failure, phase, content, args.predecessor_start,
             args.continuation_receipt)}
        world.old_presign_config = old
        world.original_bucket = day
        world.calls.clear()
        return SimpleNamespace(continue_presign_config=predecessor, predecessor_config_sha256=old_hash,
            predecessor_repair_marker=marker, predecessor_repair_marker_sha256=pipeline.sha(marker.read_bytes()),
            checkpoint_body_sha256=pipeline.sha(body.read_bytes()), checkpoint_release_sha256=pipeline.sha(release.read_bytes()),
            phase_evidence=phase, phase_evidence_sha256=pipeline.sha(phase.read_bytes()),
            content_evidence=content, content_evidence_sha256=pipeline.sha(content.read_bytes()),
            failure_terminal=failure, failure_terminal_sha256=pipeline.sha(failure.read_bytes()),
            prior_native_calls=9, prior_elapsed_seconds=3.4540565000155405,
            control_directory=world.root / "control/presign", collector_exe=binary / world.collector.name,
            signer_exe=binary / world.signer.name)

    def accept_checkpoint(self, world, args):
        """実新preparer/loadへfakeだけを注入し、実prepareの二検証をassertする。"""
        import prepare_daily_index_config as prepare
        world.config_path = prepare.continue_presign_config(args, budget=world)
        world.config, world.scope, world.config_hash = pipeline.load_config(world.config_path)
        self.assertEqual([argv[1] for argv, _, _ in world.calls],
                         ["--verify-daily-reservation", "--distribution-verify-floor-history"])
        self.assertEqual(world.config["codeRepair"], world.old_presign_config["codeRepair"])
        self.assertEqual(world.config["legacyReservationFence"]["generation"], 4)
        world.calls.clear()

    def assert_retained(self, world):
        """保存した全旧入力をbyteとmtimeの両方で比較する。"""
        for path, (raw, modified) in world.retained_checkpoint.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), (raw, modified), str(path))

    def test_p01_exact_checkpoint_and_complete_same_byte_reuse(self):
        """200/304の元二artifactを保持し、再収集/再解析/重複署名なしで二回接続する。"""
        for status in (200, 304):
            with self.subTest(status=status), self.world(status=status) as world:
                args = self.checkpoint(world)
                self.accept_checkpoint(world, args)
                self.assertEqual(world.execute()["status"], "PUBLISHED")
                marker = world.out / (world.original_bucket + ".acquisition.presign-continuation.json")
                frozen = marker.read_bytes()
                self.assertEqual(world.execute()["status"], "PUBLISHED")
                self.assertEqual(marker.read_bytes(), frozen)
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.command_count("--parse-collected-release"), 0)
                self.assertEqual(world.command_count("--inspect-collected-package"), 1)
                self.assertEqual(world.command_count("--collect-terms-link-script"), 1)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assert_retained(world)

    def test_p02_old_default_refusals_and_single_explicit_transition(self):
        """既存再修復拒否を維持し、新mode自体を前configとして多段化できない。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.checkpoint(world)
            with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_PREDECESSOR$"):
                pipeline.load_config(args.continue_presign_config, predecessor_v2=True)
            self.accept_checkpoint(world, args)
            with self.assertRaisesRegex(ValueError, "^PRESIGN_PREDECESSOR$"):
                pipeline.load_config(world.config_path, presign_predecessor=True)
            self.assertEqual(world.calls, [])
            args.repair_config = args.continue_presign_config
            with self.assertRaisesRegex(ValueError, "^PRESIGN_INPUTS$"):
                prepare.continue_presign_config(args, budget=world)

    def test_p03_all_explicit_raw_pins_precede_native(self):
        """旧config/marker/checkpoint/実証拠/原terminalのpin相違を副作用前に拒否する。"""
        import prepare_daily_index_config as prepare
        for field in ("predecessor_config_sha256", "predecessor_repair_marker_sha256", "checkpoint_body_sha256",
                      "checkpoint_release_sha256", "phase_evidence_sha256", "content_evidence_sha256",
                      "failure_terminal_sha256"):
            with self.subTest(field=field), self.world() as world:
                args = self.checkpoint(world)
                setattr(args, field, "0" * 64)
                with self.assertRaisesRegex(ValueError, "^(PRESIGN_PIN|PRESIGN_CHECKPOINT_PIN)$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])
                self.assertFalse(args.control_directory.exists())

    def test_p04_old_code_current_code_and_native_bytes_verified(self):
        """旧四moduleを旧versionで確認し、現pinとnative pinも弱めない。"""
        import prepare_daily_index_config as prepare
        for name in sorted(pipeline.MODULE_NAMES) + ["native", "current"]:
            with self.subTest(name=name), self.world() as world:
                args = self.checkpoint(world)
                if name == "current":
                    self.accept_checkpoint(world, args)
                    Path(pipeline.__file__).write_bytes(b"FOREIGN_CURRENT")
                    action = world.execute
                elif name == "native":
                    args.signer_exe.write_bytes(b"FOREIGN_NATIVE")
                    action = lambda: prepare.continue_presign_config(args, budget=world)
                else:
                    version = world.root / "scripts" / Path(world.old_presign_config["collectorExe"]).parent.name
                    (version / name).write_bytes(b"FOREIGN_OLD_CODE")
                    action = lambda: prepare.continue_presign_config(args, budget=world)
                with self.assertRaisesRegex(ValueError, "^(SCRIPT_PIN|MODULE_PIN|CONFIG_PIN_signerExe)$"):
                    action()
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_p05_all_immutable_semantics_and_no_caller_day(self):
        """全意味fieldと原codeRepairを比較し、任意day追加も閉fieldで拒否する。"""
        with self.world() as world:
            args = self.checkpoint(world)
            self.accept_checkpoint(world, args)
            mutable = {"scopeFile", "collectorExe", "signerExe", "pipelineSha256", "modulePins"}
            for field in sorted(pipeline.V2_CONFIG_FIELDS - mutable) + ["codeRepair"]:
                with self.subTest(field=field):
                    changed = deepcopy(world.config)
                    changed[field] = "FOREIGN_SEMANTICS"
                    reason = {"collectorSha256": "CONFIG_PIN_collectorExe", "signerSha256": "CONFIG_PIN_signerExe",
                              "producerSha256": "SCRIPT_PIN"}.get(field, "PRESIGN_SEMANTICS")
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        pipeline.validate_presign_continuation(changed)
            world.config["preSignContinuation"]["day"] = "20261018"
            with self.assertRaisesRegex(ValueError, "^PRESIGN_FIELDS$"):
                world.execute()
            self.assertEqual(world.calls, [])

    def test_p06_partial_extra_and_rebound_changed_release_refused(self):
        """新marker前の余分/欠損/改変partialは削除・上書きで回避しない。"""
        import prepare_daily_index_config as prepare
        for variant in ("inspection", "script", "review", "extra", "missing-body", "body", "release"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.checkpoint(world)
                stem = "acquisition-" + Path(world.config["codeRepair"]["receiptFile"]).stem
                if variant == "missing-body":
                    (world.out / (stem + ".body")).unlink()
                elif variant == "body":
                    path = world.out / (stem + ".body")
                    path.write_bytes(b"FOREIGN")
                    args.checkpoint_body_sha256 = pipeline.sha(path.read_bytes())
                elif variant == "release":
                    path = world.out / (stem + ".release.json")
                    value = json.loads(path.read_bytes())
                    value["observedUtcSeconds"] = str(int(value["observedUtcSeconds"]) - 1)
                    path.write_bytes(pipeline.canonical(value))
                    args.checkpoint_release_sha256 = pipeline.sha(path.read_bytes())
                else:
                    (world.out / (stem + "." + variant + ".json")).write_bytes(b"{}")
                with self.assertRaises((ValueError, OSError)):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])
                self.assertFalse(args.control_directory.exists())

    def test_p07_claim_envelope_unsigned_and_unknown_witness_refused(self):
        """署名前のclaim/署名/unsigned/CAS witnessを一つでも観測すれば継承しない。"""
        import prepare_daily_index_config as prepare
        for variant in ("claim", "envelope", "unsigned", "success", "native-unknown", "native-verified", "cas"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.checkpoint(world)
                prefix = str(world.out / world.original_bucket) + ".acquisition"
                if variant == "claim":
                    world.claim_path().write_bytes(b"{}")
                elif variant in {"envelope", "unsigned", "success"}:
                    suffix = {"envelope": ".manifest.json", "unsigned": ".manifest.raw.json", "success": ".success.json"}[variant]
                    Path(prefix + suffix).write_bytes(b"{}")
                else:
                    value = {"generation": world.receipt["generation"]}
                    if variant == "cas":
                        value["publicationOutcome"] = "CAS_INTENT_UNKNOWN"
                    else:
                        value["signingOutcome"] = "NATIVE_OUTCOME_UNKNOWN" if variant == "native-unknown" else "NATIVE_CURRENT_VERIFIED"
                    (world.out / (world.original_bucket + ".terminal-987654321.json")).write_bytes(pipeline.canonical(value))
                with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_p08_phase_and_native_parse_contract_cannot_be_rebound(self):
        """witnessのhashを更新してもforeign parse/exit/署名呼出し/不足会計を拒否する。"""
        import prepare_daily_index_config as prepare
        for variant in ("argv", "exit", "handle", "sign", "cwd", "accounting"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.checkpoint(world)
                value = json.loads(args.phase_evidence.read_bytes())
                process = value["native"][4]
                if variant == "argv":
                    process["actualArgv"][3] = "0" * 64
                elif variant == "sign":
                    process["actualArgv"][1] = "--distribution-acquisition-sign"
                elif variant == "handle":
                    process["sameHandleTerminal"] = False
                elif variant == "cwd":
                    process["actualCwd"] = str(world.root)
                elif variant == "exit":
                    process["exitCode"] = 2
                else:
                    value["totalNativeIncludingCarry"] = 1
                args.phase_evidence.write_bytes(pipeline.canonical(value))
                args.phase_evidence_sha256 = pipeline.sha(args.phase_evidence.read_bytes())
                with self.assertRaisesRegex(ValueError, "^PRESIGN_PHASE$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_p09_local_midnight_main_terminal_and_report_use_original_bucket(self):
        """JST翌日でもUTC同日なら元jobへ完了/terminalを保存し、reportの分母を変えない。"""
        with self.world() as world:
            args = self.checkpoint(world)
            world.now = world.now.replace(hour=15, minute=1)
            self.accept_checkpoint(world, args)
            code, result = world.execute(main=True)
            self.assertEqual((code, result["status"]), (0, "PUBLISHED"))
            self.assertFalse(any(world.out.glob("20261018.*")))
            terminals = sorted(world.out.glob(world.original_bucket + ".terminal-*.json"))
            self.assertTrue(any(json.loads(path.read_bytes()).get("status") == "PUBLISHED" for path in terminals))
            report = pipeline.report(world.config)
            self.assertEqual(report["denominator"], 7)
            self.assertEqual(report["days"][1]["status"], "PUBLISHED")
            self.assertEqual(pipeline.acquisition_job_day(world.config), world.original_bucket)
            self.assert_retained(world)

    def test_p10_utc_day_window_head_and_marker_guards(self):
        """local bucket例外でUTC日/window/現head/新markerを迂回しない。"""
        for variant in ("utc-day", "window", "head", "marker"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.checkpoint(world)
                self.accept_checkpoint(world, args)
                if variant == "utc-day":
                    world.now += timedelta(days=1)
                elif variant == "window":
                    world.now = pipeline.parse_time(world.config["firstDailyLocal"]) + timedelta(days=7)
                elif variant == "head":
                    world.head_generation = world.receipt["generation"] + 1
                else:
                    (world.out / (world.original_bucket + ".acquisition.presign-continuation.json")).write_bytes(b"FOREIGN")
                with self.assertRaises(ValueError):
                    world.execute()
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)

    def test_p11_after_marker_unknown_sign_and_partial_remain_fail_closed(self):
        """明示marker後もnative未知結果/部分envelopeを再署名せず原fileを保持する。"""
        for behavior in ("nonzero", "partial", "result-before-record-crash"):
            with self.subTest(behavior=behavior), self.world() as world:
                args = self.checkpoint(world)
                self.accept_checkpoint(world, args)
                world.sign_behavior = behavior
                with self.assertRaises((ValueError, SystemExit)):
                    world.execute()
                with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                    world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assertEqual(world.command_count("--parse-collected-release"), 0)
                self.assert_retained(world)

    def test_p12_original_lock_attempt_calls_seconds_and_preparer_history(self):
        """共有lock/attemptと証拠付き既使用call/秒、prepareのhistory/FRESH拒否を確認する。"""
        import prepare_daily_index_config as prepare
        for variant in ("lock", "attempt", "calls", "seconds", "history", "head"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.checkpoint(world)
                if variant == "calls":
                    args.prior_native_calls = 8
                elif variant == "seconds":
                    args.prior_elapsed_seconds = 3.0
                elif variant == "history":
                    world.fail_verify = "--distribution-verify-floor-history"
                elif variant == "head":
                    world.head_generation = world.receipt["generation"] + 1
                elif variant == "attempt":
                    for index in range(1, 33):
                        (world.out / (world.original_bucket + f".collection-{index:02d}.json")).write_bytes(b'{"outcome":"FAILED"}')
                if variant == "lock":
                    with pipeline.exclusive(world.out / "pipeline.lock"):
                        with self.assertRaisesRegex(ValueError, "^PIPELINE_ALREADY_RUNNING$"):
                            prepare.continue_presign_config(args, budget=world)
                else:
                    with self.assertRaises(ValueError):
                        prepare.continue_presign_config(args, budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.command_count("--daily-evidence"), 0)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
        budget = pipeline.Budget()
        before = budget.end
        pipeline.carry_code_repair_budget(budget, 11, 3.9540565000155405)
        self.assertEqual((budget.calls, budget.end), (11, before - 3.9540565000155405))
        with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_BUDGET$"):
            pipeline.carry_code_repair_budget(budget, 11, 3.9540565000155405)

    def test_p14_after_marker_partial_refuses_reexecution(self):
        """marker後のinspectionだけの状態は新checkpointへ昇格せず、再検査もしない。"""
        with self.world() as world:
            args = self.checkpoint(world)
            self.accept_checkpoint(world, args)
            real_run = world.run
            def fail_script(argv, **kwargs):
                """内容検査成功の後だけscript入口を失敗させ、部分artifactを保持する。"""
                if argv[1] == "--collect-terms-link-script":
                    world.calls.append((list(argv), kwargs.get("seconds", 600), kwargs.get("maximum", pipeline.MAX_FILE)))
                    return 2, b"", b"ARTIFICIAL_SCRIPT_FAILURE"
                return real_run(argv, **kwargs)
            with patch.object(world, "run", side_effect=fail_script):
                with self.assertRaisesRegex(ValueError, "^FRESH_SCRIPT_FAILED$"):
                    world.execute()
            with self.assertRaisesRegex(ValueError, "^PRESIGN_CHECKPOINT_SHAPE$"):
                world.execute()
            self.assertEqual(world.command_count("--inspect-collected-package"), 1)
            self.assertEqual(world.command_count("--collect-terms-link-script"), 1)
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
            self.assert_retained(world)

    def test_p15_marker_binds_exact_current_config_bytes(self):
        """現configの空白差もmarkerに同一視せず、全byte hashへ結合する。"""
        with self.world() as world:
            args = self.checkpoint(world)
            self.accept_checkpoint(world, args)
            original = world.config_path.read_bytes()
            world.config_path.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "^PRESIGN_CONFIG_BYTES$"):
                pipeline.load_config(world.config_path)
            self.assertEqual(world.calls, [])
            world.config_path.write_bytes(original)
            self.assertEqual(world.execute()["status"], "PUBLISHED")
            marker = world.out / (world.original_bucket + ".acquisition.presign-continuation.json")
            self.assertEqual(json.loads(marker.read_bytes())["configSha256"], pipeline.sha(original))
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)

    def test_p13_real_cli_mode_and_mixed_flags_refused(self):
        """実argparseから専用入口を呼び、他modeへの専用flag混入を拒否する。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.checkpoint(world)
            argv = ["prepare_daily_index_config.py"]
            for name, value in vars(args).items():
                argv.extend(["--" + name.replace("_", "-"), str(value)])
            real_prepare = prepare.continue_presign_config
            with patch.object(prepare, "continue_presign_config", side_effect=lambda parsed:
                    real_prepare(parsed, budget=world)), patch("sys.argv", argv), redirect_stdout(io.StringIO()) as output:
                prepare.main()
            self.assertEqual(output.getvalue().strip(),
                "PRESIGN_CONTINUATION_CONFIG_PREPARED_NO_COLLECTION_NO_TASK_NO_SIGN_NO_GITHUB")
            self.assertTrue((args.control_directory / "config.json").exists())
            world.calls.clear()
            with patch("sys.argv", ["prepare_daily_index_config.py", "--checkpoint-body-sha256", "0" * 64]):
                with self.assertRaisesRegex(ValueError, "^PRESIGN_MODE_REQUIRED$"):
                    prepare.main()
            self.assertEqual(world.calls, [])


class VerifiedUnsignedRefreshTests(unittest.TestCase):
    """ADR0376の閉じた四原file遷移を実loader/preparer/mainへ接続する人工回帰。"""

    world = DailyAcquisitionIssuanceTests.world
    transition = ReceiptAnchorAndRepairTests.transition
    accept = ReceiptAnchorAndRepairTests.accept
    checkpoint = PreSignCheckpointContinuationTests.checkpoint
    accept_checkpoint = PreSignCheckpointContinuationTests.accept_checkpoint
    assert_retained = PreSignCheckpointContinuationTests.assert_retained

    def four_file_checkpoint(self, world):
        """旧preSignの全連鎖とmarkerを保持し、review直前の既知四原file状態を作る。"""
        import prepare_daily_index_config as prepare
        args = self.checkpoint(world)
        with patch.object(prepare.time, "monotonic", side_effect=[0.0, 1.1818001000210643]):
            self.accept_checkpoint(world, args)
        old, old_hash, predecessor = deepcopy(world.config), world.config_hash, world.config_path
        verified = pipeline.validate_presign_continuation(old)
        verified["markerPath"].write_bytes(verified["marker"])
        for name in ("inspection", "script"):
            verified["paths"][name].write_bytes(pipeline.canonical(getattr(world.fixture, name)))
        failure = world.out / (world.original_bucket + ".terminal-987654321.json")
        failure.write_bytes(pipeline.canonical({"status": "FAILED", "reason": "DISTRIBUTION_UTC_SECONDS",
            "configSha256": old_hash, "purpose": pipeline.ACQUISITION_PURPOSE,
            "signingOutcome": "UNKNOWN_NO_RE_SIGN"}))
        evidence_dir = world.root / "control/verified-unsigned-evidence"
        evidence_dir.mkdir()
        witness = evidence_dir / "budget.json"
        witness.write_bytes(pipeline.canonical({"utc": world.now.isoformat(),
            "priorNativeCalls": old["preSignContinuation"]["priorNativeCalls"],
            "priorElapsedSeconds": old["preSignContinuation"]["priorElapsedSeconds"],
            "actualPrepareNativeCalls": 2, "actualPrepareMeasuredSeconds": 1.1818001000210643,
            "prepareOuterObservedSeconds": 2.7760638000327162,
            "runActualMeasuredSeconds": None, "runProcessCountDirectlyObserved": None,
            "runPathNativeCallUpperBound": 4, "runWallSecondsConservativeUpperBound": 140.08771920204163,
            "runWallUpperBoundBasis": {
                "earliestPrelaunchStreamBirthUtc": (world.now - timedelta(seconds=140.087719)).isoformat(),
                "laterNoExactRunProcessObservedUtc": world.now.isoformat(), "originalHandleTerminal": False},
            "nativeCallsIncludingCarryUpperBound": 15,
            "elapsedSecondsIncludingCarryConservativeUpperBound": 144.72357580207824,
            "globalLimits": {"calls": 96, "seconds": 1800, "attempts": 32, "holdWaitSeconds": 300},
            "qualification": "Artificial conservative bounds, not original run measurements."}))
        old_version = Path(pipeline.__file__).parent
        version = world.root / "scripts/v2-artificial-verified-unsigned"
        binary = world.root / "bin" / version.name
        version.mkdir()
        binary.mkdir(parents=True)
        for name in pipeline.MODULE_NAMES:
            raw = (old_version / name).read_bytes()
            (version / name).write_bytes(raw + (b"_VERIFIED_UNSIGNED" if name in
                {"daily_index_pipeline.py", "prepare_daily_index_config.py"} else b""))
        for field in ("collectorExe", "signerExe"):
            source = Path(old[field])
            (binary / source.name).write_bytes(source.read_bytes())
        for owner, name, path in ((pipeline, "__file__", version / "daily_index_pipeline.py"),
            (pipeline.projection, "__file__", version / "project_collected_native_index.py"),
            (pipeline.cr, "__file__", version / "collector_registry.py"),
            (prepare, "__file__", version / "prepare_daily_index_config.py")):
            world.stack.enter_context(patch.object(owner, name, str(path)))
        for path in (predecessor, verified["markerPath"], failure, witness, *verified["paths"].values()):
            if path.exists():
                world.retained_checkpoint[path] = (path.read_bytes(), path.stat().st_mtime_ns)
        world.refresh_predecessor = old
        world.refresh_old_version = old_version
        world.refresh_paths = verified["paths"]
        world.calls.clear()
        return SimpleNamespace(continue_presign_config=predecessor, predecessor_config_sha256=old_hash,
            predecessor_presign_marker=verified["markerPath"],
            predecessor_presign_marker_sha256=pipeline.sha(verified["marker"]),
            checkpoint_body_sha256=pipeline.sha(verified["paths"]["body"].read_bytes()),
            checkpoint_release_sha256=pipeline.sha(verified["paths"]["release"].read_bytes()),
            checkpoint_inspection_sha256=pipeline.sha(verified["paths"]["inspection"].read_bytes()),
            checkpoint_script_sha256=pipeline.sha(verified["paths"]["script"].read_bytes()),
            failure_terminal=failure, failure_terminal_sha256=pipeline.sha(failure.read_bytes()),
            budget_witness=witness, budget_witness_sha256=pipeline.sha(witness.read_bytes()),
            prior_native_calls=15, prior_elapsed_seconds=144.72357580207824,
            control_directory=world.root / "control/verified-unsigned", collector_exe=binary / world.collector.name,
            signer_exe=binary / world.signer.name)

    def accept_refresh(self, world, args, *, budget=None):
        """実既存入口とloaderを通し、二検証と原codeRepair保持を確認する。"""
        import prepare_daily_index_config as prepare
        world.config_path = prepare.continue_presign_config(args, budget=budget or world)
        world.config, world.scope, world.config_hash = pipeline.load_config(world.config_path)
        self.assertEqual([argv[1] for argv, _, _ in world.calls],
                         ["--verify-daily-reservation", "--distribution-verify-floor-history"])
        self.assertEqual(world.config["codeRepair"], world.refresh_predecessor["codeRepair"])
        self.assertEqual(world.config["preSignContinuation"]["schema"], pipeline.VERIFIED_UNSIGNED_SCHEMA)
        self.assert_retained(world)
        world.calls.clear()

    def test_v01_four_raw_200_304_fractional_clock_and_exact_reuse(self):
        """四原byte/時刻を保持し、一reviewだけ生成して通常claim/署名/再利用へ接続する。"""
        for status in (200, 304):
            with self.subTest(status=status), self.world(status=status) as world:
                args = self.four_file_checkpoint(world)
                self.accept_refresh(world, args)
                world.now = world.now.replace(microsecond=678901)
                producer = pipeline.projection.make_pinned_static_terms_revalidation
                with patch.object(pipeline.projection, "make_pinned_static_terms_revalidation", wraps=producer) as make:
                    self.assertEqual(world.execute()["status"], "PUBLISHED")
                    self.assertEqual(make.call_count, 1)
                    paths = [*world.refresh_paths.values(), world.claim_path(), world.artifact(".manifest.raw.json"),
                             world.artifact(".index.json.gz"), world.artifact(".manifest.json")]
                    saved = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
                    review = json.loads(world.refresh_paths["review"].read_bytes())
                    self.assertEqual(review["revalidatedCheckedAtUtcSeconds"], int(world.now.timestamp()))
                    self.assertEqual(world.command_count("--verify-daily-reservation"), 3)
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                    self.assertEqual(world.command_count("--distribution-acquisition-verify"), 3)
                    self.assertEqual(world.command_count("--distribution-verify-floor-history"), 1)
                    world.remote.events.clear()
                    world.now += timedelta(seconds=3)
                    self.assertTrue(world.execute()["resumed"])
                    self.assertEqual(make.call_count, 1)
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                    self.assertTrue(all(method == "GET" for method, _, _ in world.remote.events))
                    for path, expected in saved.items():
                        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), expected)
                for command in ("--daily-evidence", "--parse-collected-release", "--inspect-collected-package",
                                "--collect-terms-link-script"):
                    self.assertEqual(world.command_count(command), 0)
                self.assert_retained(world)

    def test_v02_default_refusals_and_second_refresh(self):
        """既存通常入口の四file拒否と一回refreshの非再帰境界を保持する。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.four_file_checkpoint(world)
            with self.assertRaisesRegex(ValueError, "^PRESIGN_CHECKPOINT_SHAPE$"):
                pipeline.validate_presign_continuation(world.refresh_predecessor, version=world.refresh_old_version)
            with self.assertRaisesRegex(ValueError, "^PRESIGN_PREDECESSOR$"):
                pipeline.load_config(args.continue_presign_config, presign_predecessor=True)
            self.assertEqual(world.calls, [])
            self.accept_refresh(world, args)
            args.continue_presign_config = world.config_path
            args.predecessor_config_sha256 = world.config_hash
            args.control_directory = world.root / "control/forbidden-second-refresh"
            with self.assertRaisesRegex(ValueError, "^VERIFIED_UNSIGNED_PREDECESSOR$"):
                prepare.continue_presign_config(args, budget=world)
            self.assertEqual(world.calls, [])
            self.assertFalse(args.control_directory.exists())

    def test_v03_each_explicit_raw_pin_precedes_native(self):
        """旧config/marker/失敗/witnessと四fileの全指定pinを個別に拒否する。"""
        import prepare_daily_index_config as prepare
        names = ("predecessor_config_sha256", "predecessor_presign_marker_sha256", "failure_terminal_sha256",
                 "budget_witness_sha256", "checkpoint_body_sha256", "checkpoint_release_sha256",
                 "checkpoint_inspection_sha256", "checkpoint_script_sha256")
        for name in names:
            with self.subTest(name=name), self.world() as world:
                args = self.four_file_checkpoint(world)
                setattr(args, name, "0" * 64)
                with self.assertRaisesRegex(ValueError, "^(VERIFIED_UNSIGNED_PIN|VERIFIED_UNSIGNED_CHECKPOINT_PIN)$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])
                self.assertFalse(args.control_directory.exists())

    def test_v04_missing_extra_and_different_partial(self):
        """四原fileの各欠損・余分・未結合reviewを一般修復へ変換しない。"""
        import prepare_daily_index_config as prepare
        for variant in ("body", "release", "inspection", "script", "extra", "review"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.four_file_checkpoint(world)
                if variant in {"body", "release", "inspection", "script"}:
                    world.refresh_paths[variant].unlink()
                elif variant == "extra":
                    world.refresh_paths["body"].with_suffix(".extra.json").write_bytes(b"{}")
                else:
                    world.refresh_paths["review"].write_bytes(b"{}")
                with self.assertRaises((ValueError, OSError)):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_v05_each_old_current_module_and_native_pin(self):
        """旧四module/nativeと現四module/nativeをそれぞれ保存版の全byteで検証する。"""
        import prepare_daily_index_config as prepare
        for context in ("old", "current"):
            for name in sorted(pipeline.MODULE_NAMES) + ["collectorExe", "signerExe"]:
                with self.subTest(context=context, name=name), self.world() as world:
                    args = self.four_file_checkpoint(world)
                    if context == "current":
                        self.accept_refresh(world, args)
                        target = (Path(world.config[name]) if name.endswith("Exe") else
                                  Path(pipeline.__file__).parent / name)
                        action = world.execute
                    else:
                        target = (Path(world.refresh_predecessor[name]) if name.endswith("Exe") else
                                  world.refresh_old_version / name)
                        action = lambda: prepare.continue_presign_config(args, budget=world)
                    target.write_bytes(b"FOREIGN_PINNED_BYTES")
                    reason = "^(SCRIPT_PIN|MODULE_PIN|CONFIG_PIN_collectorExe|CONFIG_PIN_signerExe)$"
                    with self.assertRaisesRegex(ValueError, reason):
                        action()
                    self.assertEqual(world.calls, [])

    def test_v06_all_immutable_semantics_and_closed_fields(self):
        """全意味field・原codeRepairと余分な日/descriptor fieldを個別に拒否する。"""
        with self.world() as world:
            args = self.four_file_checkpoint(world)
            self.accept_refresh(world, args)
            mutable = {"scopeFile", "collectorExe", "signerExe", "pipelineSha256", "modulePins"}
            for field in sorted(pipeline.V2_CONFIG_FIELDS - mutable) + ["codeRepair"]:
                with self.subTest(field=field):
                    changed = deepcopy(world.config)
                    changed[field] = "FOREIGN_SEMANTICS"
                    reason = {"collectorSha256": "CONFIG_PIN_collectorExe", "signerSha256": "CONFIG_PIN_signerExe",
                              "producerSha256": "SCRIPT_PIN"}.get(field, "VERIFIED_UNSIGNED_SEMANTICS")
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        pipeline.validate_presign_continuation(changed)
            for name in sorted(pipeline.VERIFIED_UNSIGNED_FIELDS):
                with self.subTest(missing=name):
                    changed = deepcopy(world.config)
                    del changed["preSignContinuation"][name]
                    with self.assertRaises(ValueError):
                        pipeline.validate_presign_continuation(changed)
            changed = deepcopy(world.config)
            changed["preSignContinuation"]["day"] = world.original_bucket
            with self.assertRaisesRegex(ValueError, "^VERIFIED_UNSIGNED_FIELDS$"):
                pipeline.validate_presign_continuation(changed)
            self.assertEqual(world.calls, [])

    def test_v07_original_state_start_receipt_terms_and_marker_pins(self):
        """原state/start/receiptと承認済みterms原byte・旧markerの変更を先に拒否する。"""
        import prepare_daily_index_config as prepare
        for name in ("start", "receipt", "release", "review", "script", "marker", "config"):
            with self.subTest(name=name), self.world() as world:
                args = self.four_file_checkpoint(world)
                if name in {"start", "receipt"}:
                    path = Path(world.refresh_predecessor["codeRepair"][name + "File"])
                elif name in {"release", "review", "script"}:
                    path = Path(world.refresh_predecessor["originalInputs"][name]["file"])
                else:
                    path = args.predecessor_presign_marker if name == "marker" else args.continue_presign_config
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaises(ValueError):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_v08_conservative_budget_witness_and_reduction_rejected(self):
        """15/元上界秒を縮小せず、null観測・元handle欠損と閉witnessを維持する。"""
        import prepare_daily_index_config as prepare
        variants = ("calls", "seconds", "witness-calls", "witness-seconds", "run-measured", "run-count",
                    "handle", "limits", "extra", "missing", "prepare-time")
        for variant in variants:
            with self.subTest(variant=variant), self.world() as world:
                args = self.four_file_checkpoint(world)
                value = json.loads(args.budget_witness.read_bytes())
                if variant == "calls":
                    args.prior_native_calls = 9
                elif variant == "seconds":
                    args.prior_elapsed_seconds = 1.0
                elif variant == "witness-calls":
                    value["nativeCallsIncludingCarryUpperBound"] = args.prior_native_calls = 14
                    value["runPathNativeCallUpperBound"] = 3
                elif variant == "witness-seconds":
                    value["runWallSecondsConservativeUpperBound"] = 0.0
                    args.prior_elapsed_seconds = 4.635856600036605
                    value["elapsedSecondsIncludingCarryConservativeUpperBound"] = args.prior_elapsed_seconds
                elif variant == "run-measured":
                    value["runActualMeasuredSeconds"] = 140.0
                elif variant == "run-count":
                    value["runProcessCountDirectlyObserved"] = 4
                elif variant == "handle":
                    value["runWallUpperBoundBasis"]["originalHandleTerminal"] = True
                elif variant == "limits":
                    value["globalLimits"]["calls"] = 97
                elif variant == "extra":
                    value["reset"] = True
                elif variant == "missing":
                    del value["runActualMeasuredSeconds"]
                else:
                    value["actualPrepareMeasuredSeconds"] = 0.0
                args.budget_witness.write_bytes(pipeline.canonical(value))
                args.budget_witness_sha256 = pipeline.sha(args.budget_witness.read_bytes())
                with self.assertRaisesRegex(ValueError, "^VERIFIED_UNSIGNED_BUDGET(_WITNESS)?$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_v09_all_unsigned_claim_envelope_and_witness_absence(self):
        """claim・unsigned・envelope・成功・署名結果・CAS意図があれば新遷移へ入らない。"""
        import prepare_daily_index_config as prepare
        for variant in ("claim", ".manifest.raw.json", ".index.json.gz", ".manifest.json", ".success.json",
                        "signingClaimSha256", "envelopeSha256", "publicationOutcome", "nativeCurrentVerified",
                        "unknown-sign"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.four_file_checkpoint(world)
                if variant == "claim":
                    world.claim_path().write_bytes(b"{}")
                elif variant.startswith("."):
                    world.artifact(variant).write_bytes(b"{}")
                else:
                    terminal = {"generation": world.receipt["generation"], "signingOutcome": "UNKNOWN_NO_RE_SIGN"}
                    if variant == "unknown-sign":
                        terminal["signingOutcome"] = "NATIVE_OUTCOME_UNKNOWN"
                    else:
                        terminal[variant] = "UNKNOWN"
                    world.artifact(".terminal-555.json").write_bytes(pipeline.canonical(terminal))
                with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_v10_day_expiry_window_head_and_both_locks(self):
        """元bucket例外でUTC日/期限/window/headや共有operation lockを迂回しない。"""
        import prepare_daily_index_config as prepare
        for variant in ("prepare-lock", "run-lock", "utc-day", "expiry", "window", "head", "marker"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.four_file_checkpoint(world)
                if variant == "prepare-lock":
                    with pipeline.exclusive(world.out / "pipeline.lock"):
                        with self.assertRaisesRegex(ValueError, "^PIPELINE_ALREADY_RUNNING$"):
                            prepare.continue_presign_config(args, budget=world)
                    continue
                self.accept_refresh(world, args)
                if variant == "utc-day":
                    world.now = world.now.replace(hour=0) + timedelta(days=1)
                elif variant == "expiry":
                    world.now += timedelta(days=1, seconds=1)
                elif variant == "window":
                    world.now = pipeline.parse_time(world.config["firstDailyLocal"]) + timedelta(days=7)
                elif variant == "head":
                    world.head_generation = world.receipt["generation"] + 1
                elif variant == "marker":
                    marker = world.out / (world.original_bucket + ".acquisition.verified-unsigned-refresh.json")
                    marker.write_bytes(b"FOREIGN")
                if variant == "run-lock":
                    with pipeline.exclusive(world.out / "pipeline.lock"):
                        with self.assertRaisesRegex(ValueError, "^PIPELINE_ALREADY_RUNNING$"):
                            world.execute()
                else:
                    with self.assertRaises(ValueError):
                        world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertFalse(world.refresh_paths["review"].exists())

    def test_v11_review_audit_before_write_and_partial_marker_stays_closed(self):
        """六入力audit失敗時はreview/unsigned/claimを保存せず、marker後も未知署名を拒否する。"""
        with self.world() as world:
            args = self.four_file_checkpoint(world)
            self.accept_refresh(world, args)
            with patch.object(pipeline, "audit_daily_distribution_acquisition_bundle",
                              side_effect=ValueError("AUDIT_REFUSAL")):
                with self.assertRaisesRegex(ValueError, "^AUDIT_REFUSAL$"):
                    world.execute()
            self.assertFalse(world.refresh_paths["review"].exists())
            self.assertFalse(world.claim_path().exists())
            self.assertFalse(world.artifact(".manifest.raw.json").exists())
            self.assert_retained(world)
            world.artifact(".terminal-444.json").write_bytes(pipeline.canonical({
                "generation": world.receipt["generation"], "publicationOutcome": "CAS_INTENT_UNKNOWN"}))
            with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                world.execute()
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)

    def test_v12_unknown_sign_after_refresh_never_resigns(self):
        """新review後も未知native結果・部分envelope・結果記録前crashは再署名しない。"""
        for behavior in ("nonzero", "partial", "result-before-record-crash"):
            with self.subTest(behavior=behavior), self.world() as world:
                args = self.four_file_checkpoint(world)
                self.accept_refresh(world, args)
                world.sign_behavior = behavior
                with self.assertRaises((ValueError, SystemExit)):
                    world.execute()
                with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                    world.execute()
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assert_retained(world)

    def test_v13_original_bucket_and_full_current_config_bytes(self):
        """JST翌日も元start bucketを使い、現configの空白差や旧marker差を同一視しない。"""
        with self.world() as world:
            args = self.four_file_checkpoint(world)
            world.now = world.now.replace(hour=15, minute=1, microsecond=123456)
            self.accept_refresh(world, args)
            raw = world.config_path.read_bytes()
            world.config_path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(ValueError, "^PRESIGN_CONFIG_BYTES$"):
                pipeline.load_config(world.config_path)
            world.config_path.write_bytes(raw)
            code, result = world.execute(main=True)
            self.assertEqual((code, result["status"]), (0, "PUBLISHED"))
            marker = world.out / (world.original_bucket + ".acquisition.verified-unsigned-refresh.json")
            self.assertEqual(json.loads(marker.read_bytes())["configSha256"], pipeline.sha(raw))
            self.assertEqual(pipeline.acquisition_job_day(world.config), world.original_bucket)
            self.assertFalse(any(world.out.glob("20261018.*")))
            self.assert_retained(world)

    def test_v14_real_budget_carries_old_upper_and_new_prepare_once(self):
        """実Budgetへ15/元上界秒と新prepare二callを控除し、runで同使用分を再開する。"""
        with self.world() as world:
            args = self.four_file_checkpoint(world)
            prepare_budget = pipeline.Budget()
            before = prepare_budget.end
            def counted(argv, **kwargs):
                """実processを起動せず、同Budgetのcall消費だけを記録してfakeへ渡す。"""
                prepare_budget.calls += 1
                return world.run(argv, **kwargs)
            with patch.object(prepare_budget, "run", side_effect=counted):
                self.accept_refresh(world, args, budget=prepare_budget)
            self.assertEqual(prepare_budget.calls, 17)
            self.assertEqual(prepare_budget.end, before - 144.72357580207824)
            run_budget = pipeline.Budget()
            run_before = run_budget.end
            binding = world.config["preSignContinuation"]
            def counted_run(argv, **kwargs):
                """runの人工native八callも元の96call枠へ加算する。"""
                run_budget.calls += 1
                return world.run(argv, **kwargs)
            with patch.object(run_budget, "run", side_effect=counted_run):
                result = pipeline.run_pipeline(world.config, world.scope, world.config_hash,
                                               budget=run_budget, remote=world.remote)
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(run_budget.calls, 25)
            carried_seconds = binding["priorElapsedSeconds"] + binding["preparationElapsedSeconds"]
            self.assertEqual(run_budget.end, run_before - carried_seconds)
            with self.assertRaisesRegex(ValueError, "^CODE_REPAIR_BUDGET$"):
                pipeline.carry_code_repair_budget(run_budget, 17, 145.0)

    def test_v15_cli_discriminator_and_prepare_head_history_refusals(self):
        """既存CLIのみから新記述子を作り、混在flagとprepareの現head/history不成立を拒否する。"""
        import prepare_daily_index_config as prepare
        for variant in ("cli", "mixed", "head", "history", "missing-flag", "wrong-mode"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.four_file_checkpoint(world)
                if variant in {"cli", "wrong-mode"}:
                    argv = ["prepare_daily_index_config.py"]
                    for name, value in vars(args).items():
                        if variant != "wrong-mode" or name != "continue_presign_config":
                            argv.extend(["--" + name.replace("_", "-"), str(value)])
                    real_prepare = prepare.continue_presign_config
                    with patch.object(prepare, "continue_presign_config", side_effect=lambda parsed:
                            real_prepare(parsed, budget=world)), patch("sys.argv", argv), \
                            redirect_stdout(io.StringIO()):
                        if variant == "cli":
                            prepare.main()
                            self.assertTrue((args.control_directory / "config.json").exists())
                        else:
                            with self.assertRaisesRegex(ValueError, "^PRESIGN_MODE_REQUIRED$"):
                                prepare.main()
                    continue
                if variant == "mixed":
                    args.phase_evidence = args.budget_witness
                elif variant == "head":
                    world.head_generation = world.receipt["generation"] + 1
                elif variant == "history":
                    world.fail_verify = "--distribution-verify-floor-history"
                else:
                    args.checkpoint_script_sha256 = None
                with self.assertRaises(ValueError):
                    prepare.continue_presign_config(args, budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertFalse(world.refresh_paths["review"].exists())
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)


    def test_v16_each_retained_file_byte_tamper(self):
        """四原fileの各実byte変更は旧pinのまま拒否し、原fileを補完しない。"""
        import prepare_daily_index_config as prepare
        for name in ("body", "release", "inspection", "script"):
            with self.subTest(name=name), self.world() as world:
                args = self.four_file_checkpoint(world)
                path = world.refresh_paths[name]
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaisesRegex(ValueError, "^(PRESIGN_CHECKPOINT_PIN|VERIFIED_UNSIGNED_CHECKPOINT_PIN)$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_v17_ancestor_unknown_witness_without_generation(self):
        """元acquisition/codeRepairの世代未記載witnessも既知連鎖へ結び、署名不明を拒否する。"""
        import prepare_daily_index_config as prepare
        for predecessor in ("code-repair", "base-acquisition"):
            with self.subTest(predecessor=predecessor), self.world() as world:
                args = self.four_file_checkpoint(world)
                binding = world.refresh_predecessor[
                    "preSignContinuation" if predecessor == "code-repair" else "codeRepair"]
                digest = binding["configSha256"]
                world.artifact(".terminal-333.json").write_bytes(pipeline.canonical({
                    "configSha256": digest, "signingOutcome": "NATIVE_OUTCOME_UNKNOWN"}))
                with self.assertRaisesRegex(ValueError, "^SIGNING_OUTCOME_UNKNOWN$"):
                    prepare.continue_presign_config(args, budget=world)
                self.assertEqual(world.calls, [])

    def test_v18_unknown_cas_after_refresh_is_readback_only(self):
        """新review後のCAS応答喪失も同原byte確認だけで再開し、追加CAS/署名をしない。"""
        with self.world() as world:
            args = self.four_file_checkpoint(world)
            self.accept_refresh(world, args)
            original_api = world.remote.api
            def lose(method, path, *values, **kwargs):
                """人工CASの作用後だけ一回の応答を失わせる。"""
                result = original_api(method, path, *values, **kwargs)
                if path == "graphql":
                    raise ValueError("ARTIFICIAL_CAS_REPLY_UNKNOWN")
                return result
            with patch.object(world.remote, "api", lose), \
                    self.assertRaisesRegex(ValueError, "^ARTIFICIAL_CAS_REPLY_UNKNOWN$"):
                world.execute()
            review = world.refresh_paths["review"].read_bytes()
            claim = world.claim_path().read_bytes()
            cas = world.remote.ref_updates
            world.calls.clear()
            world.remote.events.clear()
            result = world.execute()
            self.assertEqual((result["status"], result["resumed"]), ("PUBLISHED", True))
            self.assertEqual(world.remote.ref_updates, cas)
            self.assertTrue(all(method == "GET" for method, _, _ in world.remote.events))
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
            self.assertEqual(world.refresh_paths["review"].read_bytes(), review)
            self.assertEqual(world.claim_path().read_bytes(), claim)
            self.assert_retained(world)

    def test_v19_rebound_inspection_script_still_require_pure_validation(self):
        """指定pinを変えても不正な内容/実行済みscriptをreview保存前の既存pureで拒否する。"""
        for name in ("inspection", "script"):
            with self.subTest(name=name), self.world() as world:
                args = self.four_file_checkpoint(world)
                path = world.refresh_paths[name]
                value = json.loads(path.read_bytes())
                field, replacement = ("inspectionError", 1) if name == "inspection" else ("scriptExecuted", True)
                value[field] = replacement
                path.write_bytes(pipeline.canonical(value))
                setattr(args, "checkpoint_" + name + "_sha256", pipeline.sha(path.read_bytes()))
                world.retained_checkpoint[path] = (path.read_bytes(), path.stat().st_mtime_ns)
                self.accept_refresh(world, args)
                with self.assertRaises(ValueError):
                    world.execute()
                self.assertFalse(world.refresh_paths["review"].exists())
                self.assertFalse(world.claim_path().exists())
                self.assertEqual(world.command_count("--inspect-collected-package"), 0)
                self.assertEqual(world.command_count("--collect-terms-link-script"), 0)


class ApprovedWorkspaceBindingTests(unittest.TestCase):
    """ADR0370の明示承認・config/state・code配置・Task/cwd結合を人工fileだけで検査する。"""

    def test_b01_explicit_binding_is_immutable_and_separate_from_code(self):
        """明示recordの組を固定し、script位置・cwd・caller引数から承認を作らない。"""
        with workspace_fixture() as world:
            original = pipeline.approved_workspace()
            with patch.object(pipeline, "__file__", str(world.root / "scripts/relocated/daily_index_pipeline.py")), \
                    patch.object(pipeline.os, "getcwd", return_value=str(world.directory / "unapproved-cwd")):
                self.assertEqual(pipeline.approved_workspace(), original)
            self.assertEqual(original.repositoryRoot, world.repository)
            self.assertEqual(original.stateRoot, world.state)
            self.assertEqual(original.approvalSha256, pipeline.sha(world.path.read_bytes()))
            with self.assertRaises(AttributeError):
                original.repositoryRoot = world.directory
            with self.assertRaises(TypeError):
                pipeline.approved_workspace(world.path)

    def test_b02_missing_unapproved_and_changed_approval_fail_closed(self):
        """欠損・非承認kindと初回検証後のroot/原byte変更を、fallbackなしで拒否する。"""
        for variant in ("missing", "unapproved", "changed-root", "changed-byte"):
            with self.subTest(variant=variant), workspace_fixture() as world:
                expected = "WORKSPACE_APPROVAL_AUTHORITY"
                if variant == "missing":
                    world.path.unlink()
                    expected = "WORKSPACE_APPROVAL_REQUIRED"
                elif variant == "unapproved":
                    world.path.write_bytes(pipeline.canonical(dict(world.approval, approvalKind="UNAPPROVED")))
                else:
                    pipeline.approved_workspace()
                    expected = "WORKSPACE_APPROVAL_CHANGED"
                    if variant == "changed-root":
                        other = world.directory / "not-approved"
                        state = other / pipeline.STATE_RELATIVE
                        state.mkdir(parents=True)
                        world.path.write_bytes(pipeline.canonical(workspace_approval(other, state)))
                    else:
                        world.path.write_bytes(world.path.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "^" + expected + "$"):
                    pipeline.approved_workspace()

    def test_b03_config_and_state_must_match_approved_pair(self):
        """configのroot/state完全一致と承認recordの固定相対stateを独立に要求する。"""
        for variant in ("repository-mismatch", "state-mismatch", "approval-state-derivation"):
            with self.subTest(variant=variant), workspace_fixture() as world:
                other = world.directory / "other-existing"
                other.mkdir()
                config = {"repositoryRoot": str(world.repository), "stateRoot": str(world.state)}
                if variant == "approval-state-derivation":
                    world.path.write_bytes(pipeline.canonical(dict(world.approval, stateRoot=str(other))))
                else:
                    config["repositoryRoot" if variant == "repository-mismatch" else "stateRoot"] = str(other)
                with self.assertRaisesRegex(ValueError, "^FIXED_EXISTING_ROOT$"):
                    pipeline.require_config_workspace(config)

    def test_b04_approval_schema_paths_acl_and_reparse_are_checked(self):
        """閉schema、duplicate JSON、任意path、reparse、非保護ACLとscope差を拒否する。"""
        cases = (("unknown", "WORKSPACE_APPROVAL_FIELDS"), ("duplicate", "DUPLICATE_JSON_KEY"),
                 ("relative", "ABSOLUTE_FIXED_PATH"), ("unc", "ABSOLUTE_FIXED_PATH"),
                 ("parent", "ABSOLUTE_FIXED_PATH"), ("reparse", "REPARSE_PATH"),
                 ("acl", "PROTECTED_OWNER"), ("manifest", "WORKSPACE_APPROVAL_AUTHORITY"),
                 ("task", "WORKSPACE_APPROVAL_AUTHORITY"))
        for variant, reason in cases:
            with self.subTest(variant=variant), workspace_fixture() as world, ExitStack() as stack:
                value = dict(world.approval)
                if variant == "unknown":
                    value["approvedByConfig"] = True
                elif variant == "relative":
                    value["repositoryRoot"] = "arbitrary-relative-workspace"
                elif variant == "unc":
                    value["repositoryRoot"] = "\\\\artificial-host\\workspace"
                elif variant == "parent":
                    value["repositoryRoot"] = str(world.repository / ".." / "arbitrary")
                elif variant == "reparse":
                    stack.enter_context(patch.object(Path, "is_junction", return_value=True))
                elif variant == "acl":
                    stack.enter_context(patch.object(pipeline, "acl_snapshot", return_value=("S-1-5-32-545", True, [])))
                elif variant == "manifest":
                    value["collectorManifestSha256"] = "0" * 64
                elif variant == "task":
                    value["taskName"] = "Other.Task"
                raw = pipeline.canonical(value)
                if variant == "duplicate":
                    raw = raw[:-1] + b',"schema":"dc-approved-daily-workspace-v1"}'
                world.path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    pipeline.approved_workspace()

    def test_b05_relocated_versioned_code_keeps_v1_v2_workspace(self):
        """versioned v2と明示継承v1は同じ人工承認先だけを使い、config変更を拒否する。"""
        with DailyAcquisitionIssuanceTests().world() as world:
            binding = pipeline.approved_workspace()
            self.assertNotEqual(world.version, binding.repositoryRoot)
            self.assertEqual(world.config["schema"], "dc-private-daily-index-config-v2")
            legacy, _, _ = pipeline.load_config(world.args.inherit_config, inherited_v1=True)
            self.assertEqual(legacy["schema"], "dc-private-daily-index-config-v1")
            for config in (legacy, world.config):
                self.assertEqual(pipeline.require_config_workspace(config), binding)
            other = world.root / "not-approved-workspace"
            other.mkdir()
            with self.assertRaisesRegex(ValueError, "^FIXED_EXISTING_ROOT$"):
                pipeline.require_config_workspace(dict(world.config, repositoryRoot=str(other)))
            self.assertEqual(world.calls, [])
            self.assertEqual(world.remote.events, [])

    def test_b06_task_action_and_cwd_are_bound_to_config(self):
        """TaskのAction/code/configと承認cwdを同時確認し、configだけのroot差替えを拒否する。"""
        with workspace_fixture() as world:
            config = {"repositoryRoot": str(world.repository), "stateRoot": str(world.state),
                "pythonExe": __import__("sys").executable, "smokeLocal": "2026-10-15T15:00:00+09:00",
                "firstDailyLocal": "2026-10-16T15:00:00+09:00"}
            config_path = world.root / "control/artificial/config.json"
            code = world.root / "scripts/v2-artificial/daily_index_pipeline.py"
            with patch.object(pipeline, "__file__", str(code)):
                tree = ET.fromstring(pipeline.task_xml(config, config_path, "S-1-5-21-111-222-333-1001"))
            ns = {"t": pipeline.TASK_NS}
            self.assertEqual(tree.find("t:Actions/t:Exec/t:WorkingDirectory", ns).text, str(world.repository))
            self.assertEqual(tree.find("t:Actions/t:Exec/t:Command", ns).text,
                             str(Path(config["pythonExe"]).with_name("pythonw.exe")))
            self.assertEqual(tree.find("t:Actions/t:Exec/t:Arguments", ns).text,
                pipeline.subprocess.list2cmdline(["-I", str(code), "run", str(config_path)]))
            with self.assertRaisesRegex(ValueError, "^FIXED_EXISTING_ROOT$"):
                pipeline.task_xml(dict(config, repositoryRoot=str(world.directory)), config_path,
                                  "S-1-5-21-111-222-333-1001")

    def test_b07_process_cwd_and_changed_binding_precede_spawn(self):
        """実processを起動せず、承認cwdと変更recordのspawn前拒否を確認する。"""
        with workspace_fixture() as world:
            directory = world.root / "operations/artificial-job"
            directory.mkdir(parents=True)
            budget = pipeline.Budget()
            budget.directory = directory
            process = SimpleNamespace(returncode=0, poll=lambda: 0)
            with patch.object(pipeline.subprocess, "Popen", return_value=process) as spawn:
                self.assertEqual(budget.run(["ARTIFICIAL_NO_PROCESS"]), (0, b"", b""))
                self.assertEqual(spawn.call_args.kwargs["cwd"], world.repository)
                spawn.reset_mock()
                world.path.write_bytes(world.path.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "^WORKSPACE_APPROVAL_CHANGED$"):
                    budget.run(["ARTIFICIAL_NO_PROCESS"])
                spawn.assert_not_called()
            self.assertEqual(budget.calls, 2)

    def test_b08_prepare_defaults_need_explicit_approval(self):
        """prepareの既定pathも人工承認先から導き、欠損時は継承処理より前に拒否する。"""
        import prepare_daily_index_config as prepare
        with workspace_fixture() as world:
            config_path = world.root / "control/artificial/config.json"
            argv = ["prepare_daily_index_config.py", "--inherit-config", str(config_path)]
            with patch.object(prepare, "inherit_config") as inherit, \
                    patch.object(pipeline.sys, "argv", argv), redirect_stdout(io.StringIO()):
                prepare.main()
                args = inherit.call_args.args[0]
                self.assertEqual(args.manifest_file, world.repository / "tests/fixtures/local_driver_collector_intel_live_v1.json")
                self.assertEqual(args.collector_exe, world.repository / "build/Release/DriverCrateCollector.exe")
                self.assertEqual(args.signer_exe, world.repository / "build/Release/DriverCrateLocalIndexSigner.exe")
                world.path.unlink()
                inherit.reset_mock()
                with self.assertRaisesRegex(ValueError, "^WORKSPACE_APPROVAL_REQUIRED$"):
                    prepare.main()
                inherit.assert_not_called()


class AssetUploadLengthTests(unittest.TestCase):
    """ADR0377の実GitHub.apiを人工Budgetへ接続し、要求byteと起動前拒否を確認する。"""

    @staticmethod
    def route(name="index.json.gz"):
        """実配布先を呼ばず、固定repositoryの人工Release IDへ要求を構築する。"""
        return "https://uploads.github.com/" + pipeline.API + "/releases/7/assets?name=" + name

    def test_u01_exact_3352_1493_bytes_mime_url_and_single_length(self):
        """二assetの元byteをそのまま渡し、既知長headerを一件だけ付ける。"""
        for name, size, mime in (("index.json.gz", 3352, "application/gzip"),
                                 ("manifest.json", 1493, "application/json")):
            with self.subTest(asset=name):
                raw = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
                budget = DiagnosticBudget([(0, b'{"id":7}', b"")])
                remote = pipeline.GitHub("artificial-gh", budget)
                self.assertEqual(remote.api("POST", self.route(name), raw, content_type=mime), {"id": 7})
                argv, data, maximum, seconds = budget.calls[0]
                self.assertIs(data, raw)
                self.assertEqual((maximum, seconds), (pipeline.MAX_FILE, 30))
                self.assertEqual(argv[:7], ["artificial-gh", "api", "--hostname", "github.com",
                                           "--method", "POST", self.route(name)])
                self.assertEqual(argv.count("--input"), 1)
                self.assertEqual(argv[argv.index("--input") + 1], "-")
                headers = [argv[index + 1] for index, value in enumerate(argv) if value == "--header"]
                self.assertEqual([value for value in headers if value.lower().startswith("content-length:")],
                                 ["Content-Length: " + str(size)])
                self.assertEqual(headers.count("Content-Type: " + mime), 1)
                self.assertEqual(remote.ordinal, 1)

    def test_u02_non_ascii_length_is_encoded_bytes(self):
        """JSON文字数や再serializationを使わず、送るUTF-8 byteの長さへ拘束する。"""
        raw = '{"表示":"日本語"}'.encode("utf-8")
        budget = DiagnosticBudget([(0, b"{}", b"")])
        pipeline.GitHub("artificial-gh", budget).api(
            "POST", self.route("manifest.json"), raw, content_type="application/json")
        argv, data, _, _ = budget.calls[0]
        self.assertIs(data, raw)
        self.assertIn("Content-Length: " + str(len(raw)), argv)
        self.assertNotIn("Content-Length: " + str(len(raw.decode("utf-8"))), argv)

    def test_u03_get_binary_and_json_argv_are_unchanged(self):
        """通常GET/JSON要求のheader・raw input・結果契約を既存形のまま維持する。"""
        budget = DiagnosticBudget([(0, b"{}", b""), (0, b"raw", b""), (0, b"{}", b"")])
        remote = pipeline.GitHub("artificial-gh", budget)
        self.assertEqual(remote.api("GET", "user"), {})
        self.assertEqual(remote.api("GET", pipeline.API + "/releases/assets/1", binary=True), b"raw")
        body = {"name": "日本語", "draft": True}
        self.assertEqual(remote.api("POST", pipeline.API + "/releases", body), {})
        base = ["artificial-gh", "api", "--hostname", "github.com", "--method"]
        common = ["--header", "X-GitHub-Api-Version: 2022-11-28", "--header"]
        self.assertEqual(budget.calls[0][:2], (base + ["GET", "user"] + common +
                         ["Accept: application/vnd.github+json"], None))
        self.assertEqual(budget.calls[1][:2], (base + ["GET", pipeline.API + "/releases/assets/1"] +
                         common + ["Accept: application/octet-stream"], None))
        self.assertEqual(budget.calls[2][:2], (base + ["POST", pipeline.API + "/releases"] + common +
                         ["Accept: application/vnd.github+json", "--input", "-", "--header",
                          "Content-Type: application/json"], pipeline.canonical(body)))
        self.assertFalse(any(any(value.startswith("Content-Length:") for value in call[0])
                             for call in budget.calls))

    def test_u04_invalid_path_method_and_mime_are_no_child(self):
        """別repository・未知名・曖昧query・不正ID・method/MIMEを起動前に拒否する。"""
        route = self.route()
        variants = [("GET", route, "application/gzip"), ("PATCH", route, "application/gzip"),
            ("POST", route.replace("EnterOgawa/drivercrate", "other/drivercrate"), "application/gzip"),
            ("POST", route.replace("/7/", "/0/"), "application/gzip"),
            ("POST", route.replace("/7/", "/07/"), "application/gzip"),
            ("POST", self.route("unknown.gz"), "application/gzip"),
            ("POST", route + "&label=x", "application/gzip"),
            ("POST", route + "#fragment", "application/gzip"),
            ("POST", route.replace("index.json.gz", "index%2Ejson.gz"), "application/gzip"),
            ("POST", route, "application/json"),
            ("POST", self.route("manifest.json"), "application/gzip"),
            ("POST", route, "application/gzip\r\nContent-Length: 1")]
        for method, path, mime in variants:
            with self.subTest(method=method, path=path, mime=mime):
                budget = DiagnosticBudget([])
                remote = pipeline.GitHub("artificial-gh", budget)
                with self.assertRaises(ValueError):
                    remote.api(method, path, b"artificial", content_type=mime)
                self.assertFalse(budget.calls)
                self.assertEqual(remote.ordinal, 0)

    def test_u05_invalid_body_type_empty_or_oversize_are_no_child(self):
        """可変buffer・非byte・空・上限超過をJSON化や子processへ進めない。"""
        class ByteSubclass(bytes):
            """正確なbytes型の拒否境界を確認する人工subclass。"""
        for raw in (None, "x", 1, {"x": 1}, bytearray(b"x"), memoryview(b"x"),
                    ByteSubclass(b"x"), b"", b"x" * (pipeline.MAX_FILE + 1)):
            with self.subTest(kind=type(raw).__name__):
                budget = DiagnosticBudget([])
                remote = pipeline.GitHub("artificial-gh", budget)
                with self.assertRaisesRegex(ValueError, "^ASSET_UPLOAD_BYTES$"):
                    remote.api("POST", self.route(), raw, content_type="application/gzip")
                self.assertFalse(budget.calls)
                self.assertEqual(remote.ordinal, 0)


class PublicDailyConfigTests(unittest.TestCase):
    """ADR0382の実loader/明示prepare/Publisher接続と、未認証履歴の閉入口を検査する。"""

    @contextmanager
    def world(self, *, status=200, initial_now=None):
        """公開sourceの公開blobと隔離fileを使い、OS ACL問い合わせとnativeだけを人工化する。"""
        trust = (Path(__file__).resolve().parents[1] / "src/platform/index_distribution_trust.h").read_text(
            encoding="utf-8").split("PUBLIC_BLOB{", 1)[1].split("} ;", 1)[0]
        blob = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})U", trust))
        self.assertEqual(len(blob), 411)
        self.assertEqual(pipeline.sha(blob), "0ac4d0ce9873c82b3c7bb7bd3fb3f5d2a57044bf968c5c6e2af02176cee39d3f")
        with tempfile.TemporaryDirectory() as temporary:
            world = IssuanceWorld.__new__(IssuanceWorld)
            try:
                world.__init__(Path(temporary), status=status, public_blob=blob, initial_now=initial_now)
                world.stack.enter_context(patch.object(pipeline, "_APPROVED_PUBLIC_PUBLISHER", None))
                world.public_approval = world.root / "control/approved-public-publisher.json"
                world.public_approval.write_bytes(pipeline.canonical(dict(pipeline.PUBLIC_APPROVAL_VALUES)))
                # 実path/ACL/ancestor/reparse/link policyを戻し、snapshotのOS照会だけを人工化する。
                with ReceiptAnchorAndRepairTests().policy(world.root):
                    yield world
            finally:
                if hasattr(world, "stack"):
                    world.close()

    def args(self, world):
        """原v2/承認recordの原SHAを明示し、任意approval pathや新outputを持たない引数を返す。"""
        return SimpleNamespace(public_config_from=world.config_path, predecessor_config_sha256=world.config_hash,
            public_publisher_approval_sha256=pipeline.sha(world.public_approval.read_bytes()),
            control_directory=world.root / "control/public-v3")

    def prepare(self, world):
        """実preparerと実loaderを通し、new configと原byte hashを返す。"""
        import prepare_daily_index_config as prepare
        path = prepare.prepare_public_config(self.args(world))
        config, scope, digest = pipeline.load_config(path)
        return path, config, scope, digest

    def test_q01_fixed_approval_bytes_pin_and_identity(self):
        """固定保護位置・原SHA・意味/型・process内初回原byteを外部作用なしで検査する。"""
        variants = ("exact", "missing", "pin", "pin-type", "unknown", "identity", "type", "changed")
        for variant in variants:
            with self.subTest(variant=variant), workspace_fixture() as world, \
                    patch.object(pipeline, "_APPROVED_PUBLIC_PUBLISHER", None):
                path = world.root / "control/approved-public-publisher.json"
                raw = pipeline.canonical(dict(pipeline.PUBLIC_APPROVAL_VALUES))
                path.write_bytes(raw)
                digest = pipeline.sha(raw)
                reason = None
                if variant == "missing":
                    path.unlink()
                    reason = "PUBLIC_APPROVAL_REQUIRED"
                elif variant == "pin":
                    digest, reason = "f" * 64, "PUBLIC_APPROVAL_PIN"
                elif variant == "pin-type":
                    digest, reason = True, "PUBLIC_APPROVAL_PIN"
                elif variant in {"unknown", "identity", "type"}:
                    value = json.loads(raw)
                    value["extra" if variant == "unknown" else "repositoryId"] = "wrong" if variant != "type" else True
                    raw = pipeline.canonical(value)
                    path.write_bytes(raw)
                    digest = pipeline.sha(raw)
                    reason = "PUBLIC_APPROVAL_FIELDS" if variant == "unknown" else "PUBLIC_APPROVAL_VALUE"
                elif variant == "changed":
                    pipeline.approved_public_publisher(digest)
                    path.write_bytes(raw + b"\n")
                    digest, reason = pipeline.sha(path.read_bytes()), "PUBLIC_APPROVAL_CHANGED"
                if reason is not None:
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        pipeline.approved_public_publisher(digest)
                else:
                    target = pipeline.approved_public_publisher(digest)
                    self.assertEqual(target.approval_bytes, raw)
                    self.assertEqual(target.approval_sha256, digest)
                    with self.assertRaises(TypeError):
                        pipeline.approved_public_publisher(digest, path)

    def test_q02_prepare_load_and_public_publisher(self):
        """正常v2→明示prepare→実load→既存Public Publisherへ二asset/一CASで接続する。"""
        for status in (200, 304):
            with self.subTest(status=status), self.world(status=status) as world:
                original = world.config_path.read_bytes()
                path, config, scope, digest = self.prepare(world)
                self.assertEqual(digest, pipeline.sha(path.read_bytes()))
                self.assertEqual(config["predecessorConfigSha256"], pipeline.sha(original))
                self.assertEqual(world.config_path.read_bytes(), original)
                self.assertEqual(scope, world.scope)
                inherited = {name: value for name, value in config.items() if name not in pipeline.PUBLIC_CONFIG_FIELDS}
                inherited["schema"] = "dc-private-daily-index-config-v2"
                self.assertEqual(pipeline.canonical(inherited), pipeline.canonical(world.config))
                self.assertEqual(list(path.parent.iterdir()), [path])
                boundary = PublicPublisherIdentityTests()
                try:
                    boundary.setUp()
                    remote = PublicIdentityRemote()
                    callback = []
                    publisher = pipeline.acquisition_publisher(config, remote, boundary.verify,
                        before_cas=lambda: callback.append("CAS"), anonymous=publisher_anonymous_fixture)
                    result = publisher.publish(boundary.bundle)
                    self.assertEqual(result["status"], "PUBLISHED")
                    self.assertEqual(remote.ref_updates, 1)
                    writes = [event for event in remote.events if event[0] != "GET"]
                    self.assertEqual(len(writes), 8)
                    self.assertEqual(callback, ["CAS"])
                    self.assertEqual({name for _, route, _ in writes if "?name=" in route
                                      for name in [route.split("?name=")[1]]}, pipeline.ASSETS)
                    self.assertTrue(boundary.verifications)
                finally:
                    boundary.doCleanups()
                # 使用時にも固定recordの原byteを再検査し、load済みを許可の永続cacheにしない。
                world.public_approval.write_bytes(world.public_approval.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "^PUBLIC_APPROVAL_PIN$"):
                    pipeline.acquisition_publisher(config, PublicIdentityRemote(), lambda *a, **k: None)
                self.assertEqual(world.calls, [])

    def test_q03_v3_closed_fields_types_and_predecessor(self):
        """v3だけの閉field/型/原config pin・位置・schemaをremote構築前に拒否する。"""
        with self.world() as world:
            path, _, _, _ = self.prepare(world)
            for name in ("inherited_v1", "predecessor_v2", "presign_predecessor", "verified_unsigned_predecessor"):
                with self.subTest(context=name):
                    with self.assertRaisesRegex(ValueError, "^PUBLIC_CONFIG_CONTEXT$"):
                        pipeline.load_config(path, **{name: True})
        variants = ("missing", "unknown", "duplicate", "approval-path", "approval-pin", "approval-type",
                    "predecessor-pin", "predecessor-type", "predecessor-location", "v1", "v3-chain", "purpose")
        for variant in variants:
            with self.subTest(variant=variant), self.world() as world:
                path, config, _, _ = self.prepare(world)
                reason = "PUBLIC_CONFIG_FIELDS"
                raw = None
                if variant == "missing":
                    del config["publicPublisherApprovalSha256"]
                elif variant in {"unknown", "approval-path"}:
                    config["unknown" if variant == "unknown" else "publicPublisherApprovalFile"] = str(world.public_approval)
                elif variant == "duplicate":
                    raw = pipeline.canonical(config)[:-1] + b',"predecessorConfigSha256":"' + b"a" * 64 + b'"}'
                    reason = "DUPLICATE_JSON_KEY"
                elif variant in {"approval-pin", "approval-type"}:
                    config["publicPublisherApprovalSha256"] = "f" * 64 if variant.endswith("pin") else False
                    reason = "PUBLIC_APPROVAL_PIN"
                elif variant in {"predecessor-pin", "predecessor-type"}:
                    config["predecessorConfigSha256"] = "f" * 64 if variant.endswith("pin") else 1
                    reason = "PUBLIC_PREDECESSOR_PIN"
                elif variant == "predecessor-location":
                    config["predecessorConfigFile"] = str(world.out / "config.json")
                    Path(config["predecessorConfigFile"]).write_bytes(world.config_path.read_bytes())
                    reason = "PUBLIC_PREDECESSOR_LOCATION"
                elif variant in {"v1", "v3-chain"}:
                    old = json.loads(world.config_path.read_bytes())
                    old["schema"] = "dc-private-daily-index-config-v1" if variant == "v1" else pipeline.PUBLIC_CONFIG_SCHEMA
                    world.config_path.write_bytes(pipeline.canonical(old))
                    config["predecessorConfigSha256"] = pipeline.sha(world.config_path.read_bytes())
                    reason = "PUBLIC_PREDECESSOR_SCHEMA"
                else:
                    config["purpose"], reason = "METADATA", "PUBLIC_CONFIG_PURPOSE"
                path.write_bytes(raw or pipeline.canonical(config))
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    pipeline.load_config(path)
                self.assertEqual(world.calls, [])

    def test_q04_predecessor_and_semantics_cannot_change(self):
        """元byte/code/全意味fieldを保持し、実旧continuationのcarryと原markerも削除しない。"""
        with self.subTest(variant="key-order"), self.world() as world:
            path, config, _, _ = self.prepare(world)
            path.write_bytes(pipeline.canonical(dict(reversed(list(config.items())))))
            reordered, _, _ = pipeline.load_config(path)
            self.assertEqual(reordered, config)
            reordered["archiveBytes"] = float(reordered["archiveBytes"])
            path.write_bytes(pipeline.canonical(reordered))
            with self.assertRaisesRegex(ValueError, "^PUBLIC_CONFIG_SEMANTICS$"):
                pipeline.load_config(path)
        for variant in ("raw", "module", "scope", "outputRoot", "stateRoot", "repositoryRoot", "fingerprint",
                        "firstDailyLocal", "codeRepair", "preSignContinuation"):
            with self.subTest(variant=variant), self.world() as world:
                path, config, _, _ = self.prepare(world)
                reason = "PUBLIC_CONFIG_SEMANTICS"
                if variant == "raw":
                    world.config_path.write_bytes(world.config_path.read_bytes() + b"\n")
                    reason = "PUBLIC_PREDECESSOR_PIN"
                elif variant == "module":
                    module = Path(pipeline.__file__)
                    module.write_bytes(module.read_bytes() + b"CHANGED")
                    reason = "SCRIPT_PIN"
                elif variant == "scope":
                    config["scopeFile"] = str(world.root / "control/rebound-scope.json")
                elif variant in {"codeRepair", "preSignContinuation"}:
                    config[variant] = {"priorNativeCalls": 0, "priorElapsedSeconds": 0}
                else:
                    config[variant] = "CHANGED"
                path.write_bytes(pipeline.canonical(config))
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    pipeline.load_config(path)
                self.assertEqual(world.calls, [])
        with self.subTest(variant="original-continuation-carry"), self.world() as world:
            import prepare_daily_index_config as prepare
            old_fixture = VerifiedUnsignedRefreshTests()
            # 旧fixtureの二読取clockをprepare専用へ隔離し、実保護treeの有限clockを置換しない。
            with patch.object(prepare, "time", SimpleNamespace(monotonic=pipeline.time.monotonic)):
                args = old_fixture.four_file_checkpoint(world)
                old_fixture.accept_refresh(world, args)
            before = deepcopy(world.config)
            retained = dict(world.retained_checkpoint)
            path, config, _, _ = self.prepare(world)
            self.assertEqual(config["codeRepair"], before["codeRepair"])
            self.assertEqual(config["preSignContinuation"], before["preSignContinuation"])
            self.assertEqual(config["preSignContinuation"]["priorNativeCalls"], 15)
            for source, (raw, modified) in retained.items():
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual(source.stat().st_mtime_ns, modified)
            config["preSignContinuation"]["priorNativeCalls"] = 0
            path.write_bytes(pipeline.canonical(config))
            with self.assertRaisesRegex(ValueError, "^PUBLIC_CONFIG_SEMANTICS$"):
                pipeline.load_config(path)
            self.assertEqual(world.calls, [])

    def test_q05_approval_acl_reparse_and_hardlink(self):
        """実保護path規則で固定recordと祖先のACL・reparse・linkを検査する。"""
        for variant, reason in (("owner", "PROTECTED_OWNER"), ("write", "PROTECTED_GENERAL_USER_WRITE"),
            ("ancestor", "PROTECTED_GENERAL_USER_WRITE"), ("protected", "PROTECTED_DACL_REQUIRED"),
            ("reparse", "REPARSE_PATH"), ("hardlink", "PROTECTED_HARDLINK")):
            with self.subTest(variant=variant), workspace_fixture() as world, ExitStack() as stack:
                stack.enter_context(patch.object(pipeline, "_APPROVED_PUBLIC_PUBLISHER", None))
                path = world.root / "control/approved-public-publisher.json"
                raw = pipeline.canonical(dict(pipeline.PUBLIC_APPROVAL_VALUES))
                path.write_bytes(raw)
                owner, protected, entries = world.safe
                target = path
                if variant == "owner":
                    owner = "S-1-5-32-545"
                elif variant in {"write", "ancestor"}:
                    entries = entries + [(0, 0, 0x40 if variant == "ancestor" else 0x100, "S-1-5-32-545")]
                    target = world.directory if variant == "ancestor" else path
                elif variant == "protected":
                    target, protected = world.root, False
                elif variant == "reparse":
                    original = Path.is_junction
                    stack.enter_context(patch.object(Path, "is_junction", lambda item: item == path or original(item)))
                elif variant == "hardlink":
                    original = Path.stat
                    def linked(item, *args, **kwargs):
                        """人工recordのlink数だけを変更し、実linkや保護fileを作らない。"""
                        value = original(item, *args, **kwargs)
                        return SimpleNamespace(st_mode=value.st_mode, st_size=value.st_size,
                            st_file_attributes=value.st_file_attributes, st_nlink=2) if item == path else value
                    stack.enter_context(patch.object(Path, "stat", linked))
                stack.enter_context(patch.object(pipeline, "acl_snapshot",
                    side_effect=lambda item: (owner, protected, entries) if item == target else world.safe))
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    pipeline.approved_public_publisher(pipeline.sha(raw))

    def test_q06_prepare_create_new_and_mode_separation(self):
        """旧先上書き・新root/日程・混合modeを拒否し、失敗時の部分新fileを保持する。"""
        import prepare_daily_index_config as prepare
        for variant in ("existing", "old-control", "new-output", "schedule", "native", "mixed", "pin", "partial",
                        "preparer-location"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.args(world)
                before = world.config_path.read_bytes()
                reason = "PUBLIC_PREPARE_MIXED_MODE"
                if variant == "existing":
                    args.control_directory.mkdir()
                    reason = "NEW_CONTROL_DIRECTORY"
                elif variant == "old-control":
                    args.control_directory, reason = world.config_path.parent, "NEW_CONTROL_DIRECTORY"
                elif variant == "new-output":
                    args.new_output_root = world.root / "operations/rebound"
                elif variant == "schedule":
                    args.first_daily_local = "2026-10-19T12:00:00Z"
                elif variant == "native":
                    args.collector_exe = world.collector
                elif variant == "mixed":
                    args.repair_config = world.config_path
                elif variant == "pin":
                    args.predecessor_config_sha256, reason = "f" * 64, "PUBLIC_PREDECESSOR_PIN"
                elif variant == "preparer-location":
                    with patch.object(prepare, "__file__", str(world.root / "not-approved/prepare_daily_index_config.py")):
                        with self.assertRaisesRegex(ValueError, "^PROTECTED_PREPARER_LOCATION$"):
                            prepare.prepare_public_config(args)
                    self.assertFalse(args.control_directory.exists())
                    self.assertEqual(world.config_path.read_bytes(), before)
                    continue
                else:
                    with patch.object(pipeline, "write_new", side_effect=OSError("ARTIFICIAL_PARTIAL")):
                        with self.assertRaisesRegex(OSError, "ARTIFICIAL_PARTIAL"):
                            prepare.prepare_public_config(args)
                    self.assertTrue(args.control_directory.is_dir())
                    self.assertEqual(world.config_path.read_bytes(), before)
                    continue
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    prepare.prepare_public_config(args)
                self.assertEqual(world.config_path.read_bytes(), before)
                self.assertEqual(world.calls, [])

    def test_q07_pending_history_precedes_all_effects(self):
        """同観測/新日/due前/UNKNOWN/失効でもv3を閉じ、carry・lock・署名・terminalを変更しない。"""
        for variant in ("same-observation", "new-day", "before-due", "unknown", "expired"):
            with self.subTest(variant=variant), self.world() as world:
                path, config, scope, digest = self.prepare(world)
                budget = pipeline.Budget()
                budget.calls = 90
                end = budget.end
                if variant == "new-day":
                    world.now += timedelta(days=1)
                elif variant == "before-due":
                    world.now -= timedelta(days=1)
                elif variant == "expired":
                    world.now += timedelta(days=20)
                if variant == "unknown":
                    world.artifact(".terminal-unknown.json").write_bytes(pipeline.canonical({
                        "status": "UNKNOWN", "publicationOutcome": "CAS_INTENT_UNKNOWN",
                        "configSha256": world.config_hash}))
                original = {item.name: item.read_bytes() for item in world.out.iterdir() if item.is_file()}
                with patch.object(pipeline, "exclusive") as lock, \
                        patch.object(pipeline, "collect_daily_acquisition_receipt") as collect, \
                        patch.object(pipeline, "acquisition_publisher") as publish, \
                        patch.object(pipeline, "write_new") as write:
                    for action in (lambda: pipeline.run_pipeline(config, scope, digest, budget=budget),
                        lambda: pipeline.run_acquisition(config, scope, digest, path.parent, budget, world.remote),
                        lambda: pipeline.task_xml(config, path, "S-1-5-21-111-222-333-1001"),
                        lambda: pipeline.report(config)):
                        with self.assertRaisesRegex(ValueError, "^PUBLIC_HISTORY_TRANSITION_REQUIRED$"):
                            action()
                    lock.assert_not_called()
                    collect.assert_not_called()
                    publish.assert_not_called()
                    write.assert_not_called()
                self.assertEqual(budget.calls, 90)
                self.assertEqual(budget.end, end)
                self.assertEqual(original, {item.name: item.read_bytes() for item in world.out.iterdir() if item.is_file()})
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_q08_legacy_defaults_and_plan_truth(self):
        """実CLI関数の明示mode/planを隔離して検査し、v1/v2のPrivate既定と閉fieldを保持する。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.args(world)
            argv = ["prepare_daily_index_config.py", "--public-config-from", str(args.public_config_from),
                "--predecessor-config-sha256", args.predecessor_config_sha256,
                "--public-publisher-approval-sha256", args.public_publisher_approval_sha256,
                "--control-directory", str(args.control_directory)]
            with patch("sys.argv", argv), redirect_stdout(io.StringIO()) as output:
                prepare.main()
            self.assertIn("HISTORY_TRANSITION_REQUIRED", output.getvalue())
            path = args.control_directory / "config.json"
            for mode in ("run", "task", "report"):
                with self.subTest(mode=mode), patch("sys.argv", ["daily_index_pipeline.py", mode, str(path)]), \
                        patch.object(pipeline, "write_new") as write:
                    with self.assertRaisesRegex(ValueError, "^PUBLIC_HISTORY_TRANSITION_REQUIRED$"):
                        pipeline.main()
                    write.assert_not_called()
            plan_path = path.parent / "plan.json"
            with patch("sys.argv", ["daily_index_pipeline.py", "plan", str(path), "--output", str(plan_path)]), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(pipeline.main(), 0)
            plan = json.loads(plan_path.read_bytes())
            self.assertFalse(plan["privateRequired"])
            self.assertFalse(plan["executable"])
            self.assertTrue(plan["historyTransitionRequired"])
            self.assertIsNone(plan["taskName"])
            with patch("sys.argv", ["prepare_daily_index_config.py", "--public-publisher-approval-sha256",
                                    args.public_publisher_approval_sha256]):
                with self.assertRaisesRegex(ValueError, "^PUBLIC_PREPARE_MODE_REQUIRED$"):
                    prepare.main()
            for schema in ("dc-private-daily-index-config-v1", "dc-private-daily-index-config-v2"):
                with self.subTest(schema=schema):
                    publisher = pipeline.acquisition_publisher({"schema": schema}, PublicIdentityRemote(), lambda *a, **k: None)
                    self.assertIsNone(publisher._public_target)
                    with self.assertRaisesRegex(ValueError, "^PRIVATE_IDENTITY$"):
                        publisher.identity()
            old_v1 = Path(world.config["legacyMetadata"]["configFile"])
            for source, reason in ((world.config_path, "CONFIG_FIELDS_V2"), (old_v1, "CONFIG_FIELDS")):
                with self.subTest(closed=reason):
                    old = json.loads(source.read_bytes())
                    old["publicPublisherApprovalSha256"] = args.public_publisher_approval_sha256
                    source.write_bytes(pipeline.canonical(old))
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        pipeline.load_config(source)
            self.assertEqual(world.calls, [])


class PublicHistoryTransitionTests(unittest.TestCase):
    """ADR0383の固定九test。実旧環境を触らず、期限後chainから共通取得への有限接続を確認する。"""

    @contextmanager
    def world(self, *, status=200, chain=True, initial_now=None):
        """原旧成功を作り、現在runtimeとfake保護headだけを別のbyteへ切り替える。"""
        import prepare_daily_index_config as prepare
        with PublicDailyConfigTests().world(initial_now=initial_now) as world:
            if chain:
                prior = VerifiedUnsignedRefreshTests()
                with patch.object(prepare, "time", SimpleNamespace(monotonic=pipeline.time.monotonic)):
                    args = prior.four_file_checkpoint(world)
                    prior.accept_refresh(world, args)
            code, result = world.execute(main=True)
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "PUBLISHED")
            world.old_config, world.old_hash, world.old_config_path = deepcopy(world.config), world.config_hash, world.config_path
            world.old_receipt = deepcopy(world.receipt)
            world.old_day = world.now.strftime("%Y%m%d")
            world.old_envelope = world.artifact(".manifest.json")
            world.old_signer = world.config["signerExe"]
            world.retained = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in world.out.iterdir() if path.is_file()}
            old_remote = world.remote
            world.remote = PublicIdentityRemote()
            for name in ("releases", "assets", "blobs", "trees", "commits", "head", "counter"):
                setattr(world.remote, name, deepcopy(getattr(old_remote, name)))
            version = world.root / "scripts/v2-artificial-public-current"
            binary = world.root / "bin" / version.name
            version.mkdir()
            binary.mkdir(parents=True)
            old_version = Path(pipeline.__file__).parent
            for name in pipeline.MODULE_NAMES:
                (version / name).write_bytes((old_version / name).read_bytes() + b"_PUBLIC_CURRENT")
            for name in ("DriverCrateCollector.exe", "DriverCrateLocalIndexSigner.exe"):
                (binary / name).write_bytes(b"ARTIFICIAL_CURRENT_NONEXECUTABLE")
            for owner, name, path in ((pipeline, "__file__", version / "daily_index_pipeline.py"),
                (pipeline.projection, "__file__", version / "project_collected_native_index.py"),
                (pipeline.cr, "__file__", version / "collector_registry.py"),
                (prepare, "__file__", version / "prepare_daily_index_config.py")):
                world.stack.enter_context(patch.object(owner, name, str(path)))
            world.now += timedelta(days=1, seconds=2)
            world.refresh(status=status, generation=world.old_receipt["generation"] + 1)
            world.receipt["previousReceiptSha256"] = pipeline.sha(pipeline.canonical(world.old_receipt))
            if status == 304:
                for name in ("lastFetchedAt", "bodySha256", "bodyBytesBase64", "projectionSha256",
                             "projectionBytesBase64", "records"):
                    world.receipt[name] = deepcopy(world.old_receipt[name])
            args = PublicDailyConfigTests().args(world)
            args.public_history_envelope = world.old_envelope
            args.public_history_envelope_sha256 = pipeline.sha(world.old_envelope.read_bytes())
            args.collector_exe = binary / "DriverCrateCollector.exe"
            args.signer_exe = binary / "DriverCrateLocalIndexSigner.exe"
            world.config_path = prepare.prepare_public_config(args)
            world.config, world.scope, world.config_hash = pipeline.load_config(world.config_path)
            self.assertNotEqual(world.old_signer, world.config["signerExe"])
            self.assertEqual(world.config.get("preSignContinuation"), world.old_config.get("preSignContinuation"))
            world.history_path = world.config_path.parent / "history.json"
            self.history(world)
            world.calls.clear()
            world.fake = self.Fake(world)
            world.public_old_head = world.remote.head
            yield world

    def history(self, world):
        """閉contextへ原九artifact/六入力/全terminalと、元会計のsealed証拠を結合する。"""
        out, day = world.out, world.old_day
        receipt_path = next(path for path in out.glob(day + ".collection-*.json") if
            json.loads(path.read_bytes()).get("outcome") in {"NEW_200", "REVALIDATED_304"})
        generation = world.old_receipt["generation"]
        terminals = sorted(out.glob(day + ".terminal-*.json"))
        signing = next(path for path in terminals if json.loads(path.read_bytes()).get("signingOutcome") ==
                       "NATIVE_CURRENT_VERIFIED")
        terminal = next(path for path in terminals if json.loads(path.read_bytes()).get("status") == "PUBLISHED")
        prefix = str(out / day) + ".acquisition"
        files = {"start": Path(world.old_config.get("codeRepair", {}).get("startFile", prefix + ".start.json")),
            "receipt": receipt_path, "claim": out / f"issuance-v1-{generation:016d}.claim.json",
            "rawManifest": Path(prefix + ".manifest.raw.json"), "gzip": Path(prefix + ".index.json.gz"),
            "envelope": Path(prefix + ".manifest.json"), "signingResult": signing, "terminal": terminal,
            "success": Path(prefix + ".success.json")}
        inputs = {"scope": Path(world.old_config["scopeFile"]), "evidence": receipt_path}
        inputs.update({name: out / ("acquisition-" + receipt_path.stem + "." + name + ".json") for name in
                       ("release", "inspection", "review", "script")})
        evidence, carry = self.carry_evidence(world, generation)
        world.history_record = {"schema": "dc-public-daily-history-v1", "publicConfigFile": str(world.config_path),
            "publicConfigSha256": world.config_hash, "predecessorConfigSha256": world.old_hash,
            "oldDay": day, "operationDay": world.now.strftime("%Y%m%d"),
            "files": {name: self.pin(path) for name, path in files.items()},
            "inputs": {name: self.pin(path) for name, path in inputs.items()},
            "terminalPins": {path.name: pipeline.sha(path.read_bytes()) for path in terminals},
            "retainedCarry": carry, "carryEvidence": evidence}
        self.save_history(world)

    @staticmethod
    def pin(path):
        """人工fileの原byte hashを作る。"""
        return {"file": str(path), "sha256": pipeline.sha(path.read_bytes())}

    def carry_evidence(self, world, generation):
        """元58+24+8callと外側単調時間の原receipt形を人工証拠として保持する。"""
        directory = world.config_path.parent / "original-carry"
        directory.mkdir()
        summary = {"carryCalls": 58, "carrySeconds": 829.4723543021437, "newGhCalls": 18, "newNativeCalls": 6,
            "totalManagedCalls": 82, "mainExitCode": 0, "mainActualPid": 123, "mainSameHandleTerminal": True,
            "resultStatus": "PUBLISHED", "outsideHelperGhCalls": 0, "outsideHelperNativeVerificationCalls": 0,
            "directoryBirthToMainExitSeconds": 13.707423686981201}
        summary = dict.fromkeys(("utc", "effortActuallyUsed", "mainExitCode", "mainActualPid", "mainSameHandleTerminal",
            "directoryBirthUtc", "mainExitUtc", "directoryBirthToMainExitSeconds", "resultPath", "resultStatus",
            "newGhCalls", "newNativeCalls", "totalManagedCalls", "carryCalls", "carrySeconds", "outsideHelperGhCalls",
            "outsideHelperNativeVerificationCalls", "originalIndividualPidKernelCoverage", "nativeSignCalls",
            "appAnonymousConfirmation", "pnpCandidateCount", "supportIncrease", "wholeGoalComplete",
            "rootRemoteVerification", "reads", "conservativeReadUpperBytes")) | summary
        terminal = {"pid": 123, "sameHandleTerminal": True, "exitCode": 0, "elapsedSeconds": 13.66885130002629}
        terminal = dict.fromkeys(("pid", "sameHandleTerminal", "exitCode", "originalHandleValue", "creationTicks",
            "exitTicks", "creationUtc", "exitUtc", "requestedArgv", "requestedCwd", "optionalObservation",
            "elapsedSeconds", "waitTimeouts", "stdoutRaw", "stderrRaw", "stdoutBytes", "stderrBytes", "stdoutSha256",
            "stderrSha256", "directChildObservation", "qualification")) | terminal
        review = {"stage": "G13-I7r231h14r16ev", "status": "PASS", "generation": generation,
            "checks": [{"name": "original-accounting", "pass": True}], "rootGhCalls": 8, "nativeCalls": 0,
            "carryCalls": 90, "carrySeconds": summary["carrySeconds"] + summary["directoryBirthToMainExitSeconds"] +
                3.2988645999575965, "rootGhElapsedSeconds": 3.2988645999575965}
        review = dict.fromkeys(("stage", "status", "checks", "readBytes", "privateIndexAccepted", "denominator",
            "generation", "commit", "private", "normalAppAnonymousVerified", "pnpCandidates", "supportIncrease",
            "rootGhCalls", "nativeCalls", "remoteWrites", "carryCalls", "carrySeconds", "rootGhElapsedSeconds",
            "expiresAtUtc", "utc")) | review
        paths = {name: directory / (name + ".json") for name in
                 ("summary", "terminal", "review", "index", "seal", "reviewIndex", "reviewSeal")}
        for name, value in (("summary", summary), ("terminal", terminal), ("review", review)):
            paths[name].write_bytes(pipeline.canonical(value))
        for index_name, seal_name, payloads in (("index", "seal", ("summary", "terminal")),
                                               ("reviewIndex", "reviewSeal", ("review",))):
            entries = [{"path": name + ".json", "sha256": pipeline.sha(paths[name].read_bytes()),
                        "bytes": len(paths[name].read_bytes())} for name in payloads]
            raw = pipeline.canonical({"files": entries})
            if index_name == "index":
                raw = pipeline.canonical({"files": entries, "stage": "G13-I7r231h14r16e",
                    "effortActuallyUsed": "max", "payloadCount": len(entries),
                    "payloadBytes": sum(entry["bytes"] for entry in entries), "recoveryOutcome": "PUBLISHED",
                    "rootNext": "REVIEW", "remoteReadbackPerformedOutsideHelperByChild": False})
            paths[index_name].write_bytes(raw)
            seal = {"sealedUtc": world.now.replace(microsecond=123456).isoformat(),
                "indexSha256": pipeline.sha(raw), "indexBytes": len(raw), "payloadCount": len(entries),
                "payloadBytes": sum(entry["bytes"] for entry in entries)}
            # 元snapshotと同じfractional時刻形を、fixtureの現在より前へ保つ。
            seal["sealedUtc"] = (world.now - timedelta(seconds=1)).replace(microsecond=123456).isoformat()
            if seal_name == "seal":
                seal.update(controllerExplicitReadBytes=0, returnedAuditReadBytes=0, roadmapReadBytes=0,
                    sealPayloadReadBytes=0, sourceReadConservativeUpperBytes=0,
                    sourceReadQualification="Artificial saved accounting evidence only.", operationalHelperCalls=0,
                    outsideHelperGhCalls=0, outsideHelperNativeVerificationCalls=0, wholeGoalComplete=False)
            paths[seal_name].write_bytes(pipeline.canonical(seal))
        return {name: self.pin(path) for name, path in paths.items()}, {
            "calls": review["carryCalls"], "seconds": review["carrySeconds"]}

    def save_history(self, world):
        """意図的改変caseもcontextの原pinを明示更新し、意味検証を迂回させない。"""
        world.history_path.write_bytes(pipeline.canonical(world.history_record))
        world.history_context = (world.history_path, pipeline.sha(world.history_path.read_bytes()))

    class Fake:
        """現nativeとghの呼出しだけを人工化し、実GitHub/Budget経路を通す。"""
        def __init__(self, world):
            self.world, self.calls = world, 0
            self.head_raw = pipeline.canonical(world.old_receipt)
            self.reject_head = False
            self.fail_command = None

        def remaining(self, maximum=600):
            return min(float(maximum), 1800.0)

        def run(self, argv, data=None, maximum=pipeline.MAX_FILE, seconds=600):
            self.calls += 1
            world = self.world
            if argv[1] == "api":
                method, path = argv[5], argv[6]
                binary = "Accept: application/octet-stream" in argv
                upload = path.startswith("https://uploads.github.com/")
                body = data if upload else json.loads(data) if data is not None else None
                mime = "application/gzip" if path.endswith("index.json.gz") else "application/json"
                try:
                    value = world.remote.api(method, path, body, binary=binary, content_type=mime)
                except pipeline.Missing:
                    return 1, b"", b"HTTP 404"
                return 0, value if binary else pipeline.canonical(value), b""
            if argv[1] == self.fail_command:
                world.calls.append((list(argv), seconds, maximum))
                return 2, b"", b"ARTIFICIAL_NATIVE_FAILURE"
            if argv[1] == "--verify-daily-reservation":
                raw = Path(argv[-2]).read_bytes()
                if self.reject_head or raw != self.head_raw:
                    return 2, b"HEAD_MISMATCH", b""
            result = world.run(argv, data, maximum=maximum, seconds=seconds)
            if argv[1] == "--daily-evidence":
                self.head_raw = Path(argv[-1]).read_bytes()
            return result

    def execute(self, world):
        """実loaderとrun_pipelineから明示contextを渡し、共通run_acquisitionまで進める。"""
        config, scope, digest = pipeline.load_config(world.config_path)
        return pipeline.run_pipeline(config, scope, digest, budget=world.fake, public_history=world.history_context)

    def assert_retained(self, world):
        """全旧成果物・失敗terminalをbyte/mtimeの両方で保持する。"""
        for path, expected in world.retained.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), expected, path.name)

    def test_h01_expired_history_to_fresh_200_and_304(self):
        """期限後chainを履歴に限定し、current runtimeと実共通経路へ新観測を接続する。"""
        for status in (200, 304):
            with self.subTest(status=status), self.world(status=status) as world:
                with self.assertRaisesRegex(ValueError, "^SCRIPT_PIN$"):
                    pipeline.load_config(world.old_config_path)
                old_version = world.root / "scripts" / Path(world.old_config["collectorExe"]).parent.name
                with patch.object(pipeline, "__file__", str(old_version / "daily_index_pipeline.py")), \
                    patch.object(pipeline.projection, "__file__", str(old_version / "project_collected_native_index.py")), \
                    patch.object(pipeline.cr, "__file__", str(old_version / "collector_registry.py")):
                    with self.assertRaisesRegex(ValueError, "^DAILY_OBSERVATION_TIME$"):
                        pipeline.load_config(world.old_config_path)
                result = self.execute(world)
                self.assertEqual(result["status"], "PUBLISHED")
                self.assertEqual(result["generation"], world.receipt["generation"])
                self.assertEqual(result["retainedCarry"], {"calls": 90, "seconds": 846.4786425890825})
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assertEqual(world.command_count("--daily-evidence"), 1)
                self.assertEqual(world.remote.ref_updates, 1)
                uploads = [path for method, path, _ in world.remote.events if path.startswith("https://uploads.github.com/")]
                self.assertEqual(len(uploads), 2)
                self.assertTrue(all(argv[0] not in {world.old_signer, world.old_config["collectorExe"]}
                    for argv, _, _ in world.calls))
                self.assert_retained(world)
                self.assertLess(world.fake.calls, 96)

    def test_h02_original_artifact_claim_and_signing_result_pins(self):
        """全rawと原署名/terminalを改変したcontextはchild開始前に拒否する。"""
        variants = [("inputs", name) for name in ("scope", "evidence", "release", "inspection", "review", "script")]
        variants += [("files", name) for name in ("claim", "envelope", "gzip", "signingResult", "terminal")]
        for group, name in variants:
            with self.subTest(group=group, name=name), self.world(chain=False) as world:
                path = Path(world.history_record[group][name]["file"])
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(world.fake.calls, 0)
                self.assertEqual(world.remote.events, [])

    def test_h03_historical_current_pins_profiles_and_carry(self):
        """旧codeと新codeのpinを別々に要求し、原carry会計・未知profileを閉じる。"""
        for variant in ("old-module", "current-module", "unknown-profile", "chain-proof", "carry", "carry-proof", "seal"):
            with self.subTest(variant=variant), self.world() as world:
                if variant in {"old-module", "current-module"}:
                    version = Path(world.old_config["collectorExe"]).parent.name if variant == "old-module" else Path(
                        world.config["collectorExe"]).parent.name
                    path = world.root / "scripts" / version / "daily_index_pipeline.py"
                    path.write_bytes(path.read_bytes() + b"CHANGED")
                elif variant == "unknown-profile":
                    config = deepcopy(world.config)
                    config["historicalPredecessor"]["schema"] = "UNKNOWN"
                    world.config_path.write_bytes(pipeline.canonical(config))
                elif variant == "chain-proof":
                    path = Path(world.old_config["preSignContinuation"]["budgetWitnessFile"])
                    path.write_bytes(path.read_bytes() + b"\n")
                elif variant == "carry":
                    world.history_record["retainedCarry"]["calls"] = 0
                    self.save_history(world)
                else:
                    name = "summary" if variant == "carry-proof" else "seal"
                    path = Path(world.history_record["carryEvidence"][name]["file"])
                    path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(world.fake.calls, 0)

    def test_h04_due_receipt_chain_generation_and_fresh_head(self):
        """同観測/低世代/別state/期限切れ/元fetch偽装を署名とremote writeより前に拒否する。"""
        for variant in ("before-due", "same-observation", "previous", "lower", "stale-head", "fresh-stale", "state", "expired", "304-fetch"):
            with self.subTest(variant=variant), self.world(status=304, chain=False) as world:
                if variant == "before-due":
                    world.now -= timedelta(seconds=40)
                elif variant == "same-observation":
                    world.receipt = deepcopy(world.old_receipt)
                elif variant == "previous":
                    world.receipt["previousReceiptSha256"] = "a" * 64
                elif variant == "lower":
                    world.receipt["generation"] = world.old_receipt["generation"] - 1
                elif variant == "stale-head":
                    world.fake.reject_head = True
                elif variant == "fresh-stale":
                    world.head_generation = world.old_receipt["generation"]
                elif variant == "state":
                    config = deepcopy(world.config)
                    config["stateRoot"] = str(world.root / "workspace/other-state")
                    Path(config["stateRoot"]).mkdir()
                    world.config_path.write_bytes(pipeline.canonical(config))
                elif variant == "expired":
                    world.receipt["lastSuccessfulValidationAt"] -= 86400
                else:
                    world.receipt["lastFetchedAt"] += 1
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertFalse(any(method != "GET" for method, _, _ in world.remote.events))

    def test_h05_missing_terminal_unknown_sign_and_unresolved_publication(self):
        """原結果はshapeだけで補完せず、未知の旧作用を新観測へ進めない。"""
        for variant in ("exit", "verified", "missing", "unknown", "cas"):
            with self.subTest(variant=variant), self.world(chain=False) as world:
                key = "terminal" if variant == "cas" else "signingResult"
                path = Path(world.history_record["files"][key]["file"])
                value = json.loads(path.read_bytes())
                if variant == "exit":
                    value["childExitCode"] = True
                elif variant == "verified":
                    value["nativeCurrentVerified"] = False
                elif variant == "missing":
                    value.pop("childExitCode")
                elif variant == "unknown":
                    value["signingOutcome"] = "NATIVE_OUTCOME_UNKNOWN"
                else:
                    value["status"] = "UNKNOWN"
                path.write_bytes(pipeline.canonical(value))
                world.history_record["files"][key] = self.pin(path)
                world.history_record["terminalPins"][path.name] = pipeline.sha(path.read_bytes())
                self.save_history(world)
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(world.fake.calls, 0)

    def test_h06_exact_resume_and_unknown_cas_are_readback_only(self):
        """新operationの再開は同じbudgetで原byteを読むだけで、追加署名/upload/CASしない。"""
        for variant in ("success", "cas-response"):
            with self.subTest(variant=variant), self.world(chain=False) as world:
                world.remote.failure = None if variant == "success" else variant
                if variant == "success":
                    self.execute(world)
                else:
                    original = world.fake.run
                    def lost(argv, data=None, **kwargs):
                        if argv[1] == "api" and argv[6] == "graphql":
                            world.remote.failure = None
                            world.remote.api("POST", "graphql", json.loads(data))
                            return 1, b"", b"HTTP 502"
                        return original(argv, data, **kwargs)
                    with patch.object(world.fake, "run", lost), self.assertRaises(ValueError):
                        self.execute(world)
                native_calls, calls = len(world.calls), world.fake.calls
                world.remote.failure = None
                world.remote.events.clear()
                result = self.execute(world)
                self.assertEqual(result["status"], "PUBLISHED")
                self.assertTrue(result["publicOperationReadbackOnly"])
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assertEqual(world.command_count("--daily-evidence"), 1)
                self.assertTrue(all(method == "GET" for method, _, _ in world.remote.events))
                self.assertGreater(world.fake.calls, calls)
                self.assertGreater(len(world.calls), native_calls)
                self.assert_retained(world)

    def test_h07_partial_failure_keeps_originals_and_refuses_writes(self):
        """部分公開と未知署名の原失敗を保持し、再開で追加writeを行わない。"""
        for variant in ("upload", "sign", "prepare"):
            with self.subTest(variant=variant), self.world(chain=False) as world:
                if variant == "upload":
                    world.remote.failure = "upload"
                elif variant == "sign":
                    world.sign_behavior = "timeout"
                else:
                    world.fake.fail_command = "--inspect-collected-package"
                reason = {"upload": "FAKE_UPLOAD_FAILURE", "sign": "SIGNING_OUTCOME_UNKNOWN",
                          "prepare": "FRESH_INSPECTION_FAILED"}[variant]
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    self.execute(world)
                self.assertEqual(world.remote.head, world.public_old_head)
                self.assertEqual(world.command_count("--inspect-collected-package"), 1)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0 if variant == "prepare" else 1)
                self.assertEqual(sum(method != "GET" for method, _, _ in world.remote.events), 2 if variant == "upload" else 0)
                world.remote.events.clear()
                world.remote.failure = None
                world.sign_behavior = None
                world.fake.fail_command = None
                resumed_reason = {"upload": "PUBLIC_RESUME_READBACK_ONLY", "sign": "PUBLIC_RESUME_READBACK_ONLY",
                                  "prepare": "PUBLIC_RESUME_READBACK_ONLY"}[variant]
                with self.assertRaisesRegex(ValueError, "^" + resumed_reason + "$"):
                    self.execute(world)
                self.assertTrue(all(method == "GET" for method, _, _ in world.remote.events))
                self.assertLessEqual(world.command_count("--distribution-acquisition-sign"), 1)
                self.assert_retained(world)

    def test_h08_budget_exhaustion_and_tampered_journal(self):
        """call/time上限と永続journalを作用前に確認し、旧Budget持込みresetを拒否する。"""
        for variant in ("journal", "missing-journal", "missing-summary", "new-config", "metadata-time",
                        "preused-budget", "call-limit", "time-limit"):
            with self.subTest(variant=variant), self.world(chain=False) as world:
                if variant == "preused-budget":
                    budget = pipeline.Budget()
                    budget.calls = 90
                    end = budget.end
                    with self.assertRaisesRegex(ValueError, "PUBLIC_BUDGET_NOT_FRESH"):
                        pipeline.run_pipeline(world.config, world.scope, world.config_hash, budget=budget,
                            public_history=world.history_context)
                    self.assertEqual((budget.calls, budget.end), (90, end))
                    continue
                if variant == "metadata-time":
                    original_record, original_clock = pipeline.public_history_record, pipeline.time
                    offset = [0.0]
                    def metadata(*args, **kwargs):
                        """metadata認証完了までの人工7秒を現在clockへ前進させる。"""
                        result = original_record(*args, **kwargs)
                        offset[0] += 7.0
                        return result
                    clock = SimpleNamespace(monotonic=lambda: original_clock.monotonic() + offset[0],
                        time_ns=original_clock.time_ns, sleep=original_clock.sleep)
                    with patch.object(pipeline, "public_history_record", metadata), patch.object(pipeline, "time", clock):
                        self.execute(world)
                    summary = next(world.out.glob(world.now.strftime("%Y%m%d") + ".public-budget-summary-*.json"))
                    self.assertGreaterEqual(json.loads(summary.read_bytes())["elapsedSeconds"], 7.0)
                    continue
                self.execute(world)
                prefix = world.out / world.now.strftime("%Y%m%d")
                if variant == "journal":
                    path = next(world.out.glob(prefix.name + ".public-budget-*.intent.json"))
                    path.write_bytes(path.read_bytes() + b"\n")
                elif variant in {"missing-journal", "missing-summary"}:
                    quarantine = world.out / "artificial-journal-quarantine"
                    quarantine.mkdir()
                    pattern = ".public-budget-*.json" if variant == "missing-journal" else ".public-budget-summary-*.json"
                    for path in world.out.glob(prefix.name + pattern):
                        path.rename(quarantine / path.name)
                elif variant == "new-config":
                    world.config_path.write_bytes(world.config_path.read_bytes() + b"\n")
                    world.config_hash = pipeline.sha(world.config_path.read_bytes())
                    world.history_record["publicConfigSha256"] = world.config_hash
                    self.save_history(world)
                else:
                    start = Path(str(prefix) + ".acquisition.public-start.json").read_bytes()
                    budget = pipeline.PublicOperationBudget(world.fake, prefix, pipeline.sha(start))
                    if variant == "call-limit":
                        argv = [world.config["signerExe"], "--distribution-acquisition-verify-history",
                            str(world.old_envelope), world.history_record["files"]["gzip"]["file"],
                            world.config["publicKeyFile"], world.config["fingerprint"],
                            str(int((world.now - timedelta(days=1)).timestamp()))]
                        while budget.calls < 96:
                            budget.run(argv, seconds=30)
                        budget.save()
                        before = world.fake.calls
                        with self.assertRaisesRegex(ValueError, "PROCESS_COUNT"):
                            self.execute(world)
                        self.assertEqual(world.fake.calls, before)
                    else:
                        clock = SimpleNamespace(monotonic=lambda: budget.started + 1800 - budget.spent)
                        with patch.object(pipeline, "time", clock):
                            budget.save()
                        with self.assertRaisesRegex(ValueError, "TOTAL_TIMEOUT"):
                            self.execute(world)
                    continue
                before = world.fake.calls
                reason = "RESUME_BYTES_CONFLICT" if variant == "new-config" else "PUBLIC_BUDGET_JOURNAL"
                with self.assertRaisesRegex(ValueError, reason):
                    self.execute(world)
                self.assertEqual(world.fake.calls, before)

    def test_h09_unbound_context_next_cycle_cli_and_lock(self):
        """未認証実行・同contextの翌日再利用を閉じ、Task/CLIは未開通として残す。"""
        with self.world(chain=False) as world:
            for context in (None, {}, (world.history_path, "0" * 64)):
                with self.subTest(context=type(context).__name__), self.assertRaises(ValueError):
                    pipeline.run_pipeline(world.config, world.scope, world.config_hash, budget=world.fake,
                        public_history=context)
            with self.assertRaisesRegex(ValueError, "PUBLIC_HISTORY_TRANSITION_REQUIRED"):
                pipeline.run_acquisition(world.config, world.scope, world.config_hash,
                    world.out / world.now.strftime("%Y%m%d"), world.fake, world.remote)
            self.execute(world)
            before = world.fake.calls
            world.now += timedelta(days=1)
            with self.assertRaisesRegex(ValueError, "PUBLIC_HISTORY_OPERATION_DAY"):
                self.execute(world)
            self.assertEqual(world.fake.calls, before)
            for mode in ("run", "task", "report"):
                with self.subTest(mode=mode), patch("sys.argv", ["daily_index_pipeline.py", mode, str(world.config_path)]):
                    with self.assertRaisesRegex(ValueError, "PUBLIC_HISTORY_TRANSITION_REQUIRED"):
                        pipeline.main()


class PublicDailyCycleTests(unittest.TestCase):
    """ADR0384の42固定ID。実loader/producer/取得/Publisherを隔離I/Oと有限clockで通す。"""

    @contextmanager
    def world(self, *, status=200, chain=False, now=None, seven=False):
        """固定旧v2履歴から同じv3/rootを一回だけ準備し、全managed argvを記録する。"""
        import prepare_daily_index_config as prepare
        prior = PublicHistoryTransitionTests()
        with prior.world(status=status, chain=chain,
                         initial_now=pipeline.parse_time("2026-10-15T06:00:00Z") if seven else None) as world:
            world.now = pipeline.parse_time(now or "2026-10-20T06:00:02Z")
            world.refresh(status=status, generation=world.old_receipt["generation"] + 1)
            world.receipt["previousReceiptSha256"] = pipeline.sha(pipeline.canonical(world.old_receipt))
            if status == 304:
                for name in ("lastFetchedAt", "bodySha256", "bodyBytesBase64", "projectionSha256", "projectionBytesBase64", "records"):
                    world.receipt[name] = deepcopy(world.old_receipt[name])
            world.history_record["operationDay"] = pipeline.public_jst_day(world.now)
            for name in ("seal", "reviewSeal"):
                path = Path(world.history_record["carryEvidence"][name]["file"])
                value = json.loads(path.read_bytes())
                if pipeline.datetime.fromisoformat(value["sealedUtc"].replace("Z", "+00:00")) > world.now:
                    value["sealedUtc"] = (world.now - timedelta(seconds=1)).isoformat()
                    path.write_bytes(pipeline.canonical(value))
                    world.history_record["carryEvidence"][name] = prior.pin(path)
            prior.save_history(world)
            args = SimpleNamespace(public_context_from_history=world.history_path,
                public_history_sha256=world.history_context[1], public_config=world.config_path,
                public_config_sha256=world.config_hash)
            world.context_path = prepare.prepare_public_context(args)
            world.context = (world.context_path, pipeline.sha(world.context_path.read_bytes()))
            world.trace = []
            original_run = world.fake.run
            def traced(argv, *args, **kwargs):
                """fake内部の実GH/native共通Budget callを漏れなく一度だけ数える。"""
                world.trace.append(list(argv))
                return original_run(argv, *args, **kwargs)
            world.stack.enter_context(patch.object(world.fake, "run", traced))
            yield world

    def execute(self, world):
        """通常loaderから固定原SHAを渡し、実Public coordinatorを実lockで動かす。"""
        config, scope, digest = pipeline.load_config(world.config_path)
        return pipeline.run_pipeline(config, scope, digest, budget=world.fake, public_context=world.context)

    def next_day(self, world, status=200):
        """同config/rootのまま次のnative保護headと24時間後の実観測を作る。"""
        previous = deepcopy(world.receipt)
        world.now += timedelta(days=1, seconds=2)
        world.refresh(status=status, generation=previous["generation"] + 1)
        world.receipt["previousReceiptSha256"] = pipeline.sha(pipeline.canonical(previous))
        if status == 304:
            for name in ("lastFetchedAt", "bodySha256", "bodyBytesBase64", "projectionSha256", "projectionBytesBase64", "records"):
                world.receipt[name] = deepcopy(previous[name])

    def prefix(self, world, day=None):
        """Public専用固定JST保存bucketを返す。"""
        return world.out / (day or pipeline.public_jst_day(world.now))

    def summary(self, world, day=None):
        """同操作の最終原summaryを返す。"""
        return sorted(world.out.glob(self.prefix(world, day).name + ".public-budget-summary-*.json"))[-1]

    def test_cycles_and_immutable_context(self):
        """C01/C02/C16/C19: 二Public日と追加読戻しで原byte・作用数・hash方向を確認する。"""
        for status in (200, 304):
            with self.subTest(case="C01", status=status), self.world(chain=status == 200) as world:
                originals = {path: path.read_bytes() for path in (world.config_path, world.context_path,
                    world.public_approval, world.history_path)}
                action = f'-I "{pipeline.__file__}" run-public "{world.config_path}" --public-context "{world.context_path}" --public-context-sha256 {world.context[1]}'
                for position in range(2):
                    if position:
                        self.next_day(world, status)
                    world.trace.clear()
                    before_upload = len(world.remote.assets)
                    before_cas = world.remote.ref_updates
                    before_sign = world.command_count("--distribution-acquisition-sign")
                    result = self.execute(world)
                    self.assertEqual(result["status"], "PUBLISHED")
                    self.assertEqual((len(world.remote.assets)-before_upload, world.remote.ref_updates-before_cas,
                        world.command_count("--distribution-acquisition-sign")-before_sign), (2, 1, 1))
                    native = sum(argv[1] != "api" for argv in world.trace)
                    gh = sum(argv[1] == "api" for argv in world.trace)
                    with self.subTest(case="C19", position=position, native=native, gh=gh):
                        self.assertLessEqual(native, 19)
                        self.assertLessEqual(gh, 50)
                        self.assertLessEqual(len(world.trace), 69)
                    prefix = self.prefix(world)
                    cycle_path = Path(str(prefix) + ".acquisition.public-cycle.json")
                    cycle_raw = cycle_path.read_bytes()
                    summary = json.loads(self.summary(world).read_bytes())
                    self.assertEqual(summary["completedCycleSha256"], pipeline.sha(cycle_raw))
                    self.assertNotIn("summary", json.loads(cycle_raw))
                    self.assertEqual(len(summary), 6)
                    with self.subTest(case="C16", position=position):
                        world.trace.clear()
                        uploads, cas, signs = len(world.remote.assets), world.remote.ref_updates, world.command_count("--distribution-acquisition-sign")
                        reread = self.execute(world)
                        self.assertTrue(reread["publicOperationReadbackOnly"])
                        self.assertEqual((len(world.remote.assets), world.remote.ref_updates,
                            world.command_count("--distribution-acquisition-sign")), (uploads, cas, signs))
                        self.assertEqual(cycle_path.read_bytes(), cycle_raw)
                        self.assertLessEqual(len(world.trace), 18)
                with self.subTest(case="C02"):
                    self.assertEqual({path: path.read_bytes() for path in originals}, originals)
                    self.assertEqual(action, f'-I "{pipeline.__file__}" run-public "{world.config_path}" --public-context "{world.context_path}" --public-context-sha256 {world.context[1]}')
                    PublicHistoryTransitionTests().assert_retained(world)
                with self.subTest(case="C16", variant="late-unknown-terminal"):
                    path = Path(str(self.prefix(world)) + f".terminal-{pipeline.time.time_ns()}.json")
                    path.write_bytes(pipeline.canonical({"status": "UNKNOWN", "configSha256": world.config_hash,
                        "generation": world.receipt["generation"], "publicationOutcome": "CAS_INTENT_UNKNOWN"}))
                    before = len(world.trace)
                    with self.assertRaisesRegex(ValueError, "PUBLIC_CYCLE_EXTRA_TERMINAL"):
                        self.execute(world)
                    self.assertEqual(len(world.trace), before)
                with self.subTest(case="C07", variant="public-cycle-as-bootstrap"):
                    original_history = world.history_path.read_bytes()
                    world.history_path.write_bytes(cycle_raw)
                    with self.assertRaises(ValueError):
                        pipeline.public_history_record(world.config, world.scope, world.config_hash,
                            (world.history_path, pipeline.sha(cycle_raw)))
                    world.history_path.write_bytes(original_history)

    def repin_root(self, world):
        """意図的な構造拒否試験用にcaller原SHAだけを明示し、semantic監査を残す。"""
        world.context = (world.context_path, pipeline.sha(world.context_path.read_bytes()))

    def test_closed_root_and_pins(self):
        """C04/C05/C06/C07/C22: 閉rootと全来歴pinを作用前に拒否する。"""
        with self.world() as world:
            root_raw = world.context_path.read_bytes()
            for variant in ("missing", "extra", "duplicate", "bool", "noncanonical", "oversize", "relative", "wrong-schema"):
                with self.subTest(case="C07" if variant == "wrong-schema" else "C04", variant=variant):
                    value = json.loads(root_raw)
                    if variant == "missing":
                        value.pop("dayPolicy")
                    elif variant == "extra":
                        value["counter"] = 0
                    elif variant == "bool":
                        value["publicConfigSha256"] = True
                    elif variant == "relative":
                        value["bootstrapHistoryFile"] = "history.json"
                    elif variant == "wrong-schema":
                        value["schema"] = "dc-public-daily-history-v1"
                    raw = pipeline.canonical(value)
                    if variant == "duplicate":
                        raw = b'{"schema":"duplicate",' + raw[1:]
                    elif variant == "noncanonical":
                        raw += b"\n"
                    elif variant == "oversize":
                        raw = b" " * 65537
                    world.context_path.write_bytes(raw)
                    self.repin_root(world)
                    before = world.fake.calls
                    with self.assertRaises((ValueError, OSError)):
                        self.execute(world)
                    self.assertEqual(world.fake.calls, before)
                    world.context_path.write_bytes(root_raw)
                    self.repin_root(world)
            targets = [world.context_path, world.config_path, world.public_approval, world.history_path,
                Path(world.config["collectorExe"]), Path(world.config["signerExe"])]
            targets.extend(Path(pipeline.__file__).parent / name for name in pipeline.MODULE_NAMES)
            targets.extend(Path(entry["file"]) for entry in world.history_record["inputs"].values())
            targets.extend(Path(entry["file"]) for entry in world.history_record["files"].values())
            for target in dict.fromkeys(targets):
                with self.subTest(case="C05", target=target.name):
                    raw = target.read_bytes()
                    target.write_bytes(raw + b"\n")
                    before = world.fake.calls
                    with self.assertRaises(ValueError):
                        self.execute(world)
                    self.assertEqual(world.fake.calls, before)
                    target.write_bytes(raw)
            with self.subTest(case="C06", variant="owner"):
                with patch.object(pipeline, "acl_snapshot", return_value=("S-1-5-21-999", True, [])):
                    with self.assertRaises(ValueError):
                        self.execute(world)
            with self.subTest(case="C06", variant="other-control"):
                other = world.root / "control/other"
                other.mkdir()
                path = other / "public-context.json"
                path.write_bytes(root_raw)
                with self.assertRaisesRegex(ValueError, "PUBLIC_CONTEXT_LOCATION"):
                    pipeline.public_context_record(world.config, world.scope, world.config_hash,
                        (path, pipeline.sha(root_raw)))
            with self.subTest(case="C22", variant="lock"):
                with pipeline.exclusive(world.out / "pipeline.lock"):
                    with self.assertRaisesRegex(ValueError, "PIPELINE_ALREADY_RUNNING"):
                        self.execute(world)
            with self.subTest(case="C22", variant="root-change"):
                real = pipeline.exclusive
                @contextmanager
                def changed(path):
                    with real(path):
                        world.context_path.write_bytes(root_raw + b"\n")
                        yield
                with patch.object(pipeline, "exclusive", changed):
                    with self.assertRaisesRegex(ValueError, "PUBLIC_CONTEXT_PIN"):
                        self.execute(world)

    def test_predecessor_and_fresh_rejection(self):
        """C08/C09/C10/C21: 偽署名・旧current・予約鎖・厳密鮮度を認証で止める。"""
        for case, variant in (("C08", "nonzero"), ("C08", "missing-exit"), ("C08", "native-false"),
            ("C08", "unknown"), ("C09", "remote-commit"), ("C09", "remote-bytes"), ("C09", "remote-lower"),
            ("C09", "remote-higher"), ("C09", "success-missing"), ("C09", "success-failed"),
            ("C09", "terminal-failed"), ("C09", "late-cas"), ("C10", "head"), ("C10", "same-receipt"),
            ("C10", "low-generation"), ("C10", "contract"), ("C21", "fresh-boundary"), ("C21", "schedule-end")):
            with self.subTest(case=case, variant=variant), self.world() as world:
                if case == "C08":
                    path = Path(world.history_record["files"]["signingResult"]["file"])
                    value = json.loads(path.read_bytes())
                    if variant == "nonzero":
                        value["childExitCode"] = 2
                    elif variant == "missing-exit":
                        value.pop("childExitCode")
                    elif variant == "native-false":
                        value["nativeCurrentVerified"] = False
                    else:
                        value["signingOutcome"] = "NATIVE_OUTCOME_UNKNOWN"
                    path.write_bytes(pipeline.canonical(value))
                    world.history_record["files"]["signingResult"] = PublicHistoryTransitionTests.pin(path)
                    world.history_record["terminalPins"][path.name] = pipeline.sha(path.read_bytes())
                    PublicHistoryTransitionTests().save_history(world)
                    root = json.loads(world.context_path.read_bytes())
                    root["bootstrapHistorySha256"] = world.history_context[1]
                    world.context_path.write_bytes(pipeline.canonical(root))
                    self.repin_root(world)
                elif variant == "remote-commit":
                    old = world.remote.head
                    world.remote.commits["f" * 40] = deepcopy(world.remote.commits[old])
                    world.remote.head = "f" * 40
                elif variant == "remote-bytes":
                    index = max(world.remote.assets)
                    world.remote.assets[index] += b" "
                elif variant in {"remote-lower", "remote-higher"}:
                    original = pipeline.Publisher.current
                    delta = -1 if variant == "remote-lower" else 1
                    def wrong_generation(publisher):
                        head, raw, generation = original(publisher)
                        return head, raw, generation + delta
                    world.stack.enter_context(patch.object(pipeline.Publisher, "current", wrong_generation))
                elif variant in {"success-missing", "success-failed", "terminal-failed", "late-cas"}:
                    key = "terminal" if variant == "terminal-failed" else "success"
                    path = Path(world.history_record["files"][key]["file"])
                    if variant == "success-missing":
                        path.rename(path.with_name(path.name + ".quarantine"))
                    elif variant == "late-cas":
                        path = world.out / (world.old_day + f".terminal-{pipeline.time.time_ns()}.json")
                        path.write_bytes(pipeline.canonical({"publicationOutcome": "CAS_INTENT_UNKNOWN",
                            "status": "UNKNOWN", "configSha256": world.old_hash,
                            "generation": world.old_receipt["generation"],
                            "envelopeSha256": pipeline.sha(world.old_envelope.read_bytes())}))
                        world.history_record["terminalPins"][path.name] = pipeline.sha(path.read_bytes())
                    else:
                        value = json.loads(path.read_bytes())
                        value["status"] = "FAILED"
                        path.write_bytes(pipeline.canonical(value))
                        world.history_record["files"][key] = PublicHistoryTransitionTests.pin(path)
                        if key == "terminal":
                            world.history_record["terminalPins"][path.name] = pipeline.sha(path.read_bytes())
                    if variant != "success-missing":
                        PublicHistoryTransitionTests().save_history(world)
                        root = json.loads(world.context_path.read_bytes())
                        root["bootstrapHistorySha256"] = world.history_context[1]
                        world.context_path.write_bytes(pipeline.canonical(root))
                        self.repin_root(world)
                elif variant == "head":
                    world.fake.reject_head = True
                elif variant == "same-receipt":
                    world.receipt = deepcopy(world.old_receipt)
                elif variant == "low-generation":
                    world.receipt["generation"] = world.old_receipt["generation"]
                elif variant == "contract":
                    world.receipt["contractSha256"] = "f" * 64
                elif variant == "fresh-boundary":
                    world.now = pipeline.datetime.fromtimestamp(world.receipt["notBefore"], pipeline.timezone.utc)
                    with self.assertRaises(ValueError):
                        pipeline.projection._validated_daily_generation(world.receipt, world.now)
                else:
                    world.now = pipeline.parse_time("2026-10-23T06:00:00Z")
                before = world.command_count("--distribution-acquisition-sign")
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), before)
                self.assertEqual(world.remote.ref_updates, 0)
                if case in {"C08", "C09"}:
                    self.assertEqual(world.command_count("--daily-evidence"), 0)

    def test_hold_no_network_and_partial(self):
        """C11/C12/C13/C14/C23: preflight待機と今回未通信・部分作用を分ける。"""
        for count in (2, 3):
            with self.subTest(case="C11", holds=count), self.world(now="2026-10-18T05:50:00Z") as world:
                held = deepcopy(world.receipt)
                held.update(outcome="HOLD", generation=0, httpStatus=0, lastAttemptAt=0, error=0, stateError=0,
                    notBefore=world.old_receipt["notBefore"])
                original = world.fake.run
                def hold(argv, *args, **kwargs):
                    if argv[1] == "--daily-evidence":
                        world.trace.append(list(argv))
                        pipeline.write_new(Path(argv[-1]), pipeline.canonical(held))
                        return 3, b"", b""
                    return original(argv, *args, **kwargs)
                with patch.object(world.fake, "run", hold):
                    for _ in range(count):
                        before = len(world.trace)
                        self.assertEqual(self.execute(world)["status"], "HOLD")
                        self.assertEqual(len(world.trace)-before, 13)
                start = Path(str(self.prefix(world)) + ".acquisition.public-start.json")
                raw = start.read_bytes()
                world.now = pipeline.datetime.fromtimestamp(held["notBefore"] + 32, pipeline.timezone.utc)
                world.refresh(generation=world.old_receipt["generation"] + 1)
                world.receipt["previousReceiptSha256"] = pipeline.sha(pipeline.canonical(world.old_receipt))
                if count == 2:
                    result = self.execute(world)
                    self.assertEqual(result["status"], "PUBLISHED")
                    self.assertEqual(start.read_bytes(), raw)
                    self.assertLessEqual(json.loads(self.summary(world).read_bytes())["calls"], 95)
                else:
                    before = len(world.trace)
                    with self.assertRaisesRegex(ValueError, "PUBLIC_CYCLE_BUDGET_INSUFFICIENT"):
                        self.execute(world)
                    self.assertEqual(len(world.trace), before)
        with self.subTest(case="C11", variant="second-day-due-seconds"), self.world(now="2026-10-20T06:00:33Z") as world:
            self.execute(world)
            previous = deepcopy(world.receipt)
            world.now = pipeline.parse_time("2026-10-21T06:00:00Z")
            due = previous["notBefore"]
            self.assertEqual(due - int(world.now.timestamp()), 3)
            original = world.fake.run
            waits, count = [], [0]
            def sleep(delay):
                waits.append(delay)
                world.now += timedelta(seconds=delay)
                world.refresh(generation=previous["generation"] + 1)
                observed = int(world.now.timestamp())
                world.receipt.update(lastAttemptAt=observed, lastFetchedAt=observed,
                    lastSuccessfulValidationAt=observed, notBefore=observed+86400,
                    previousReceiptSha256=pipeline.sha(pipeline.canonical(previous)))
                projected = pipeline.canonical({name: world.receipt[name] for name in
                    ("requestBindingSha256", "bodySha256", "lastFetchedAt", "records")})
                world.receipt.update(projectionSha256=pipeline.sha(projected),
                    projectionBytesBase64=base64.b64encode(projected).decode())
                world.fixture.release["observedUtcSeconds"] = str(observed)
                world.fixture.script.update(pageObservedUtcSeconds=str(observed), scriptObservedUtcSeconds=str(observed))
                world.fixture.inspection["contentCheckedUtcSeconds"] = str(observed)
            def due_native(argv, *args, **kwargs):
                if argv[1] == "--daily-evidence" and count[0] == 0:
                    count[0] += 1
                    held = deepcopy(previous)
                    held.update(day="20261021", outcome="HOLD", generation=0, httpStatus=0,
                        lastAttemptAt=0, error=0, stateError=0)
                    world.trace.append(list(argv))
                    pipeline.write_new(Path(argv[-1]), pipeline.canonical(held))
                    return 3, b"", b""
                return original(argv, *args, **kwargs)
            world.trace.clear()
            with patch.object(world.fake, "run", due_native), patch.object(pipeline.time, "sleep", sleep):
                result = self.execute(world)
            self.assertEqual((result["status"], waits), ("PUBLISHED", [4]))
            with self.subTest(case="C21", variant="next-observation-due"):
                self.assertGreaterEqual(world.receipt["lastAttemptAt"], due)
                self.assertEqual(len(world.trace), 69)
                self.assertEqual(sum(argv[1] != "api" for argv in world.trace), 19)
        with self.subTest(case="C23", variant="NOT_RUN"), self.world() as world:
            world.now += timedelta(days=1)
            with self.assertRaisesRegex(ValueError, "PUBLIC_UNRESOLVED_PREVIOUS_DAY"):
                self.execute(world)
            self.assertEqual(len(world.trace), 0)
        for variant in ("claim", "cas-intent", "pending-intent"):
            with self.subTest(case="C12", variant=variant), self.world(now="2026-10-18T05:50:00Z") as world:
                held = deepcopy(world.receipt)
                held.update(outcome="HOLD", generation=0, httpStatus=0, lastAttemptAt=0, error=0, stateError=0,
                    notBefore=world.old_receipt["notBefore"])
                original = world.fake.run
                def hold(argv, *args, **kwargs):
                    if argv[1] == "--daily-evidence":
                        world.trace.append(list(argv))
                        pipeline.write_new(Path(argv[-1]), pipeline.canonical(held))
                        return 3, b"", b""
                    return original(argv, *args, **kwargs)
                with patch.object(world.fake, "run", hold):
                    self.assertEqual(self.execute(world)["status"], "HOLD")
                prefix = self.prefix(world)
                if variant == "claim":
                    path = world.out / f"issuance-v1-{world.old_receipt['generation']+1:016d}.claim.json"
                    path.write_bytes(pipeline.canonical({"configSha256": world.config_hash,
                        "generation": world.old_receipt["generation"]+1}))
                elif variant == "cas-intent":
                    Path(str(prefix) + f".terminal-{pipeline.time.time_ns()}.json").write_bytes(pipeline.canonical({
                        "status": "UNKNOWN", "publicationOutcome": "CAS_INTENT_UNKNOWN", "configSha256": world.config_hash}))
                else:
                    def crash(*args, **kwargs):
                        raise SystemExit("ARTIFICIAL_CHILD_UNKNOWN")
                    inner = SimpleNamespace(remaining=lambda maximum=600: maximum, run=crash)
                    start = Path(str(prefix) + ".acquisition.public-start.json").read_bytes()
                    budget = pipeline.PublicOperationBudget(inner, prefix, pipeline.sha(start), cycle_profile=True)
                    with self.assertRaises(SystemExit):
                        budget.run(["fake", "bounded"], seconds=1)
                    budget.save()
                before = len(world.trace)
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(len(world.trace), before)
        for variant in ("FAILED", "state-error", "reserved", "NO_NETWORK", "DEFERRED", "saved-error", "partial", "unknown", "upload"):
            case = "C12" if variant in {"FAILED", "state-error", "reserved"} else "C13" if variant in {"NO_NETWORK", "DEFERRED", "saved-error"} else "C14"
            with self.subTest(case=case, variant=variant), self.world() as world:
                if case in {"C12", "C13"}:
                    value = deepcopy(world.receipt)
                    value.update(outcome="HOLD" if case == "C12" else "NO_NETWORK", generation=0, httpStatus=0,
                        lastAttemptAt=0, error=0, stateError=0, notBefore=int(world.now.timestamp()) + 301)
                    if variant == "state-error":
                        value["stateError"] = 5
                    elif variant == "reserved":
                        value["generation"] = world.receipt["generation"]
                    elif variant == "FAILED":
                        value.update(outcome="FAILED", generation=world.receipt["generation"], error=13,
                            lastAttemptAt=int(world.now.timestamp()), httpStatus=500)
                    elif variant == "saved-error":
                        value["error"] = 13
                    if case == "C13":
                        value = deepcopy(world.old_receipt)
                        value.update(outcome="NO_NETWORK", httpStatus=0, lastAttemptAt=0, projectionBytesBase64="")
                        if variant == "DEFERRED":
                            value.update(day=pipeline.public_jst_day(), generation=0,
                                notBefore=int(world.now.timestamp())+301)
                        elif variant == "saved-error":
                            value.update(error=13, stateError=5)
                    original = world.fake.run
                    def nonobservation(argv, *args, **kwargs):
                        if argv[1] == "--daily-evidence":
                            world.trace.append(list(argv))
                            pipeline.write_new(Path(argv[-1]), pipeline.canonical(value))
                            if variant == "FAILED":
                                world.fake.head_raw = pipeline.canonical(value)
                            return (2 if variant == "FAILED" else 3 if case == "C12" else 0), b"", b""
                        return original(argv, *args, **kwargs)
                    with patch.object(world.fake, "run", nonobservation):
                        if case == "C12":
                            with self.assertRaises(ValueError):
                                self.execute(world)
                        else:
                            self.assertEqual(self.execute(world)["status"], "NO_NETWORK")
                else:
                    if variant == "partial":
                        world.fake.fail_command = "--inspect-collected-package"
                    elif variant == "unknown":
                        world.sign_behavior = "nonzero"
                    else:
                        world.remote.failure = "upload"
                    with self.assertRaises(ValueError):
                        self.execute(world)
                calls, writes = len(world.trace), world.remote.ref_updates
                signs = world.command_count("--distribution-acquisition-sign")
                world.remote.failure = None
                with self.assertRaises(ValueError):
                    self.execute(world)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), signs)
                self.assertEqual(world.remote.ref_updates, writes)
                self.assertEqual(world.command_count("--daily-evidence"), 0 if case in {"C12", "C13"} else 1)
                with self.subTest(case="C23", variant=variant):
                    world.now += timedelta(days=1)
                    with self.assertRaises(ValueError):
                        self.execute(world)
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), signs)

    def test_exact_readback_and_carry(self):
        """C15/C17/C24: 同日/翌日の原予算readbackとreset拒否を確認する。"""
        for variant in ("same", "next", "cas-lost", "different", "expired", "missing-summary", "missing-journal",
                        "new-root", "new-config", "carry-lowered", "counter", "native-head", "outside-window"):
            case = "C17" if variant in {"missing-summary", "missing-journal", "new-root", "new-config", "carry-lowered", "counter"} else \
                "C24" if variant in {"next", "expired", "native-head", "outside-window"} else "C15"
            with self.subTest(case=case, variant=variant), self.world(now="2026-10-20T14:59:20Z") as world:
                if variant == "cas-lost":
                    original = world.fake.run
                    def lost(argv, data=None, **kwargs):
                        if argv[1] == "api" and argv[6] == "graphql":
                            world.trace.append(list(argv))
                            world.remote.api("POST", "graphql", json.loads(data))
                            return 1, b"", b"HTTP 502"
                        return original(argv, data, **kwargs)
                    with patch.object(world.fake, "run", lost), self.assertRaises(ValueError):
                        self.execute(world)
                elif variant == "expired":
                    with patch.object(pipeline, "public_complete_cycle", side_effect=ValueError("ARTIFICIAL_BEFORE_CYCLE")):
                        with self.assertRaises(ValueError):
                            self.execute(world)
                else:
                    self.execute(world)
                day = pipeline.public_jst_day(world.now)
                cycle = Path(str(self.prefix(world)) + ".acquisition.public-cycle.json")
                saved_cycle = cycle.read_bytes() if cycle.exists() else None
                if variant == "next":
                    world.now += timedelta(seconds=41)
                elif variant == "expired":
                    world.now += timedelta(days=1)
                elif variant == "different":
                    world.remote.head = world.public_old_head
                elif variant == "missing-summary":
                    quarantine = world.out / "summary-quarantine"
                    quarantine.mkdir()
                    for path in world.out.glob(day + ".public-budget-summary-*.json"):
                        path.rename(quarantine / path.name)
                elif variant == "missing-journal":
                    quarantine = world.out / "journal-quarantine"
                    quarantine.mkdir()
                    for suffix in ("intent", "complete"):
                        for path in world.out.glob(day + ".public-budget-*." + suffix + ".json"):
                            path.rename(quarantine / path.name)
                elif variant == "new-root":
                    root = json.loads(world.context_path.read_bytes())
                    root["kind"] = "DIFFERENT"
                    world.context_path.write_bytes(pipeline.canonical(root))
                    self.repin_root(world)
                elif variant == "new-config":
                    world.config_path.write_bytes(world.config_path.read_bytes() + b"\n")
                elif variant == "carry-lowered":
                    world.history_record["retainedCarry"]["calls"] = 0
                    PublicHistoryTransitionTests().save_history(world)
                    root = json.loads(world.context_path.read_bytes())
                    root["bootstrapHistorySha256"] = world.history_context[1]
                    world.context_path.write_bytes(pipeline.canonical(root))
                    self.repin_root(world)
                elif variant == "counter":
                    path = self.summary(world)
                    value = json.loads(path.read_bytes())
                    value["calls"] = 0
                    path.write_bytes(pipeline.canonical(value))
                elif variant == "native-head":
                    world.now += timedelta(seconds=41)
                    world.fake.reject_head = True
                elif variant == "outside-window":
                    world.now = pipeline.parse_time("2026-10-23T06:00:00Z")
                before = (world.command_count("--daily-evidence"), world.command_count("--distribution-acquisition-sign"),
                          len(world.remote.assets), world.remote.ref_updates)
                world.trace.clear()
                if variant in {"same", "next", "cas-lost"}:
                    result = self.execute(world)
                    self.assertTrue(result["publicOperationReadbackOnly"])
                    self.assertEqual(result["retainedCarry"], {"calls": 90, "seconds": 846.4786425890825})
                    self.assertLessEqual(len(world.trace), 18)
                else:
                    with self.assertRaises(ValueError):
                        self.execute(world)
                self.assertEqual((world.command_count("--daily-evidence"), world.command_count("--distribution-acquisition-sign"),
                    len(world.remote.assets), world.remote.ref_updates), before)
                if saved_cycle is not None:
                    self.assertEqual(cycle.read_bytes(), saved_cycle)

    def test_budget_chain_and_bounds(self):
        """C03/C18: 七日最大鎖と予算96/1800・旧完成会計のpure読取を確認する。"""
        with self.subTest(case="C03", variant="seven"), self.world(now="2026-10-16T06:00:02Z", seven=True) as world:
            for position in range(7):
                if position:
                    self.next_day(world, 304 if position % 2 else 200)
                world.trace.clear()
                self.assertEqual(self.execute(world)["status"], "PUBLISHED")
                self.assertLessEqual(sum(argv[1] != "api" for argv in world.trace), 19)
                self.assertEqual(sum(argv[1] == "api" for argv in world.trace), 50)
            root = pipeline.public_context_record(world.config, world.scope, world.config_hash, world.context)
            before = len(world.trace)
            previous, day, last = pipeline.public_cycle_target(world.config, world.config_hash, root, world.out)
            self.assertEqual(day, "20261022")
            self.assertIsNotNone(last)
            self.assertEqual(len(world.trace), before)
            for variant, name in (("eighth", "20261023"), ("future", "20991231"), ("outside-schedule", "20261015"),
                                  ("unexpected-name", "notaday")):
                path = world.out / (name + ".acquisition.public-cycle.json")
                path.write_bytes(pipeline.canonical(last["record"]))
                with self.subTest(case="C03", variant=variant), self.assertRaisesRegex(ValueError, "PUBLIC_CYCLE_CHAIN"):
                    pipeline.public_cycle_target(world.config, world.config_hash, root, world.out)
                path.rename(world.out / ("artificial-" + variant + "-rejected.json"))
            first = world.out / "20261016.acquisition.public-cycle.json"
            saved = first.read_bytes()
            value = json.loads(saved)
            value["previousEvidenceSha256"] = pipeline.sha(saved)
            first.write_bytes(pipeline.canonical(value))
            with self.subTest(case="C03", variant="cycle-branch"), self.assertRaises(ValueError):
                pipeline.public_cycle_target(world.config, world.config_hash, root, world.out)
            first.write_bytes(saved)
            with self.subTest(case="C18", variant="old-completed-1800"):
                summary = self.summary(world, "20261016")
                raw = summary.read_bytes()
                value = json.loads(raw)
                value["elapsedSeconds"] = 1800
                summary.write_bytes(pipeline.canonical(value))
                first_record = json.loads(first.read_bytes())
                ledger = pipeline.PublicOperationBudget(pipeline.Budget(), world.out / "20261016",
                    first_record["budgetContextSha256"], cycle_profile=True, read_only=True)
                self.assertEqual(ledger.spent, 1800)
                for action in (lambda: ledger.run(["fake", "forbidden"]), lambda: ledger.save()):
                    with self.assertRaisesRegex(ValueError, "PUBLIC_LEDGER_READ_ONLY"):
                        action()
                summary.write_bytes(raw)
        with self.subTest(case="C18", variant="next-day-from-near-limit"), self.world() as world:
            original, clock = pipeline.public_complete_cycle, pipeline.time
            offset = [0.0]
            def near_limit(*args, **kwargs):
                result = original(*args, **kwargs)
                budget = args[-1]
                offset[0] += 1799.0 - budget.elapsed()
                return result
            with patch.object(pipeline, "public_complete_cycle", near_limit), patch.object(pipeline, "time",
                SimpleNamespace(monotonic=lambda: clock.monotonic()+offset[0], time_ns=clock.time_ns, sleep=clock.sleep)):
                self.execute(world)
            old_summary = json.loads(self.summary(world).read_bytes())
            self.assertGreaterEqual(old_summary["elapsedSeconds"], 1799.0)
            self.assertIsNotNone(old_summary["completedCycleSha256"])
            self.next_day(world)
            self.assertEqual(self.execute(world)["status"], "PUBLISHED")
            self.assertLess(json.loads(self.summary(world).read_bytes())["elapsedSeconds"], 60)
        with self.subTest(case="C18", variant="96-and-time"), tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            called = []
            inner = SimpleNamespace(remaining=lambda maximum=600: maximum,
                run=lambda *args, **kwargs: called.append(args) or (0, b"", b""))
            budget = pipeline.PublicOperationBudget(inner, directory / "20261020", "a" * 64, cycle_profile=True)
            for _ in range(96):
                budget.run(["fake", "bounded"], seconds=1)
            with self.assertRaisesRegex(ValueError, "PROCESS_COUNT"):
                budget.run(["fake", "bounded"])
            self.assertEqual(len(called), 96)
            original = pipeline.time
            with patch.object(pipeline, "time", SimpleNamespace(monotonic=lambda: budget.started + 1800 - budget.spent)):
                with self.assertRaisesRegex(ValueError, "TOTAL_TIMEOUT"):
                    budget.remaining()
            budget.save()
        with self.subTest(case="C18", variant="metadata-time"), self.world() as world:
            original = pipeline.public_context_record
            clock = pipeline.time
            offset = [0.0]
            def metadata(*args, **kwargs):
                value = original(*args, **kwargs)
                offset[0] += 7
                return value
            with patch.object(pipeline, "public_context_record", metadata), patch.object(pipeline, "time",
                SimpleNamespace(monotonic=lambda: clock.monotonic()+offset[0], time_ns=clock.time_ns, sleep=clock.sleep)):
                self.execute(world)
            self.assertGreaterEqual(json.loads(self.summary(world).read_bytes())["elapsedSeconds"], 7)

    def test_jst_boundaries(self):
        """T01–T09: native固定JST dayとUTC epoch/due、受付後の跨日を独立に確認する。"""
        for case, instant in (("T01", "2026-10-19T15:00:00Z"), ("T02", "2026-10-19T23:59:59Z"),
            ("T03", "2026-10-20T00:00:00Z"), ("T04", "2026-10-20T06:00:00Z")):
            with self.subTest(case=case), self.world(now=instant) as world:
                self.assertEqual(world.receipt["day"], "20261020")
                if case in {"T01", "T02"}:
                    self.assertEqual(world.now.strftime("%Y%m%d"), "20261019")
                    fake = deepcopy(world.receipt)
                    fake["day"] = "20261019"
                    real = world.receipt
                    world.receipt = fake
                    with self.assertRaisesRegex(ValueError, "PUBLIC_OPERATION_DAY_CHANGED"):
                        self.execute(world)
                    # 別fixtureで正常側を確認し、失敗済み操作を新予算へ戻さない。
                    self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                    world.receipt = real
                else:
                    self.assertEqual(self.execute(world)["status"], "PUBLISHED")
        for case, instant in (("T01", "2026-10-19T15:00:00Z"), ("T02", "2026-10-19T23:59:59Z")):
            with self.subTest(case=case, variant="native-jst-positive"), self.world(now=instant) as world:
                self.assertEqual(self.execute(world)["status"], "PUBLISHED")
        for case in ("T05", "T06", "T07"):
            with self.subTest(case=case), self.world(now="2026-10-20T14:59:59Z") as world:
                original = world.fake.run
                if case == "T06":
                    world.receipt["day"] = "20261021"
                elif case == "T07":
                    world.receipt["day"] = "20261019"
                def cross(argv, *args, **kwargs):
                    result = original(argv, *args, **kwargs)
                    if (case == "T05" and argv[1] == "--verify-daily-reservation" and argv[-1] == "LEGACY_FENCE") or \
                            (case == "T06" and argv[1] == "--daily-evidence"):
                        world.now += timedelta(seconds=1)
                    return result
                with patch.object(world.fake, "run", cross), self.assertRaisesRegex(ValueError, "PUBLIC_OPERATION_DAY_CHANGED"):
                    self.execute(world)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.command_count("--daily-evidence"), 0 if case == "T05" else 1)
                self.assertTrue(self.summary(world, "20261020").exists())
                self.assertFalse(list(world.out.glob("20261021.public-budget-*.json")))
        with self.subTest(case="T08"), self.world(now="2026-10-20T23:59:59Z") as world:
            self.assertEqual(self.execute(world)["status"], "PUBLISHED")
            before = world.command_count("--daily-evidence")
            world.now += timedelta(seconds=1)
            self.assertTrue(self.execute(world)["publicOperationReadbackOnly"])
            self.assertEqual(world.command_count("--daily-evidence"), before)
            self.assertEqual(pipeline.public_jst_day(), "20261021")
        with self.subTest(case="T09"):
            for offset in ("+00:00", "+08:00"):
                with self.assertRaisesRegex(ValueError, "PUBLIC_JST_SCHEDULE_REQUIRED"):
                    pipeline.public_schedule_pin({"smokeLocal": "2026-10-15T15:00:00" + offset,
                        "firstDailyLocal": "2026-10-16T15:00:00" + offset})

    def test_save_boundaries(self):
        """F01–F08: 原途中fileを保持し、完全な最終予算だけから原byte読戻しする。"""
        for case in ("F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08"):
            with self.subTest(case=case), self.world() as world:
                original = pipeline.write_new
                injected = [False]
                def interrupted(path, raw):
                    selected = (case == "F01" and path.name.endswith(".acquisition.success.json")) or (
                        case == "F02" and ".terminal-" in path.name and json.loads(raw).get("status") == "PUBLISHED") or (
                        case in {"F03", "F05"} and path.name.endswith(".acquisition.public-cycle.json"))
                    if selected and not injected[0]:
                        injected[0] = True
                        if case == "F05":
                            original(path, b"{")
                        raise ValueError("ARTIFICIAL_SAVE_BOUNDARY")
                    return original(path, raw)
                if case in {"F01", "F02", "F03", "F05"}:
                    with patch.object(pipeline, "write_new", interrupted), self.assertRaisesRegex(ValueError, "ARTIFICIAL_SAVE_BOUNDARY"):
                        self.execute(world)
                elif case == "F04":
                    with patch.object(pipeline, "public_complete_cycle", side_effect=ValueError("ARTIFICIAL_ASSEMBLY")):
                        with self.assertRaisesRegex(ValueError, "ARTIFICIAL_ASSEMBLY"):
                            self.execute(world)
                elif case == "F06":
                    with patch.object(pipeline.PublicOperationBudget, "save", side_effect=SystemExit("ARTIFICIAL_HARD_CRASH")):
                        with self.assertRaisesRegex(SystemExit, "ARTIFICIAL_HARD_CRASH"):
                            self.execute(world)
                else:
                    self.execute(world)
                files = {path: path.read_bytes() for path in world.out.iterdir() if path.is_file()}
                signs, uploads, cas = world.command_count("--distribution-acquisition-sign"), len(world.remote.assets), world.remote.ref_updates
                if case in {"F01", "F02", "F03", "F04", "F07"}:
                    if case != "F07":
                        self.assertIsNone(json.loads(self.summary(world).read_bytes())["completedCycleSha256"])
                    self.assertTrue(self.execute(world)["publicOperationReadbackOnly"])
                elif case in {"F05", "F06"}:
                    with self.assertRaisesRegex(ValueError, "PUBLIC_CYCLE_EVIDENCE_INCOMPLETE|PUBLIC_BUDGET_JOURNAL"):
                        self.execute(world)
                else:
                    summary = self.summary(world)
                    saved = summary.read_bytes()
                    for variant in ("completed", "tail", "calls"):
                        with self.subTest(case="F08", variant=variant):
                            value = json.loads(saved)
                            value[{"completed": "completedCycleSha256", "tail": "lastEntrySha256", "calls": "calls"}[variant]] = (
                                value["calls"] - 1 if variant == "calls" else "f" * 64)
                            summary.write_bytes(pipeline.canonical(value))
                            with self.assertRaisesRegex(ValueError, "PUBLIC_BUDGET_JOURNAL"):
                                self.execute(world)
                            summary.write_bytes(saved)
                self.assertEqual((world.command_count("--distribution-acquisition-sign"), len(world.remote.assets),
                    world.remote.ref_updates), (signs, uploads, cas))
                for path, raw in files.items():
                    self.assertEqual(path.read_bytes(), raw, path.name)

    def test_cli_and_future_action(self):
        """C20/C25: 唯一の正規CLIと将来固定Actionだけを構造確認する。"""
        exact = ["run-public", "C:/fake/config.json", "--public-context", "C:/fake/public-context.json",
                 "--public-context-sha256", "a" * 64]
        args = pipeline.pipeline_arguments(exact)
        self.assertEqual(args.mode, "run-public")
        variants = [exact[:-2], exact + ["--smoke"], exact + ["--output", "C:/fake/out"],
            exact + ["--user-sid", "fake"], exact + exact[2:4], exact[:2] + ["--public-con", exact[3]] + exact[4:],
            ["run"] + exact[1:], ["plan"] + exact[1:], ["report"] + exact[1:], ["task"] + exact[1:]]
        for index, values in enumerate(variants):
            with self.subTest(case="C20", variant=index):
                with self.assertRaises((ValueError, SystemExit)):
                    pipeline.pipeline_arguments(values)
        with self.world() as world:
            with self.subTest(case="C20", variant="private-config"):
                with self.assertRaises(ValueError):
                    pipeline.run_pipeline(world.old_config, world.scope, world.old_hash, budget=world.fake,
                        public_context=world.context)
            for mode in ("run", "task", "report"):
                with self.subTest(case="C20", variant=mode), patch("sys.argv", ["pipeline", mode, str(world.config_path)]):
                    with self.assertRaisesRegex(ValueError, "PUBLIC_HISTORY_TRANSITION_REQUIRED"):
                        pipeline.main()
            with self.subTest(case="C25"):
                action = [str(Path(world.config["pythonExe"]).with_name("pythonw.exe")), "-I", pipeline.__file__] + [
                    "run-public", str(world.config_path), "--public-context", str(world.context_path),
                    "--public-context-sha256", world.context[1]]
                original = list(action)
                self.assertEqual(action[1], "-I")
                real_run, real_lock, real_write = pipeline.run_pipeline, pipeline.exclusive, pipeline.write_new
                active, writes = [False], []
                def injected(*args, **kwargs):
                    return real_run(*args, budget=world.fake, **kwargs)
                @contextmanager
                def locked(path):
                    with real_lock(path):
                        active[0] = True
                        try:
                            yield
                        finally:
                            active[0] = False
                def checked(path, raw):
                    if ".terminal-" in path.name or ".public-cycle.json" in path.name or ".public-budget-summary-" in path.name:
                        self.assertTrue(active[0], path.name)
                        writes.append(path.name)
                    return real_write(path, raw)
                output = io.StringIO()
                argv = ["pipeline", "run-public", str(world.config_path), "--public-context", str(world.context_path),
                        "--public-context-sha256", world.context[1]]
                with patch.object(pipeline, "run_pipeline", injected), patch.object(pipeline, "exclusive", locked), \
                    patch.object(pipeline, "write_new", checked), patch("sys.argv", argv), redirect_stdout(output):
                    code = pipeline.main()
                self.assertEqual((code, json.loads(output.getvalue())["status"]), (0, "PUBLISHED"))
                self.assertEqual(sum(".terminal-" in name for name in writes), 4)  # 匿名PENDING一件を追加。
                self.assertTrue(writes[-2].endswith(".public-cycle.json"))
                self.assertIn(".public-budget-summary-", writes[-1])
                self.assertEqual(action, original)
                with self.assertRaisesRegex(ValueError, "PUBLIC_HISTORY_TRANSITION_REQUIRED"):
                    pipeline.task_xml(world.config, world.config_path, "S-1-5-21-artificial")
            with self.subTest(case="C20", variant="preparer-main"):
                import prepare_daily_index_config as prepare
                root = world.context_path.read_bytes()
                world.context_path.rename(world.context_path.with_name("public-context.saved.json"))
                argv = ["prepare", "--public-context-from-history", str(world.history_path),
                    "--public-history-sha256", world.history_context[1], "--public-config", str(world.config_path),
                    "--public-config-sha256", world.config_hash]
                before = len(world.trace)
                with patch("sys.argv", argv), redirect_stdout(io.StringIO()):
                    prepare.main()
                self.assertEqual(world.context_path.read_bytes(), root)
                self.assertEqual(len(world.trace), before)
                with patch("sys.argv", argv), self.assertRaises(FileExistsError):
                    prepare.main()
                with patch("sys.argv", argv + argv[1:3]), \
                    patch.object(prepare.argparse.ArgumentParser, "parse_args", side_effect=AssertionError("PARSE_REACHED")), \
                    patch.object(prepare, "prepare_public_context", side_effect=AssertionError("IO_REACHED")), \
                    self.assertRaisesRegex(ValueError, "^PREPARE_ARGUMENT_DUPLICATE$"):
                    prepare.main()
                self.assertEqual(world.context_path.read_bytes(), root)
                self.assertEqual(len(world.trace), before)


class PublicAnonymousReadbackTests(unittest.TestCase):
    """ADR0385の固定6method/A01..A24。実作用は完全fakeと一時fileだけ。"""

    def helper(self):
        """旧9methodのfixtureを継承せずに借用し、実行分母を重複させない。"""
        return PublicDailyCycleTests()

    def assert_unknown(self, helper, world, result):
        """CAS事実と元束を保持し、未知をsuccess/cycleへ昇格させない。"""
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["reason"], "PUBLIC_ANONYMOUS_CONFIRMATION_UNKNOWN")
        self.assertEqual(result["commit"], world.remote.head)
        self.assertEqual(result["publicAnonymousReadback"]["status"], "UNKNOWN")
        prefix = helper.prefix(world)
        for suffix in (".acquisition.success.json", ".acquisition.public-cycle.json"):
            self.assertFalse(Path(str(prefix) + suffix).exists())
        self.assertTrue(Path(str(prefix) + ".acquisition.manifest.json").exists())
        self.assertIsNone(json.loads(helper.summary(world).read_bytes())["completedCycleSha256"])
        PublicHistoryTransitionTests().assert_retained(world)

    def historical_cycle(self, helper, world):
        """同loaderで認証可能な匿名annotationなしの歴史fixtureを一度だけ構成する。"""
        helper.execute(world)
        prefix = helper.prefix(world)
        cycle = Path(str(prefix) + ".acquisition.public-cycle.json")
        record = json.loads(cycle.read_bytes())
        for path in list(world.out.glob(prefix.name + ".terminal-*.json")) + [Path(record["files"]["success"]["file"])]:
            value = json.loads(path.read_bytes())
            if "publicAnonymousReadback" in value:
                value.pop("publicAnonymousReadback")
                if value.get("reason") == "PUBLIC_ANONYMOUS_CONFIRMATION_UNKNOWN":
                    value.update(status="PUBLISHED", reason="HISTORICAL_AUTHENTICATED_API_ONLY")
                path.write_bytes(pipeline.canonical(value))
        for name in ("success", "terminal"):
            path = Path(record["files"][name]["file"])
            record["files"][name] = PublicHistoryTransitionTests.pin(path)
        record["terminalPins"] = pipeline.public_terminal_pins(prefix)
        cycle.write_bytes(pipeline.canonical(record))
        summary_path = helper.summary(world)
        summary = json.loads(summary_path.read_bytes())
        summary["completedCycleSha256"] = pipeline.sha(cycle.read_bytes())
        summary_path.write_bytes(pipeline.canonical(summary))
        paths = [Path(entry["file"]) for entry in record["files"].values()] + [cycle]
        return cycle, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}

    def test_public_anonymous_success_and_binding(self):
        """A01..A04: 両公開成功経路、九send、callback必須、原JSON byte差を固定する。"""
        helper = self.helper()
        for case in ("A01", "A02", "A03", "A04"):
            with self.subTest(case=case), helper.world() as world:
                if case == "A03":
                    before = len(world.remote.events)
                    publisher = pipeline.acquisition_publisher(world.config, world.remote, lambda *a, **kw: None)
                    with self.assertRaisesRegex(ValueError, "PUBLIC_ANONYMOUS_TRANSPORT_REQUIRED"):
                        publisher.publish({"manifest.json": b"{}", "index.json.gz": b"x"})
                    self.assertEqual(len(world.remote.events), before)
                    continue
                world.anonymous_behavior = "nine" if case == "A02" else "current-whitespace" if case == "A04" else "success"
                result = helper.execute(world)
                if case == "A04":
                    self.assert_unknown(helper, world, result)
                    raw = Path(str(helper.prefix(world)) + ".acquisition.manifest.json").read_bytes()
                    self.assertEqual(json.loads(raw), json.loads(raw + b" "))
                    self.assertEqual(result["publicAnonymousReadback"]["worker"]["report"]["resources"][0]["state"], "FAILED")
                    continue
                annotation = result["publicAnonymousReadback"]
                self.assertEqual((result["status"], annotation["status"]), ("PUBLISHED", "VERIFIED"))
                self.assertEqual(list(annotation), list(pipeline.PUBLIC_ANONYMOUS_FIELDS))
                self.assertEqual((annotation["commit"], annotation["generation"]), (world.remote.head, world.receipt["generation"]))
                commands = [argv[1] for argv in world.trace]
                worker = commands.index("--public-index-readback")
                self.assertEqual(commands[worker + 1], "--distribution-acquisition-verify")
                self.assertEqual(commands.count("--public-index-readback"), 1)
                self.assertEqual((world.command_count("--distribution-acquisition-sign"), len(world.remote.assets), world.remote.ref_updates), (1, 6, 1))
                self.assertEqual(annotation["worker"]["report"]["sends"], 9 if case == "A02" else 3)
                for field in ("worker", "verifier"):
                    child = annotation[field]
                    self.assertEqual(child["childExitCode"], 0)
                    self.assertTrue(pipeline.public_sha(child["intentSha256"]))
                    self.assertTrue(pipeline.public_sha(child["completeSha256"]))
                self.assertEqual(annotation["worker"]["report"]["resources"][0]["sha256"], annotation["envelopeSha256"])
                self.assertEqual(annotation["worker"]["report"]["resources"][2]["sha256"], annotation["gzipSha256"])
                print(json.dumps({"case": case, "managed": len(world.trace), "native": sum(argv[1] != "api" for argv in world.trace),
                    "gh": sum(argv[1] == "api" for argv in world.trace), "httpSends": annotation["worker"]["report"]["sends"]}))

    def test_public_anonymous_unknown_and_readback_only(self):
        """A05..A08: CAS後の不明と部分応答を保持し、元束のreadbackだけで再開する。"""
        helper = self.helper()
        for case, behavior in (("A05", "timeout"), ("A06", "partial"), ("A07", "304"), ("A08", "success")):
            with self.subTest(case=case), helper.world() as world:
                if case == "A08":
                    original = world.fake.run
                    def lost(argv, data=None, **kwargs):
                        if argv[1] == "api" and argv[6] == "graphql":
                            world.trace.append(list(argv))
                            world.remote.api("POST", "graphql", json.loads(data))
                            return 1, b"", b"HTTP 502"
                        return original(argv, data, **kwargs)
                    with patch.object(world.fake, "run", lost), self.assertRaises(ValueError):
                        helper.execute(world)
                    before = (world.command_count("--daily-evidence"), world.command_count("--distribution-acquisition-sign"),
                        len(world.remote.assets), world.remote.ref_updates)
                    originals = {path: path.read_bytes() for path in world.out.glob(helper.prefix(world).name + ".acquisition.*")}
                    world.trace.clear()
                    result = helper.execute(world)
                    self.assertEqual(result["status"], "PUBLISHED")
                    self.assertTrue(result["publicOperationReadbackOnly"])
                    self.assertEqual((world.command_count("--daily-evidence"), world.command_count("--distribution-acquisition-sign"),
                        len(world.remote.assets), world.remote.ref_updates), before)
                    self.assertTrue(all(path.read_bytes() == raw for path, raw in originals.items()))
                    self.assertEqual(sum(argv[1] == "--public-index-readback" for argv in world.trace), 1)
                    self.assertLessEqual(len(world.trace), 18)
                    continue
                world.anonymous_behavior = behavior
                result = helper.execute(world)
                self.assert_unknown(helper, world, result)
                report = result["publicAnonymousReadback"]["worker"]["report"]
                expected = {"A05": ["FAILED", "NOT_STARTED", "NOT_STARTED"],
                    "A06": ["COMPLETE", "FAILED", "NOT_STARTED"], "A07": ["COMPLETE", "COMPLETE", "FAILED"]}[case]
                self.assertEqual([item["state"] for item in report["resources"]], expected)
                self.assertEqual(report["sends"], {"A05": 1, "A06": 2, "A07": 3}[case])
                if case == "A07":
                    self.assertEqual(report["resources"][2]["httpStatus"], 304)

    def test_public_anonymous_failure_classes(self):
        """A09..A12: 認証要求・原byte差・native署名・元期限の拒否を保持する。"""
        helper = self.helper()
        for case, behavior in (("A09", "401"), ("A10", "byte-mismatch"), ("A11", "signature"), ("A12", "timeout")):
            with self.subTest(case=case), helper.world() as world:
                world.anonymous_behavior = behavior
                result = helper.execute(world)
                self.assert_unknown(helper, world, result)
                annotation = result["publicAnonymousReadback"]
                if case == "A09":
                    self.assertEqual(annotation["worker"]["report"]["resources"][0]["httpStatus"], 401)
                    self.assertFalse(any("credential" in value.lower() or "Authorization" in value for argv in world.trace for value in argv))
                elif case == "A10":
                    self.assertEqual(annotation["failure"]["code"], "BYTE_MISMATCH")
                elif case == "A11":
                    self.assertEqual(annotation["failure"]["code"], "SIGNATURE")
                    self.assertEqual(annotation["worker"]["childExitCode"], 2)
                else:
                    path = Path(str(helper.prefix(world)) + ".acquisition.manifest.json")
                    raw = path.read_bytes()
                    manifest, _ = pipeline.unpack_envelope(raw)
                    world.now = pipeline.parse_time(manifest["expiresAtUtc"])
                    before = (world.command_count("--public-index-readback"), world.command_count("--distribution-acquisition-sign"),
                        len(world.remote.assets), world.remote.ref_updates)
                    with self.assertRaises(ValueError):
                        helper.execute(world)
                    self.assertEqual((world.command_count("--public-index-readback"), world.command_count("--distribution-acquisition-sign"),
                        len(world.remote.assets), world.remote.ref_updates), before)
                    self.assertEqual(path.read_bytes(), raw)

    def test_public_anonymous_durable_budget(self):
        """A13..A16: 管理callとHTTPを分離し、元journalと残枠の境界を検査する。"""
        helper = self.helper()
        for case in ("A13", "A14", "A15", "A16"):
            with self.subTest(case=case):
                if case == "A13":
                    with helper.world() as world:
                        reserves = []
                        original = pipeline.PublicOperationBudget.reserve_calls
                        def reserve(budget, count):
                            reserves.append(count)
                            return original(budget, count)
                        with patch.object(pipeline.PublicOperationBudget, "reserve_calls", reserve):
                            result = helper.execute(world)
                        native = sum(argv[1] != "api" for argv in world.trace)
                        gh = sum(argv[1] == "api" for argv in world.trace)
                        self.assertEqual((len(world.trace), native, gh), (68, 18, 50))
                        self.assertEqual(reserves, [69, 57, 2])
                        summary = json.loads(helper.summary(world).read_bytes())
                        self.assertEqual(summary["calls"], 68)
                        self.assertGreater(summary["elapsedSeconds"], 0)
                        self.assertEqual(result["publicAnonymousReadback"]["worker"]["report"]["sends"], 3)
                        print(json.dumps({"case": case, "managed": 68, "native": native, "gh": gh, "reserveTrace": reserves}))
                elif case == "A14":
                    with helper.world(now="2026-10-18T05:50:00Z") as world:
                        held = deepcopy(world.receipt)
                        held.update(outcome="HOLD", generation=0, httpStatus=0, lastAttemptAt=0, error=0, stateError=0,
                            notBefore=world.old_receipt["notBefore"])
                        original = world.fake.run
                        def hold(argv, *args, **kwargs):
                            if argv[1] == "--daily-evidence":
                                world.trace.append(list(argv))
                                pipeline.write_new(Path(argv[-1]), pipeline.canonical(held))
                                return 3, b"", b""
                            return original(argv, *args, **kwargs)
                        with patch.object(world.fake, "run", hold):
                            for _ in range(2):
                                before = len(world.trace)
                                self.assertEqual(helper.execute(world)["status"], "HOLD")
                                self.assertEqual(len(world.trace) - before, 13)
                        world.now = pipeline.datetime.fromtimestamp(held["notBefore"] + 32, pipeline.timezone.utc)
                        world.refresh(generation=world.old_receipt["generation"] + 1)
                        world.receipt["previousReceiptSha256"] = pipeline.sha(pipeline.canonical(world.old_receipt))
                        self.assertEqual(helper.execute(world)["status"], "PUBLISHED")
                        self.assertEqual((len(world.trace), json.loads(helper.summary(world).read_bytes())["calls"]), (94, 94))
                        print(json.dumps({"case": case, "holdCallsEach": 13, "holds": 2, "managed": 94}))
                elif case == "A15":
                    for goal in (79, 78):
                        with helper.world() as world:
                            helper.execute(world)
                            prefix = helper.prefix(world)
                            cycle = Path(str(prefix) + ".acquisition.public-cycle.json").read_bytes()
                            start = Path(str(prefix) + ".acquisition.public-start.json").read_bytes()
                            budget = pipeline.PublicOperationBudget(world.fake, prefix, pipeline.sha(start), cycle_profile=True)
                            argv = [world.config["signerExe"], "--distribution-acquisition-verify-history",
                                str(prefix) + ".acquisition.manifest.json", str(prefix) + ".acquisition.index.json.gz",
                                world.config["publicKeyFile"], world.config["fingerprint"], str(int(world.now.timestamp()))]
                            while budget.calls < goal:
                                budget.run(argv)
                            budget.save(completed_cycle=pipeline.sha(cycle))
                            before_seconds = json.loads(helper.summary(world).read_bytes())["elapsedSeconds"]
                            world.trace.clear()
                            if goal == 79:
                                with self.assertRaisesRegex(ValueError, "PUBLIC_CYCLE_BUDGET_INSUFFICIENT"):
                                    helper.execute(world)
                                self.assertEqual(world.trace, [])
                            else:
                                self.assertEqual(helper.execute(world)["status"], "PUBLISHED")
                                self.assertLessEqual(len(world.trace), 18)
                            final = json.loads(helper.summary(world).read_bytes())
                            self.assertGreaterEqual(final["calls"], goal)
                            self.assertGreaterEqual(final["elapsedSeconds"], before_seconds)
                else:
                    for behavior in ("hard-crash", "crash-exit"):
                        with helper.world() as world:
                            world.anonymous_behavior = behavior
                            result = helper.execute(world)
                            self.assert_unknown(helper, world, result)
                            worker = result["publicAnonymousReadback"]["worker"]
                            if behavior == "hard-crash":
                                self.assertIsNone(worker["completeSha256"])
                                self.assertIsNone(worker["report"])
                                self.assertIsNone(worker["childExitCode"])
                                summary = json.loads(helper.summary(world).read_bytes())
                                self.assertGreaterEqual(summary["elapsedSeconds"], 89.99)
                                with self.assertRaisesRegex(ValueError, "PUBLIC_RESUME_READBACK_ONLY"):
                                    helper.execute(world)
                            else:
                                self.assertEqual(worker["childExitCode"], 3221225477)
                                self.assertIsNotNone(worker["completeSha256"])
                                self.assertIsNone(worker["report"])
                                prefix = helper.prefix(world)
                                start = Path(str(prefix) + ".acquisition.public-start.json").read_bytes()
                                budget = pipeline.PublicOperationBudget(world.fake, prefix, pipeline.sha(start), cycle_profile=True)
                                signed = pipeline.public_child_record(budget, worker["ordinal"], world.config["collectorSha256"], -1073741819)
                                self.assertEqual(signed["childExitCode"], -1073741819)

    def test_public_anonymous_cycle_evidence(self):
        """A17..A20: 欠損成功を拒否し、旧cycleと現在の別観測を混同しない。"""
        helper = self.helper()
        for case in ("A17", "A18", "A19", "A20"):
            with self.subTest(case=case), helper.world() as world:
                if case == "A17":
                    result = helper.execute(world)
                    result.pop("publicAnonymousReadback")
                    prefix = helper.prefix(world)
                    root = pipeline.public_context_record(world.config, world.scope, world.config_hash, world.context)
                    previous, _, completed = pipeline.public_cycle_target(world.config, world.config_hash, root, world.out)
                    start = Path(str(prefix) + ".acquisition.public-start.json").read_bytes()
                    budget = pipeline.PublicOperationBudget(world.fake, prefix, pipeline.sha(start), cycle_profile=True)
                    with self.assertRaisesRegex(ValueError, "PUBLIC_ANONYMOUS_BINDING"):
                        pipeline.public_complete_cycle(world.config, world.config_hash, root, previous, prefix,
                            pipeline.public_resume_observation(prefix), result, Path(completed["record"]["files"]["terminal"]["file"]), budget)
                elif case in {"A18", "A19"}:
                    cycle, originals = self.historical_cycle(helper, world)
                    if case == "A18":
                        helper.next_day(world)
                        before = len(world.trace)
                        with self.assertRaisesRegex(ValueError, "PUBLIC_PREDECESSOR_ANONYMOUS_REQUIRED"):
                            helper.execute(world)
                        self.assertEqual(len(world.trace), before)
                    else:
                        world.trace.clear()
                        result = helper.execute(world)
                        self.assertEqual(result["publicAnonymousReadback"]["sourceCycleSha256"], pipeline.sha(originals[cycle][0]))
                        self.assertTrue(all((path.read_bytes(), path.stat().st_mtime_ns) == saved for path, saved in originals.items()))
                        self.assertEqual(sum(argv[1] == "--public-index-readback" for argv in world.trace), 1)
                        self.assertFalse(any(argv[1] in {"--daily-evidence", "--distribution-acquisition-sign"} for argv in world.trace))
                        final_summary = pipeline.sha(helper.summary(world).read_bytes())
                        helper.next_day(world)
                        helper.execute(world)
                        start = json.loads(Path(str(helper.prefix(world)) + ".acquisition.public-start.json").read_bytes())
                        self.assertEqual(start["previousBudgetSummarySha256"], final_summary)
                        self.assertGreater(len(start["previousTerminalPins"]), len(json.loads(originals[cycle][0])["terminalPins"]))
                else:
                    helper.execute(world)
                    world.anonymous_behavior = "401"
                    result = helper.execute(world)
                    self.assertEqual(result["status"], "UNKNOWN")
                    root = pipeline.public_context_record(world.config, world.scope, world.config_hash, world.context)
                    _, _, completed = pipeline.public_cycle_target(world.config, world.config_hash, root, world.out)
                    self.assertFalse(completed["anonymousVerified"])
                    helper.next_day(world)
                    before = len(world.trace)
                    with self.assertRaisesRegex(ValueError, "PUBLIC_PREDECESSOR_ANONYMOUS_REQUIRED"):
                        helper.execute(world)
                    self.assertEqual(len(world.trace), before)

    def test_public_anonymous_closed_cli_and_pins(self):
        """A21..A24: pin/元予算/五argv/親verifierを省略できない。"""
        helper = self.helper()
        for case in ("A21", "A22", "A23", "A24"):
            with self.subTest(case=case), helper.world() as world:
                if case == "A21":
                    self.assertEqual(pipeline.MODULE_NAMES, {"daily_index_pipeline.py", "project_collected_native_index.py",
                        "collector_registry.py", "prepare_daily_index_config.py"})
                    Path(world.config["collectorExe"]).write_bytes(b"ARTIFICIAL_CHANGED")
                    with self.assertRaises(ValueError):
                        helper.execute(world)
                    self.assertEqual(world.trace, [])
                elif case == "A22":
                    world.anonymous_behavior = "timeout"
                    helper.execute(world)
                    before = len(world.trace)
                    world.config_path.write_bytes(world.config_path.read_bytes() + b"\n")
                    with self.assertRaises(ValueError):
                        helper.execute(world)
                    self.assertEqual(len(world.trace), before)
                    module = Path(pipeline.__file__)
                    module.write_bytes(module.read_bytes() + b"CHANGED_RUNTIME")
                    with self.assertRaises(ValueError):
                        pipeline.load_config(world.config_path)
                    self.assertEqual(len(world.trace), before)
                elif case == "A23":
                    original = world.fake.run
                    def surplus(argv, *args, **kwargs):
                        if argv[1] == "--public-index-readback":
                            self.assertEqual(len(argv), 5)
                            self.assertEqual(argv[2:4], [str(helper.prefix(world)) + ".acquisition.manifest.json",
                                str(helper.prefix(world)) + ".acquisition.index.json.gz"])
                            return original(argv + ["https://example.invalid/extra"], *args, **kwargs)
                        return original(argv, *args, **kwargs)
                    with patch.object(world.fake, "run", surplus):
                        result = helper.execute(world)
                    self.assert_unknown(helper, world, result)
                    self.assertIsNone(result["publicAnonymousReadback"]["worker"]["report"])
                else:
                    world.anonymous_behavior = "verifier-failure"
                    result = helper.execute(world)
                    self.assert_unknown(helper, world, result)
                    value = result["publicAnonymousReadback"]
                    self.assertEqual((value["worker"]["childExitCode"], value["worker"]["report"]["outcome"]), (0, "VERIFIED"))
                    self.assertEqual(value["verifier"]["childExitCode"], 2)
                    self.assertEqual(value["failure"], {"stage": "VERIFIER", "code": "CONTENT"})


class AcquisitionVerifierFactoryTests(unittest.TestCase):
    """抽出した既存closureのnative argv・保存byte・current/history監査境界を確認する。"""

    def test_f01_current_and_history_keep_exact_bytes_argv_and_audit(self):
        """currentはnative後に六入力を監査し、historyだけ原公開秒をargvへ付加する。"""
        now = pipeline.parse_time("2026-10-18T12:00:00Z")
        raw_manifest = pipeline.canonical({"publishedAtUtc": "2026-10-18T11:00:00Z"})
        bundle = {"index.json.gz": b"ARTIFICIAL_GZIP", "manifest.json": envelope(raw_manifest)}
        prepared = {"inputs": {"artificial": b"original"}, "inputPins": {"artificial": "a" * 64}}
        config = {"signerExe": "artificial-signer", "publicKeyFile": "artificial-public",
                  "fingerprint": "b" * 64, "termsReviewMode": "PINNED_STATIC_REVALIDATION_V1"}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            candidate_hash = pipeline.sha(bundle["manifest.json"] + bundle["index.json.gz"])
            env_file = directory / ("verify-" + candidate_hash + ".manifest.json")
            gz_file = directory / ("verify-" + candidate_hash + ".index.json.gz")
            budget = DiagnosticBudget([(0, b"ignored", b""), (0, b"ignored", b"")])
            verify = pipeline.acquisition_verifier(config, prepared, directory, budget,
                                                  generation=5, publication=now)
            with patch.object(pipeline, "acquisition_profile", return_value="distribution-acquisition"), \
                    patch.object(pipeline, "utc", return_value=now), \
                    patch.object(pipeline, "audit_daily_distribution_acquisition_bundle") as audit:
                verify(bundle, historical=False)
                audit.assert_called_once_with(bundle, prepared["inputs"], prepared["inputPins"],
                    generation=5, published_at=now, now=now, terms_review_mode=config["termsReviewMode"])
                verify(bundle, historical=True)
                self.assertEqual(audit.call_count, 1)
            self.assertEqual(env_file.read_bytes(), bundle["manifest.json"])
            self.assertEqual(gz_file.read_bytes(), bundle["index.json.gz"])
            argv = [config["signerExe"], "--distribution-acquisition-verify", str(env_file), str(gz_file),
                    config["publicKeyFile"], config["fingerprint"]]
            self.assertEqual(budget.calls[0], (argv, None, pipeline.MAX_FILE, 600))
            self.assertEqual(budget.calls[1], ([argv[0], "--distribution-acquisition-verify-history", *argv[2:],
                             str(int(pipeline.parse_time("2026-10-18T11:00:00Z").timestamp()))],
                             None, pipeline.MAX_FILE, 600))

    def test_f02_profile_and_native_failure_keep_audit_closed(self):
        """currentの旧profileとnative非0は監査成功へ進めず、既存reasonを維持する。"""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = {"signerExe": "artificial-signer", "publicKeyFile": "artificial-public",
                      "fingerprint": "b" * 64, "termsReviewMode": "PINNED_STATIC_REVALIDATION_V1"}
            bundle = {"index.json.gz": b"artificial", "manifest.json": b"artificial"}
            budget = DiagnosticBudget([(2, b"", b"")])
            verify = pipeline.acquisition_verifier(config, {}, directory, budget,
                generation=5, publication=pipeline.parse_time("2026-10-18T12:00:00Z"))
            with patch.object(pipeline, "acquisition_profile", return_value="distribution"), \
                    patch.object(pipeline, "audit_daily_distribution_acquisition_bundle") as audit:
                with self.assertRaisesRegex(ValueError, "^SIGNING_PROFILE_UNKNOWN$"):
                    verify(bundle, historical=False)
                self.assertFalse(budget.calls)
                self.assertFalse(list(directory.iterdir()))
                audit.assert_not_called()
            with patch.object(pipeline, "acquisition_profile", return_value="distribution-acquisition"), \
                    patch.object(pipeline, "audit_daily_distribution_acquisition_bundle") as audit:
                with self.assertRaisesRegex(ValueError, "^NATIVE_DISTRIBUTION_VERIFY_FAILED$"):
                    verify(bundle, historical=False)
                audit.assert_not_called()


class LegacyMetadataFloorPreparationTests(unittest.TestCase):
    """旧record非再生成と、原byte/世代/必須native認証を人工scope準備で確認する。"""

    world = DailyAcquisitionIssuanceTests.world

    def test_old_record_bytes_prepare_without_current_projection(self):
        """現必須fieldを持たない旧recordを変更せず、準備と履歴floorへ渡せる。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            index = json.loads(gzip.decompress(world.args.legacy_gzip.read_bytes()))
            wrapper = index["records"][0]
            record = json.loads(base64.b64decode(wrapper["recordBytesBase64"], validate=True))
            self.assertEqual(record["publishedIdentityEvidence"].pop("nestedArchiveIdentity"), "")
            record_raw = pipeline.canonical(record)
            wrapper.update(recordBytesBase64=base64.b64encode(record_raw).decode(),
                           recordSha256=pipeline.sha(record_raw))
            packed = gzip.compress(pipeline.canonical(index), mtime=0)
            manifest = json.loads(world.args.legacy_raw_manifest.read_bytes())
            manifest["asset"].update(sha256=pipeline.sha(packed), sizeBytes=len(packed),
                tag="index-v1-20261015-" + pipeline.sha(packed))
            raw = pipeline.canonical(manifest)
            world.args.legacy_gzip.write_bytes(packed)
            world.args.legacy_raw_manifest.write_bytes(raw)
            world.args.legacy_envelope.write_bytes(envelope(raw, manifest["keyId"]))
            paths = [world.args.inherit_config, world.args.legacy_receipt, world.args.legacy_raw_manifest,
                     world.args.legacy_gzip, world.args.legacy_envelope]
            originals = {path: path.read_bytes() for path in paths}
            args = SimpleNamespace(**dict(vars(world.args), control_directory=world.root / "control/old-record"))
            with patch.object(pipeline.projection, "project_daily",
                    side_effect=AssertionError("LEGACY_REPROJECTION_FORBIDDEN")):
                path = prepare.inherit_config(args, budget=world)
                config, _, _ = pipeline.load_config(path)
                self.assertEqual(world.command_count("--distribution-verify-floor-history"), 1)
                self.assertEqual(world.command_count("--distribution-verify-history"), 0)
                bundle = {"manifest.json": originals[world.args.legacy_envelope], "index.json.gz": packed}
                verify = pipeline.acquisition_verifier(config, {}, world.out, world,
                    generation=9, publication=world.now)
                verify(bundle, historical=True)
                with self.assertRaisesRegex(ValueError, "^SIGNING_PROFILE_UNKNOWN$"):
                    verify(bundle, historical=False)
            self.assertEqual(world.command_count("--distribution-verify-floor-history"), 2)
            self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
            for command in (world.preparation_calls[1][0], world.calls[1][0], world.calls[2][0]):
                self.assertEqual(command[-1], str(int(pipeline.parse_time(manifest["publishedAtUtc"]).timestamp())))
                self.assertEqual(command[4:6], [config["publicKeyFile"], config["fingerprint"]])
            self.assertEqual({path: path.read_bytes() for path in paths}, originals)
            self.assertEqual(world.remote.events, [])

    def test_structure_checks_do_not_replace_native_authentication(self):
        """純粋loaderはnativeを起動せず、準備は原fenceと署名floorの順序を必須にする。"""
        with self.world() as world:
            with patch.object(pipeline.projection, "project_daily",
                    side_effect=AssertionError("LEGACY_REPROJECTION_FORBIDDEN")):
                pipeline.validate_legacy_metadata(world.config)
                pipeline.load_config(world.config_path)
            self.assertEqual(world.calls, [])
            self.assertEqual([row[0][1] for row in world.preparation_calls],
                ["--verify-daily-reservation", "--distribution-verify-floor-history"])
            self.assertEqual(world.preparation_calls[0][0][-1], "LEGACY_FENCE")
            self.assertEqual(world.preparation_calls[1][0][2:6],
                [str(world.args.legacy_envelope), str(world.args.legacy_gzip),
                 world.config["publicKeyFile"], world.config["fingerprint"]])

    def test_original_bytes_and_rebound_manifest_claims_are_refused(self):
        """各原hashの改変と、hashを再申告した異key/世代/原asset/receiptの矛盾を拒否する。"""
        for variant in ("receipt", "rawManifest", "gzip", "envelope", "key", "generation",
                        "asset-generation", "asset-hash", "asset-size", "receipt-manifest", "future"):
            with self.subTest(variant=variant), self.world() as world:
                config = deepcopy(world.config)
                binding = config["legacyMetadata"]
                if variant in {"receipt", "rawManifest", "gzip", "envelope"}:
                    path = Path(binding[variant + "File"])
                    path.write_bytes(path.read_bytes() + b" ")
                elif variant == "receipt-manifest":
                    path = Path(binding["receiptFile"])
                    receipt = json.loads(path.read_bytes())
                    receipt["manifestSha256"] = "0" * 64
                    path.write_bytes(pipeline.canonical(receipt))
                    binding["receiptSha256"] = pipeline.sha(path.read_bytes())
                else:
                    manifest = json.loads(world.args.legacy_raw_manifest.read_bytes())
                    if variant == "key":
                        manifest["keyId"] = "distribution-index-" + "0" * 32
                    elif variant in {"generation", "asset-generation"}:
                        manifest["generation" if variant == "generation" else "assetGeneration"] += 1
                    elif variant == "asset-hash":
                        manifest["asset"]["sha256"] = "0" * 64
                    elif variant == "asset-size":
                        manifest["asset"]["sizeBytes"] += 1
                    else:
                        manifest["publishedAtUtc"] = (world.now + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                    raw = pipeline.canonical(manifest)
                    world.args.legacy_raw_manifest.write_bytes(raw)
                    world.args.legacy_envelope.write_bytes(envelope(raw, manifest["keyId"]))
                    binding.update(rawManifestSha256=pipeline.sha(raw),
                        envelopeSha256=pipeline.sha(world.args.legacy_envelope.read_bytes()))
                with self.assertRaisesRegex(ValueError, "^LEGACY_METADATA_BINDING$"):
                    pipeline.validate_legacy_metadata(config)
                self.assertEqual(world.calls, [])
                self.assertEqual(world.remote.events, [])

    def test_native_fence_and_floor_failure_or_unknown_cannot_save_control(self):
        """現native head拒否と署名floor非0/不明では新scope/configを作らずfallbackしない。"""
        import prepare_daily_index_config as prepare
        for variant in ("head", "floor-rejected", "floor-unknown"):
            with self.subTest(variant=variant), self.world() as world:
                args = SimpleNamespace(**dict(vars(world.args), control_directory=world.root / "control/refused"))
                run = world.run
                def refuse(argv, **kwargs):
                    """該当する一回のnative結果だけを不成功にし、実processは呼ばない。"""
                    if ((variant == "head" and argv[1] == "--verify-daily-reservation") or
                            (variant != "head" and argv[1] == "--distribution-verify-floor-history")):
                        world.calls.append((list(argv), kwargs.get("seconds", 600), kwargs.get("maximum", pipeline.MAX_FILE)))
                        return None if variant == "floor-unknown" else 2, b"", b"ARTIFICIAL_REFUSAL"
                    return run(argv, **kwargs)
                reason = "DAILY_RESERVATION_HEAD" if variant == "head" else "LEGACY_METADATA_HISTORY_FAILED"
                with patch.object(world, "run", side_effect=refuse), \
                        self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    prepare.inherit_config(args, budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.command_count("--distribution-verify-history"), 0)
                self.assertEqual(world.command_count("--distribution-acquisition-sign"), 0)
                self.assertEqual(world.remote.events, [])


class FreshNativePreparationTests(unittest.TestCase):
    """新本体を既存六入力へ渡す明示入口。実network/鍵/署名/公開は持たない。"""

    @contextmanager
    def world(self, case="success"):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            originals = {name: (name + " original").encode() for name in ("release", "review", "script")}
            pins = {name: pipeline.sha(raw) for name, raw in originals.items()}
            config = {"schema": "dc-private-daily-index-config-v2", "purpose": pipeline.ACQUISITION_PURPOSE,
                "outputRoot": str(root), "stateRoot": "same-original-state", "selectedInf": "logical.inf",
                "termsReviewMode": pipeline.projection.PINNED_STATIC_REVALIDATION_V1}
            for name, pin in (("collectorExe", "collectorSha256"), ("signerExe", "signerSha256"),
                              ("manifestFile", "manifestSha256"), ("scopeFile", "scopeSha256")):
                path = root / name
                scope = {"schema": "dc-fixed-distribution-acquisition-scope-v1", "targetCount": 1,
                    "source": pipeline.projection.SOURCE, "distributionPage": pipeline.projection.PAGE,
                    "sourceId": "intel-ethernet-win11", "recordId": "intel-wired-31-2-2-win11",
                    "collectorManifestSha256": pipeline.sha(b"fixture"),
                    "keyId": pipeline.projection.DISTRIBUTION_KEY_ID,
                    "publicFingerprint": pipeline.projection.DISTRIBUTION_PUBLIC_FINGERPRINT,
                    "projectionPolicyRevision": pipeline.projection.DISTRIBUTION_PROJECTION_POLICY_REVISION}
                path.write_bytes(pipeline.canonical(scope) if name == "scopeFile" else b"fixture")
                config[name], config[pin] = str(path), pipeline.sha(path.read_bytes())
            now = pipeline.parse_time("2026-10-25T03:00:00Z")
            receipt = root / "fresh-01.json"
            archive = receipt.with_suffix(".payload.zip")
            old_archive = root / "old.zip"
            old_archive.write_bytes(b"original preserved archive")
            calls = []
            prepared = {"inputs": {name: b"{}" for name in ("scope", "evidence", "release", "inspection", "review", "script")},
                "inputPins": {name: "a" * 64 for name in ("scope", "evidence", "release", "inspection", "review", "script")},
                "reservation": {"generation": 9, "mode": "FRESH_INPUT", "receiptSha256": "b" * 64}}

            class FakeBudget:
                def remaining(self, maximum):
                    return maximum

                def run(self, argv, **kwargs):
                    calls.append(argv)
                    if case == "hold":
                        receipt.write_bytes(pipeline.canonical({"outcome": "HOLD"}))
                        return 3, b"", b""
                    if case in {"failed", "failed-save"}:
                        receipt.write_bytes(pipeline.canonical({"outcome": "FAILED"}))
                        if case == "failed":
                            receipt.with_suffix(".failed-page.json").write_bytes(b"private failed body diagnostic")
                        return 1, b"COLLECTOR_PAYLOAD save_error=0 held=0 not_before=86400 stage=4 acquired=0 installed=0\n", (
                            b"COLLECTOR_FAILED_PAGE save_error=5 captured=0\n" if case == "failed-save" else b"")
                    receipt.write_bytes(pipeline.canonical({"outcome": "REVALIDATED_304" if case == "304" else "NEW_200"}))
                    archive.write_bytes(b"new archive")
                    return 0, ((b"COLLECTOR_FAILED_PAGE save_error=0 captured=1\n" if case == "extra-stdout" else b"") +
                        b"COLLECTOR_PAYLOAD save_error=0 held=0 not_before=0 stage=" +
                        (b"7" if case == "failed-stage" else b"0") + b" acquired=" +
                        (b"0" if case == "no-acquired" else b"1") + b" installed=0\n"), b""

            for name in ("protected_tree", "protected_path", "require_config_workspace", "validate_v2_code", "require_native_receipt"):
                stack.enter_context(patch.object(pipeline, name))
            stack.enter_context(patch.object(pipeline, "operation_root", side_effect=lambda path, **kw: path))
            stack.enter_context(patch.object(pipeline, "normal_path", side_effect=lambda path, **kw: Path(path)))
            stack.enter_context(patch.object(pipeline, "exclusive", side_effect=lambda path: ExitStack()))
            stack.enter_context(patch.object(pipeline, "utc", return_value=now))
            stack.enter_context(patch.object(pipeline, "acquisition_originals", return_value=(originals, pins)))
            prepare = stack.enter_context(patch.object(pipeline, "prepare_daily_acquisition_inputs", return_value=prepared))
            action = lambda **kw: pipeline.prepare_fresh_daily_acquisition_inputs(config, receipt,
                budget=FakeBudget(), **{"maximum_bytes": 40477087, "consent_not_after": int(now.timestamp()) + 3600,
                    "accept_pinned_terms": True, **kw})
            yield SimpleNamespace(root=root, config=config, originals=originals, pins=pins, now=now,
                receipt=receipt, archive=archive, calls=calls, prepare=prepare, action=action, old_archive=old_archive)
            self.assertEqual(old_archive.read_bytes(), b"original preserved archive")
            self.assertFalse(any("sign" in argv[1] or "publish" in argv[1] for argv in calls))

    def test_new_archive_only_to_existing_six_inputs(self):
        with self.world() as world:
            result = world.action()
            self.assertEqual(result["status"], "PREPARED_UNSIGNED")
            self.assertFalse(result["signed"] or result["published"])
            self.assertEqual(world.calls[0][1], "--daily-acquire")
            self.assertEqual(world.calls[0][3], "same-original-state")
            self.assertEqual(world.calls[0][6], world.pins["release"])
            self.assertEqual(world.calls[0][-1], "--accept-pinned-terms")
            self.assertEqual(world.prepare.call_args.args[5], world.archive)
            self.assertNotEqual(world.prepare.call_args.args[5], world.old_archive)
            self.assertEqual(world.prepare.call_args.args[3:5], (world.originals, world.pins))
            bundle = json.loads(Path(result["nativeInputsFile"]).read_bytes())
            self.assertEqual(bundle["schema"], "dc-candidate-native-inputs-v1")
            self.assertEqual(set(bundle["inputs"]), {"scope", "evidence", "release", "inspection", "review", "script"})

    def test_missing_or_expired_consent_precedes_effects(self):
        for change in ({"accept_pinned_terms": False}, {"consent_not_after": 0}, {"maximum_bytes": 0},
                       {"maximum_bytes": 134217729}, {"consent_not_after": 9999999999}):
            with self.subTest(change=change), self.world() as world:
                with self.assertRaisesRegex(ValueError, "^FRESH_NATIVE_CONSENT$"):
                    world.action(**change)
                self.assertFalse(world.calls)
                world.prepare.assert_not_called()

    def test_hold_preserved_without_wait_or_retry(self):
        with self.world("hold") as world:
            self.assertEqual(world.action()["status"], "HOLD")
            self.assertEqual(len(world.calls), 1)
            self.assertFalse(world.archive.exists())
            world.prepare.assert_not_called()

    def test_failed_receipt_preserved_without_old_archive_fallback(self):
        with self.world("failed") as world:
            with self.assertRaisesRegex(ValueError, "^FRESH_NATIVE_PAYLOAD_FAILED$"):
                world.action()
            self.assertEqual(json.loads(world.receipt.read_bytes())["outcome"], "FAILED")
            self.assertEqual(world.receipt.with_suffix(".failed-page.json").read_bytes(),
                b"private failed body diagnostic")
            self.assertFalse(world.receipt.with_suffix(".native-inputs.json").exists())
            self.assertEqual(len(world.calls), 1)
            world.prepare.assert_not_called()

    def test_304_and_missing_acquisition_are_refused(self):
        for case in ("304", "no-acquired", "failed-stage", "extra-stdout"):
            with self.subTest(case=case), self.world(case) as world:
                with self.assertRaisesRegex(ValueError, "^FRESH_NATIVE_PAYLOAD_FAILED$"):
                    world.action()
                self.assertTrue(world.archive.exists())
                world.prepare.assert_not_called()

    def test_diagnostic_save_failure_does_not_hide_native_failure(self):
        with self.world("failed-save") as world:
            with self.assertRaisesRegex(ValueError, "^FRESH_NATIVE_PAYLOAD_FAILED$"):
                world.action()
            self.assertEqual(json.loads(world.receipt.read_bytes())["outcome"], "FAILED")
            self.assertFalse(world.receipt.with_suffix(".failed-page.json").exists())
            self.assertFalse(world.receipt.with_suffix(".native-inputs.json").exists())
            self.assertEqual(len(world.calls), 1)
            world.prepare.assert_not_called()

    def test_prior_archive_or_partial_is_not_reused(self):
        for suffix in (".payload.zip", ".payload.partial.zip", ".failed-page.json"):
            with self.subTest(suffix=suffix), self.world() as world:
                path = world.receipt.with_suffix(suffix)
                path.write_bytes(b"original")
                with self.assertRaisesRegex(ValueError, "^FRESH_NATIVE_OUTPUT_EXISTS$"):
                    world.action()
                self.assertEqual(path.read_bytes(), b"original")
                self.assertFalse(world.calls)

    def test_content_or_terms_failure_keeps_fresh_evidence(self):
        with self.world() as world:
            world.prepare.side_effect = ValueError("FRESH_INSPECTION_FAILED")
            with self.assertRaisesRegex(ValueError, "^FRESH_INSPECTION_FAILED$"):
                world.action()
            self.assertTrue(world.receipt.exists() and world.archive.exists())
            self.assertFalse(world.receipt.with_suffix(".native-inputs.json").exists())
            self.assertEqual(len(world.calls), 1)

    def test_cli_requires_explicit_complete_consent(self):
        args = ["prepare-fresh-native", "config.json", "--fresh-receipt", "fresh.json",
            "--maximum-payload-bytes", "40477087", "--terms-consent-not-after", "1792893600",
            "--accept-pinned-terms"]
        self.assertEqual(pipeline.pipeline_arguments(args).mode, "prepare-fresh-native")
        for argv in (args[:-1], ["run", *args[1:]], [*args, "--smoke"], [*args, "--fingerprint", "a" * 64]):
            with self.subTest(argv=argv), self.assertRaisesRegex(ValueError, "^FRESH_NATIVE_CLI_ARGUMENTS$"):
                pipeline.pipeline_arguments(argv)


class MetadataScopePreparationTests(unittest.TestCase):
    """正規inheritの明示v2入力を人工保護rootへ発行し、実操作へfallbackしない。"""

    world = DailyAcquisitionIssuanceTests.world

    def arguments(self, world, *, technical=False):
        """原manualと新版期待値を別fileへ固定し、正規CLIと同じ完全対を用意する。"""
        import prepare_daily_index_config as prepare
        expected = deepcopy(world.fixture.release)
        expected.update(packageVersion="99.7.4", fileName="Wired_driver_99.7.4_x64.zip",
            payloadUrl="https://downloadmirror.intel.com/999999/Wired_driver_99.7.4_x64.zip")
        expected_raw = pipeline.canonical(expected)
        scope = dict(world.scope, schema=pipeline.projection.METADATA_BOUND_SCOPE, recordId="artificial-new-99-7-4",
            acquisitionBinding={"expectedRelease": {"bytesBase64": base64.b64encode(expected_raw).decode(),
                "sha256": pipeline.sha(expected_raw)}, "selectedInf": "NEW/W11/fixture.inf",
                "modelSection": "Fixture.NTamd64.10.0.1..22000", "maximumBytes": 128*1024*1024})
        source = world.root / "control/declared-scope.json"
        source.write_text(json.dumps(scope, indent=2)+"\n", encoding="utf-8")
        body = world.root / "control/original.body"
        body.write_bytes(world.fixture.body)
        values = dict(vars(world.args), acquisition_scope=source, acquisition_scope_sha256=pipeline.sha(source.read_bytes()),
            original_body=body, selected_inf=None, control_directory=world.root / "control/metadata-new")
        for name in ("release", "body", "review", "script"):
            values["original_"+name+"_sha256"] = pipeline.sha(Path(values["original_"+name]).read_bytes())
        if technical:
            script = json.loads(world.args.original_script.read_bytes())
            raw_script = base64.b64decode(script["scriptBytesBase64"])+b"/* artificial reviewed revision */"
            script.update(scriptBytesBase64=base64.b64encode(raw_script).decode(), scriptSha256=pipeline.sha(raw_script),
                scriptSizeBytes=len(raw_script))
            review = json.loads(world.args.original_review.read_bytes())
            review["scriptSha256"] = script["scriptSha256"]
            for name, raw in (("release", world.args.original_release.read_bytes()), ("body", body.read_bytes()),
                              ("review", pipeline.canonical(review)), ("script", pipeline.canonical(script))):
                path = world.root / ("control/binding."+name)
                path.write_bytes(raw)
                values["binding_"+name] = path
                values["binding_"+name+"_sha256"] = pipeline.sha(raw)
        args = SimpleNamespace(**values)
        self.assertEqual(prepare.preparation_arguments(["--inherit-config", str(args.inherit_config),
            "--acquisition-scope", str(source), "--acquisition-scope-sha256", args.acquisition_scope_sha256]).selected_inf, None)
        return args

    def test_regular_issue_readback_keeps_raw_scope_originals_and_legacy(self):
        """別版/別selectorを正規発行し、原byte/時刻/旧archiveと全floor入力を保持する。"""
        import prepare_daily_index_config as prepare
        for technical in (False, True):
            with self.subTest(technical=technical), self.world() as world:
                args = self.arguments(world, technical=technical)
                before = {path: path.read_bytes() for path in
                    (world.args.inherit_config, world.args.legacy_receipt, world.args.legacy_raw_manifest,
                     world.args.legacy_gzip, world.args.legacy_envelope, args.acquisition_scope,
                     args.original_body, args.original_release, args.original_review, args.original_script)}
                config_path = prepare.inherit_config(args, budget=world)
                config, scope, _ = pipeline.load_config(config_path)
                self.assertEqual(config["termsReviewMode"], pipeline.projection.PINNED_STATIC_REVALIDATION_V2)
                self.assertEqual(Path(config["scopeFile"]).read_bytes(), before[args.acquisition_scope])
                self.assertEqual(config["scopeSha256"], args.acquisition_scope_sha256)
                self.assertEqual(config["selectedInf"], "NEW/W11/fixture.inf")
                for name in ("repositoryRoot", "stateRoot", "outputRoot", "smokeLocal", "firstDailyLocal", "legacyMetadata",
                             "legacyReservationFence", "archiveFile", "archiveSha256", "archiveBytes", "publicKeyFile", "fingerprint"):
                    self.assertEqual(config[name], world.config[name])
                originals, pins = pipeline.acquisition_originals(config)
                self.assertEqual(set(originals), {"release", "body", "review", "script"} |
                    (pipeline.projection.TECHNICAL_REVIEW_INPUTS if technical else set()))
                self.assertEqual(pins, {name: pipeline.sha(raw) for name, raw in originals.items()})
                self.assertEqual(json.loads(originals["review"])["checkedAtUtcSeconds"],
                    json.loads(before[args.original_review])["checkedAtUtcSeconds"])
                self.assertEqual([argv[1] for argv, _, _ in world.calls],
                    ["--verify-daily-reservation", "--distribution-verify-floor-history"])
                self.assertEqual(world.calls[0][0][-1], "LEGACY_FENCE")
                self.assertEqual({path: path.read_bytes() for path in before}, before)
                self.assertEqual(world.remote.events, [])
                if technical:
                    self.assertNotEqual(json.loads(originals["bindingScript"])["scriptSha256"],
                                        json.loads(originals["script"])["scriptSha256"])

    def test_manual_and_technical_pairs_are_complete_before_native(self):
        """全roleのfile/hash欠損と技術組の一部指定を黙って省かない。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.arguments(world, technical=True)
            for prefix in ("original", "binding"):
                for role in ("release", "body", "review", "script"):
                    for suffix in ("", "_sha256"):
                        name = prefix+"_"+role+suffix
                        changed = SimpleNamespace(**dict(vars(args), **{name: None}))
                        with self.subTest(missing=name), self.assertRaises(ValueError):
                            prepare.inherit_config(changed, budget=world)
                        self.assertFalse(changed.control_directory.exists())
                        self.assertEqual(world.calls, [])

    def test_scope_pin_hashes_root_and_capacity_fail_before_native(self):
        """scope改変、原pin不正、想定外rootと64KiB超過を新control作成前に拒否する。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.arguments(world)
            outside = world.root.parent / "outside.body"
            outside.write_bytes(args.original_body.read_bytes())
            for values in ({"acquisition_scope_sha256": "0"*64}, {"acquisition_scope_sha256": "bad"},
                           {"acquisition_scope": None}, {"original_body": outside},
                           {"original_review_sha256": "0"*64}, {"original_script_sha256": True}):
                with self.subTest(values=tuple(values)), self.assertRaises(ValueError):
                    prepare.inherit_config(SimpleNamespace(**dict(vars(args), **values)), budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.calls, [])
            raw = args.acquisition_scope.read_bytes()
            args.acquisition_scope.write_bytes(raw+b" "*(65537-len(raw)))
            args.acquisition_scope_sha256 = pipeline.sha(args.acquisition_scope.read_bytes())
            with self.assertRaisesRegex(ValueError, "FILE_SIZE"):
                prepare.inherit_config(args, budget=world)
            self.assertFalse(args.control_directory.exists())

    def test_scope_unknown_fields_and_mismatched_bindings_fail(self):
        """明示schema/公開pin/manifest/selector/最大値を同じ共通validatorへ通す。"""
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.arguments(world)
            scope = json.loads(args.acquisition_scope.read_bytes())
            variants = []
            for field, value in (("unexpected", True), ("collectorManifestSha256", "0"*64),
                                 ("publicFingerprint", "0"*64), ("schema", "dc-fixed-distribution-acquisition-scope-v1")):
                variants.append(dict(scope, **{field: value}))
            for field, value in (("unexpected", True), ("selectedInf", "../outside.inf"),
                                 ("modelSection", "Fixture.NTx86"), ("maximumBytes", 0), ("maximumBytes", True)):
                changed = deepcopy(scope)
                changed["acquisitionBinding"][field] = value
                variants.append(changed)
            for index, changed in enumerate(variants):
                raw = pipeline.canonical(changed)
                args.acquisition_scope.write_bytes(raw)
                args.acquisition_scope_sha256 = pipeline.sha(raw)
                with self.subTest(variant=index), self.assertRaises(ValueError):
                    prepare.inherit_config(args, budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.calls, [])

    def test_selector_conflict_and_old_mode_input_mixing_fail(self):
        import prepare_daily_index_config as prepare
        with self.world() as world:
            args = self.arguments(world)
            for values in ({"selected_inf": "OTHER/W11/fixture.inf"},
                           {"acquisition_scope": None, "acquisition_scope_sha256": None}):
                with self.subTest(values=tuple(values)), self.assertRaises(ValueError):
                    prepare.inherit_config(SimpleNamespace(**dict(vars(args), **values)), budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.calls, [])

    def test_changed_manual_body_witness_or_terms_refuse_without_fallback(self):
        import prepare_daily_index_config as prepare
        for variant in ("body", "witness", "binding-terms"):
            with self.subTest(variant=variant), self.world() as world:
                args = self.arguments(world, technical=True)
                if variant == "body":
                    args.original_body.write_bytes(args.original_body.read_bytes()+b"changed")
                    args.original_body_sha256 = pipeline.sha(args.original_body.read_bytes())
                else:
                    name = "original_review" if variant == "witness" else "binding_release"
                    value = json.loads(getattr(args, name).read_bytes())
                    if variant == "witness":
                        value["scriptWitnesses"][0]["literal"] = "not-present-in-reviewed-script"
                    else:
                        value["termsRevision"] = "changed terms"
                    raw = pipeline.canonical(value)
                    getattr(args, name).write_bytes(raw)
                    setattr(args, name+"_sha256", pipeline.sha(raw))
                with self.assertRaises(ValueError):
                    prepare.inherit_config(args, budget=world)
                self.assertFalse(args.control_directory.exists())
                self.assertEqual(world.calls, [])

    def test_loader_refuses_selector_rebound_after_regular_issue(self):
        import prepare_daily_index_config as prepare
        with self.world() as world:
            path = prepare.inherit_config(self.arguments(world), budget=world)
            config = json.loads(path.read_bytes())
            config["selectedInf"] = "OTHER/W11/fixture.inf"
            path.write_bytes(pipeline.canonical(config))
            with self.assertRaisesRegex(ValueError, "^NATIVE_INF_BINDING$"):
                pipeline.load_config(path)

    def test_cli_unknown_duplicate_and_noninherit_modes_fail(self):
        import prepare_daily_index_config as prepare
        for mode in ([], ["--repair-config", "old.json"], ["--public-config-from", "old.json"],
                     ["--continue-presign-config", "old.json"]):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "^INHERIT_MODE_REQUIRED$"):
                prepare.preparation_arguments(mode+["--original-body", "body"])
        with self.assertRaisesRegex(ValueError, "^PREPARE_ARGUMENT_DUPLICATE$"):
            prepare.preparation_arguments(["--inherit-config", "old", "--original-body", "a", "--original-body=b"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            prepare.preparation_arguments(["--inherit-config", "old", "--unexpected-field", "value"])


if __name__ == "__main__":
    unittest.main()
