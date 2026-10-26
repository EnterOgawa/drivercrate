"""固定Intel/P1を代表する原候補集合からmanual Publisherまでを有限fakeで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
人工署名/人工観測であり、実取得/実PC適合/本番署名/公開へ換算しない。
"""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import daily_index_pipeline as pipeline
import test_project_collected_native_index as native_fixture
from test_candidate_publication import CandidateWorld, fake_envelope
from test_daily_index_pipeline import anonymous_stdout_fixture


class PublicationWorld(CandidateWorld):
    """原六入力と既存非I/O projector、既存Publisher/匿名wire parserを接続する。"""

    def __init__(self, directory, *, nested=False, include_native=True, include_generic=True):
        super().__init__(directory, nested=nested)
        self.stack.enter_context(patch.object(pipeline, "validate_v2_code"))
        self.anonymous_behavior = "success"
        self.fixture = native_fixture.PinnedStaticRevalidationTests()
        self.fixture.setUp()
        self.stack.callback(self.fixture.doCleanups)
        self.now = self.fixture.now
        # P1を代表する人工recordは元wrapperを固定し、実公開dataとは区別する。
        index = pipeline.cr.parse_json(self.source_raw["index.json"])
        for ordinal, row in enumerate(index["records"]):
            record = pipeline.cr.parse_json(base64.b64decode(row["recordBytesBase64"]))
            record["recordId"] = "prolific-pl2303g-dchu-1-0-0-1" if ordinal == 0 else f"artificial-p1-inf-{ordinal}"
            checked = self.now - timedelta(hours=3-ordinal)
            record["acquisitionDescriptor"]["attestation"] = {
                "checkedAtUtc": checked.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "validUntilUtc": (checked + timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            body = pipeline.canonical(record)
            row.update(recordBytesBase64=base64.b64encode(body).decode(), recordSha256=pipeline.sha(body))
        packed = pipeline.candidate_publication_gzip(pipeline.cr.json_bytes(index))
        self.manifest.update(publishedAtUtc="2026-10-15T12:30:00Z",
            expiresAtUtc=(self.now + timedelta(days=8, hours=-3)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.manifest["asset"].update(tag="index-v1-20261015-" + pipeline.sha(packed),
            sha256=pipeline.sha(packed), sizeBytes=len(packed))
        self.source_raw.update({"index.json": pipeline.cr.json_bytes(index), "index.json.gz": packed,
            "manifest.raw.json": pipeline.cr.json_bytes(self.manifest)})
        self.save_candidate()
        self.generation = self.fixture.receipt["generation"]
        self.native_receipt = pipeline.canonical(self.fixture.receipt)
        self.receipt_path.write_bytes(self.native_receipt)
        self.receipt_hash = pipeline.sha(self.native_receipt)
        scope_path = directory / "scope.json"
        scope_path.write_bytes(pipeline.canonical(self.fixture.scope))
        self.config.update(scopeFile=str(scope_path), scopeSha256=pipeline.sha(scope_path.read_bytes()),
            termsReviewMode=pipeline.projection.PINNED_STATIC_REVALIDATION_V1)
        self.config_hash = pipeline.sha(pipeline.canonical(self.config))
        document = {"schema": "dc-candidate-native-inputs-v1", "inputs": {}}
        for name in ("scope", "evidence", "release", "inspection", "review", "script"):
            body = self.native_receipt if name == "evidence" else pipeline.canonical(getattr(self.fixture, name))
            path = directory / ("native-" + name + ".json")
            path.write_bytes(body)
            document["inputs"][name] = {"file": str(path), "sha256": pipeline.sha(body)}
        self.native_path = directory / "native-inputs.json"
        self.native_path.write_bytes(pipeline.canonical(document))
        self.native_selection = (self.native_path, pipeline.sha(self.native_path.read_bytes())) if include_native else None
        self.generic_selection = (self.head_path, self.head_hash)
        if not include_generic:
            self.head_path, self.head_hash = None, None
        historical = deepcopy(self.manifest)
        historical.update(generation=5, assetGeneration=5, publishedAtUtc="2026-10-12T16:32:04Z",
            expiresAtUtc="2026-10-13T13:24:11Z")
        self.set_public(fake_envelope(pipeline.cr.json_bytes(historical)), packed)
        for release in self.remote.releases.values():
            release["id"] = 1

    def remaining(self, maximum=600):
        """既存PublicOperationBudgetの有限枠をそのまま使い、実時間待機は行わない。"""
        return min(maximum, 1800)

    def run(self, argv, *args, **kwargs):
        """同native署名代役と完全匿名wireだけをfake化する。HTTP fallbackはない。"""
        if argv[1] == "--public-index-readback":
            self.calls.append(list(argv))
            bundle = {"manifest.json": Path(argv[2]).read_bytes(), "index.json.gz": Path(argv[3]).read_bytes()}
            result = anonymous_stdout_fixture(bundle, self.now, self.anonymous_behavior)
            return (0 if self.anonymous_behavior == "success" else 2), result, b""
        if argv[1] == "--distribution-verify-floor-history":
            proxy = list(argv)
            proxy[1] = "--distribution-acquisition-verify-history"
            return super().run(proxy)
        return super().run(argv, **kwargs)

    def prepare(self, **kwargs):
        return super().prepare(head_profile=kwargs.pop("head_profile", pipeline.HISTORY_FLOOR),
            native_inputs=self.native_selection, **kwargs)

    def sign(self, prepared, **kwargs):
        return super().sign(prepared, native_inputs=self.native_selection, **kwargs)

    def publish(self, prepared, signed, **kwargs):
        return pipeline.publish_candidate_publication(self.config, self.config_hash, self.head_path, self.head_hash,
            self.receipt_path, self.receipt_hash, self.out / prepared["claimName"], prepared["claimSha256"],
            self.config["fingerprint"], signed["envelopeSha256"], native_inputs=self.native_selection,
            budget=kwargs.pop("budget", self), remote=self.remote, **kwargs)


class PublicationPathTests(unittest.TestCase):
    """実公開を行わず、原集合/失効/衝突/保存窓/元不確定と単一CASを確認する。"""

    def world(self, **kwargs):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="dc-publish-path-")))
        world = PublicationWorld(directory, **kwargs)
        self.addCleanup(world.close)
        return world

    def signed(self, world):
        prepared = world.prepare()
        return prepared, world.sign(prepared)

    def test_each_explicit_producer_selection_runs_all_three_main_phases(self):
        """実CLI dispatchを通し、未指定系統のfile欠如が発行内容を補完しないことを確認する。"""
        for generic, native in ((True, False), (False, True), (True, True)):
            world = self.world(include_generic=generic, include_native=native)
            expected = []
            if generic:
                expected.append(pipeline.cr.parse_json(world.source_raw["index.json"]))
            else:
                world.generic_selection[0].unlink()
                for path in world.source.iterdir():
                    path.unlink()
            if native:
                projected = pipeline.candidate_publication_native_inputs(world.config, world.native_selection,
                    world.receipt_path, world.receipt_hash, world.now)
                expected.append(pipeline.cr.parse_json(projected["index.json"]))
            else:
                world.native_path.unlink()
            common = [str(world.base / "config.json"), "--reservation-receipt", str(world.receipt_path),
                "--reservation-receipt-sha256", world.receipt_hash]
            if generic:
                common += ["--candidate-head", str(world.head_path), "--candidate-head-sha256", world.head_hash]
            if native:
                common += ["--native-inputs", str(world.native_path), "--native-inputs-sha256", world.native_selection[1]]
            def fake_child(budget, values, *args, **kwargs):
                self.assertEqual(budget.directory, world.out)
                return world.run(values, *args, **kwargs)
            def invoke(mode, extra):
                """製品mainのload/transport/childだけを人工値へ結び、別発行APIを使わない。"""
                output = io.StringIO()
                with patch.object(pipeline.sys, "argv", ["pipeline", mode, *common, *extra]), \
                        patch.object(pipeline, "load_config", return_value=(world.config, {}, world.config_hash)), \
                        patch.object(pipeline, "GitHub", return_value=world.remote), \
                        patch.object(pipeline.Budget, "run", autospec=True, side_effect=fake_child), \
                        patch.object(pipeline, "run_pipeline", side_effect=AssertionError("DAILY_NOT_ALLOWED")), \
                        redirect_stdout(output):
                    self.assertEqual(pipeline.main(), 0, output.getvalue())
                return json.loads(output.getvalue())
            with self.subTest(generic=generic, native=native):
                prepared = invoke("prepare-candidate", ["--head-profile", pipeline.HISTORY_FLOOR])
                self.assertEqual(invoke("prepare-candidate", ["--head-profile", pipeline.HISTORY_FLOOR]), prepared)
                claim_path = world.out / prepared["claimName"]
                claim = pipeline.cr.parse_json(claim_path.read_bytes())
                self.assertEqual(claim["candidateHeadSha256"], world.head_hash)
                self.assertEqual(claim["candidateOutputs"], pipeline.cr.parse_json(world.head_raw)["outputs"] if generic else None)
                self.assertEqual(claim["nativeInputsSha256"], world.native_selection[1] if native else None)
                self.assertEqual(claim["nativeReservation"]["mode"], "LEGACY_FENCE")
                selected = ["--claim", str(claim_path), "--claim-sha256", prepared["claimSha256"],
                    "--fingerprint", world.config["fingerprint"]]
                signed = invoke("sign-candidate", selected)
                self.assertTrue(invoke("sign-candidate", selected)["resumed"])
                published = invoke("publish-candidate", [*selected, "--envelope-sha256", signed["envelopeSha256"]])
                self.assertEqual(published["status"], "PUBLISHED")
                writes = sum(event[0] != "GET" for event in world.remote.events)
                self.assertTrue(invoke("publish-candidate", [*selected,
                    "--envelope-sha256", signed["envelopeSha256"]])["resumed"])
                self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), writes)
                self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)
                paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
                actual = pipeline.cr.parse_json(paths["index.json"].read_bytes())
                self.assertEqual(actual["sources"], [row for origin in expected for row in origin["sources"]])
                self.assertEqual(actual["records"], [row for origin in expected for row in origin["records"]])
                expiries = [pipeline.cr.parse_json(base64.b64decode(row["recordBytesBase64"]))[
                    "acquisitionDescriptor"]["attestation"]["validUntilUtc"] for row in actual["records"]]
                self.assertTrue(expiries)
                self.assertEqual(claim["expiresAtUtc"], min(expiries))

    def test_native_only_claim_keeps_generic_and_legacy_unknown_claim_floors(self):
        """同namespaceの両旧claimを保持し、新入力へ世代を再利用しない。"""
        world = self.world(include_native=False)
        prepared = world.prepare()
        generic_claim = world.out / prepared["claimName"]
        old = world.add_old_claim(12)
        originals = {path: path.read_bytes() for path in (generic_claim, old)}
        world.head_path, world.head_hash = None, None
        world.native_selection = (world.native_path, pipeline.sha(world.native_path.read_bytes()))
        new = world.prepare()
        self.assertEqual(new["generation"], 13)
        self.assertEqual(world.prepare(), new)
        self.assertEqual({path: path.read_bytes() for path in originals}, originals)
        self.assertEqual(world.publish(new, world.sign(new))["status"], "PUBLISHED")

    def test_claim_selection_changes_never_reuse_original_sign_or_publish_authority(self):
        """claim作成後の系統追加/削除・異なるpin・同原byte別pinを拒否する。"""
        for starting in ("generic", "native", "both"):
            world = self.world(include_generic=starting != "native", include_native=starting != "generic")
            prepared, signed = self.signed(world)
            original_head, original_hash = world.head_path, world.head_hash
            original_native = world.native_selection
            variants = [(None, None, (world.native_path, pipeline.sha(world.native_path.read_bytes()))),
                (*world.generic_selection, None),
                (*world.generic_selection, (world.native_path, pipeline.sha(world.native_path.read_bytes())))]
            for head, digest, native in variants:
                if (head, digest, native) == (original_head, original_hash, original_native):
                    continue
                world.head_path, world.head_hash, world.native_selection = head, digest, native
                with self.subTest(starting=starting, generic=head is not None, native=native is not None):
                    with self.assertRaisesRegex(ValueError, "CANDIDATE_(SIGN_INPUTS|NATIVE_INPUT_PIN)"):
                        world.sign(prepared)
                    with self.assertRaisesRegex(ValueError, "CANDIDATE_PUBLISH_INPUTS"):
                        world.publish(prepared, signed)
            world.head_path, world.head_hash, world.native_selection = original_head, original_hash, original_native
            if original_native is not None:
                world.native_path.write_bytes(world.native_path.read_bytes() + b" ")
                world.native_selection = (world.native_path, pipeline.sha(world.native_path.read_bytes()))
                with self.assertRaisesRegex(ValueError, "CANDIDATE_NATIVE_INPUT_PIN"):
                    world.sign(prepared)
                with self.assertRaisesRegex(ValueError, "CANDIDATE_PUBLISH_INPUTS"):
                    world.publish(prepared, signed)
            self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)
            self.assertEqual(world.remote.ref_updates, 0)

    def test_native_only_explicit_content_failures_never_drop_a_selected_input(self):
        """六原入力の不適合を汎用なしでも拒否し、予約claimを作らない。"""
        for name in ("scope", "evidence", "release", "inspection", "review", "script"):
            world = self.world(include_generic=False)
            document = pipeline.cr.parse_json(world.native_path.read_bytes())
            entry = document["inputs"][name]
            path = Path(entry["file"])
            changed = pipeline.cr.parse_json(path.read_bytes())
            if name == "release":
                changed["termsText"] = "Artificial changed terms"
            elif name == "inspection":
                changed["infs"][0]["contentError"] = 13
            elif name == "review":
                changed["pageSha256"] = "0" * 64
            elif name == "script":
                changed["scriptExecuted"] = True
            else:
                changed["schema"] = "UNKNOWN"
            path.write_bytes(pipeline.canonical(changed))
            entry["sha256"] = pipeline.sha(path.read_bytes())
            world.native_path.write_bytes(pipeline.canonical(document))
            world.native_selection = (world.native_path, pipeline.sha(world.native_path.read_bytes()))
            with self.subTest(input=name), self.assertRaises(ValueError):
                world.prepare()
            self.assertFalse(list(world.out.glob("issuance-*.claim.json")))
            self.assertFalse(any(call[1] == "--distribution-acquisition-sign" for call in world.calls))
            self.assertTrue(all(event[0] == "GET" for event in world.remote.events))

    def test_broken_selected_generic_head_never_falls_back_to_valid_native(self):
        """両系統指定の壊れたheadを黙って除外せず、原byteを保持する。"""
        world = self.world()
        world.head_path.write_bytes(world.head_raw + b" ")
        with self.assertRaisesRegex(ValueError, "CANDIDATE_HEAD_PIN"):
            world.prepare()
        self.assertFalse(list(world.out.glob("issuance-*.claim.json")))
        self.assertEqual(world.remote.events, [])

    def test_native_only_original_pin_change_and_expiry_reject_each_phase_and_cas(self):
        """実時間の失効と原file変更を各段階で拒否し、署名束/未確定を保持する。"""
        for stage in ("prepare", "sign", "publish", "cas", "native-pin"):
            world = self.world(include_generic=False)
            projected = pipeline.candidate_publication_native_inputs(world.config, world.native_selection,
                world.receipt_path, world.receipt_hash, world.now)
            expiry = pipeline.parse_time(pipeline.cr.parse_json(projected["manifest.raw.json"])["expiresAtUtc"])
            prepared = world.prepare() if stage != "prepare" else None
            signed = world.sign(prepared) if stage in ("publish", "cas", "native-pin") else None
            paths = pipeline.candidate_publication_paths(world.out, prepared["generation"]) if prepared else {}
            original = {name: path.read_bytes() for name, path in paths.items() if path.exists()}
            if stage == "cas":
                def expire(remote):
                    if remote.events[-1][1] == pipeline.API + "/git/commits":
                        remote.change_after_write = None
                        world.now = expiry
                world.remote.change_after_write = expire
            elif stage == "native-pin":
                entry = pipeline.cr.parse_json(world.native_path.read_bytes())["inputs"]["inspection"]
                path = Path(entry["file"])
                path.write_bytes(path.read_bytes() + b" ")
            else:
                world.now = expiry
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                if stage == "prepare":
                    world.prepare()
                elif stage == "sign":
                    world.sign(prepared)
                else:
                    world.publish(prepared, signed)
            self.assertEqual(world.remote.ref_updates, 0)
            self.assertFalse(list(world.out.glob("candidate-publish-*.cas-intent.json")))
            self.assertEqual({name: paths[name].read_bytes() for name in original}, original)
            self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1 if signed else 0)

    def test_native_only_signing_and_cas_unknown_resume_without_repeating_actions(self):
        """原nonzeroとCAS応答不明を保存し、再開で再署名/二重CASをしない。"""
        world = self.world(include_generic=False)
        prepared = world.prepare()
        def nonzero(argv, body):
            Path(argv[4]).write_bytes(fake_envelope(body))
            return 7, b"ARTIFICIAL_NONZERO", b""
        world.sign_hook = nonzero
        with self.assertRaisesRegex(ValueError, "OUTCOME_UNKNOWN"):
            world.sign(prepared)
        paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
        original_signing = paths["signing-result.json"].read_bytes()
        signed = world.sign(prepared)
        api = world.remote.api
        def lost(method, path, body=None, **kwargs):
            result = api(method, path, body, **kwargs)
            if path == "graphql":
                raise ValueError("FAKE_CAS_RESPONSE_UNKNOWN")
            return result
        world.remote.api = lost
        with self.assertRaisesRegex(ValueError, "RESPONSE_UNKNOWN"):
            world.publish(prepared, signed)
        original_terminals = {path: path.read_bytes() for path in world.out.glob("candidate-publish-*.terminal-*.json")}
        writes = sum(event[0] != "GET" for event in world.remote.events)
        result = world.publish(prepared, signed)
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual((result["originalSigningStatus"], result["originalChildExitCode"]), ("UNKNOWN_NO_RE_SIGN", 7))
        self.assertEqual(world.remote.ref_updates, 1)
        self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), writes)
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)
        self.assertEqual(paths["signing-result.json"].read_bytes(), original_signing)
        self.assertEqual({path: path.read_bytes() for path in original_terminals}, original_terminals)

    def test_full_flat_nested_original_intel_p1_set_and_anonymous_resume(self):
        for nested in (False, True):
            world = self.world(nested=nested)
            before = deepcopy(world.source_raw)
            native = pipeline.candidate_publication_native_inputs(world.config, world.native_selection,
                world.receipt_path, world.receipt_hash, world.now)
            prepared, signed = self.signed(world)
            paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
            original = pipeline.cr.parse_json(before["index.json"])
            expected_native = pipeline.cr.parse_json(native["index.json"])
            final = pipeline.cr.parse_json(paths["index.json"].read_bytes())
            self.assertEqual(final["records"], original["records"] + expected_native["records"])
            self.assertEqual(final["sources"], original["sources"] + expected_native["sources"])
            self.assertEqual(len(final["sources"]), 2)
            records = [pipeline.cr.parse_json(base64.b64decode(row["recordBytesBase64"])) for row in final["records"]]
            self.assertIn("intel-wired-31-2-2-win11", [row["recordId"] for row in records])
            self.assertIn("prolific-pl2303g-dchu-1-0-0-1", [row["recordId"] for row in records])
            expiries = [row["acquisitionDescriptor"]["attestation"]["validUntilUtc"] for row in records]
            self.assertGreater(len(set(expiries)), 1)
            self.assertEqual(pipeline.cr.parse_json(paths["manifest.raw.json"].read_bytes())["expiresAtUtc"], min(expiries))
            result = world.publish(prepared, signed)
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(result["publicAnonymousReadback"]["status"], "VERIFIED")
            self.assertEqual(world.remote.ref_updates, 1)
            count = sum(event[0] != "GET" for event in world.remote.events)
            result = world.publish(prepared, signed)
            self.assertTrue(result["resumed"])
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), count)
            self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)
            self.assertEqual(world.source_raw, before)

    def test_explicit_native_pins_scope_receipt_and_expiry_reject_without_signing(self):
        for variant in ("hash", "scope", "receipt", "expired"):
            world = self.world()
            if variant == "hash":
                world.native_selection = (world.native_path, "0" * 64)
            elif variant == "scope":
                world.config["scopeSha256"] = "0" * 64
            elif variant == "receipt":
                document = pipeline.cr.parse_json(world.native_path.read_bytes())
                entry = document["inputs"]["evidence"]
                Path(entry["file"]).write_bytes(pipeline.canonical({"generation": 9}))
                entry["sha256"] = pipeline.sha(Path(entry["file"]).read_bytes())
                world.native_path.write_bytes(pipeline.canonical(document))
                world.native_selection = (world.native_path, pipeline.sha(world.native_path.read_bytes()))
            else:
                world.now += timedelta(days=1)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                world.prepare()
            self.assertFalse(any(call[1] == "--distribution-acquisition-sign" for call in world.calls))
            self.assertEqual(world.remote.ref_updates, 0)

    def test_source_and_record_collisions_are_rejected(self):
        world = self.world()
        native = pipeline.candidate_publication_native_inputs(world.config, world.native_selection,
            world.receipt_path, world.receipt_hash, world.now)
        with self.assertRaisesRegex(ValueError, "RECORD_CONFLICT"):
            pipeline.candidate_publication_merge(world.source_raw, world.source_raw)
        changed = pipeline.cr.parse_json(native["index.json"])
        changed["sources"][0]["sourceId"] = "fixture-source"
        with self.assertRaisesRegex(ValueError, "SOURCE_CONFLICT"):
            pipeline.candidate_publication_merge(world.source_raw,
                dict(native, **{"index.json": pipeline.cr.json_bytes(changed)}))

    def test_pins_signature_expiry_and_changed_native_head_reject_before_remote_write(self):
        for variant in ("signature", "envelope-pin", "expiry", "native-head", "source-pin"):
            world = self.world()
            prepared, signed = self.signed(world)
            if variant == "signature":
                world.fail_modes["--distribution-acquisition-verify"] = 2
            elif variant == "envelope-pin":
                signed["envelopeSha256"] = "0" * 64
            elif variant == "expiry":
                world.now = pipeline.parse_time(pipeline.cr.parse_json(world.source_raw["manifest.raw.json"])["expiresAtUtc"])
            elif variant == "native-head":
                world.generation += 1
            else:
                world.head_path.write_bytes(world.head_raw + b" ")
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                world.publish(prepared, signed)
            self.assertTrue(all(event[0] == "GET" for event in world.remote.events))
            self.assertEqual(world.remote.ref_updates, 0)

    def test_advanced_or_regressed_public_head_and_same_generation_conflict_reject(self):
        for generation in (4, 6, 10):
            world = self.world()
            prepared, signed = self.signed(world)
            historical = deepcopy(world.manifest)
            historical.update(generation=generation, assetGeneration=generation)
            world.set_public(fake_envelope(pipeline.cr.json_bytes(historical)), world.source_raw["index.json.gz"])
            with self.subTest(generation=generation), self.assertRaises(ValueError):
                world.publish(prepared, signed)
            self.assertEqual(world.remote.ref_updates, 0)

    def test_partial_upload_can_resume_same_bytes_without_resigning(self):
        world = self.world()
        prepared, signed = self.signed(world)
        world.remote.failure = "upload"
        with self.assertRaisesRegex(ValueError, "UPLOAD"):
            world.publish(prepared, signed)
        original = {path.name: path.read_bytes() for path in world.out.glob("candidate-publish-*.terminal-*.json")}
        world.remote.failure = None
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        self.assertTrue(all((world.out / name).read_bytes() == raw for name, raw in original.items()))
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_cas_intent_unknown_rejects_second_cas_and_retains_original(self):
        world = self.world()
        prepared, signed = self.signed(world)
        world.remote.failure = "cas"
        with self.assertRaisesRegex(ValueError, "CAS"):
            world.publish(prepared, signed)
        count = sum(event[0] != "GET" for event in world.remote.events)
        world.remote.failure = None
        with self.assertRaisesRegex(ValueError, "CURRENT_CAS_OUTCOME_UNKNOWN"):
            world.publish(prepared, signed)
        self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), count)
        self.assertEqual(world.remote.ref_updates, 1)

    def test_cas_applied_but_response_unknown_resumes_by_readback_only(self):
        world = self.world()
        prepared, signed = self.signed(world)
        api = world.remote.api
        once = [False]
        def lost(method, path, body=None, **kwargs):
            result = api(method, path, body, **kwargs)
            if path == "graphql" and not once[0]:
                once[0] = True
                raise ValueError("FAKE_CAS_RESPONSE_UNKNOWN")
            return result
        world.remote.api = lost
        with self.assertRaisesRegex(ValueError, "RESPONSE_UNKNOWN"):
            world.publish(prepared, signed)
        count = sum(event[0] != "GET" for event in world.remote.events)
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), count)
        self.assertEqual(world.remote.ref_updates, 1)

    def test_anonymous_unknown_retained_and_readback_can_resume(self):
        world = self.world()
        prepared, signed = self.signed(world)
        world.anonymous_behavior = "partial"
        result = world.publish(prepared, signed)
        self.assertEqual(result["status"], "UNKNOWN")
        files = {path: path.read_bytes() for path in world.out.glob("candidate-publish-*.terminal-*.json")}
        count = sum(event[0] != "GET" for event in world.remote.events)
        world.anonymous_behavior = "success"
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        self.assertTrue(all(path.read_bytes() == raw for path, raw in files.items()))
        self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), count)

    def test_original_signing_unknown_nonzero_is_preserved_when_artifact_is_verified(self):
        world = self.world()
        prepared = world.prepare()
        def nonzero(argv, body):
            Path(argv[4]).write_bytes(fake_envelope(body))
            return 7, b"ARTIFICIAL_NONZERO", b""
        world.sign_hook = nonzero
        with self.assertRaisesRegex(ValueError, "OUTCOME_UNKNOWN"):
            world.sign(prepared)
        paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
        original = paths["signing-result.json"].read_bytes()
        signed = world.sign(prepared)
        result = world.publish(prepared, signed)
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual((result["originalSigningStatus"], result["originalChildExitCode"]), ("UNKNOWN_NO_RE_SIGN", 7))
        self.assertEqual(paths["signing-result.json"].read_bytes(), original)
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_cli_publish_and_native_pin_pairs_are_explicit(self):
        base = ["publish-candidate", "config", "--candidate-head", "head", "--candidate-head-sha256", "a" * 64,
            "--reservation-receipt", "receipt", "--reservation-receipt-sha256", "b" * 64,
            "--claim", "claim", "--claim-sha256", "c" * 64, "--fingerprint", "d" * 64, "--envelope-sha256", "e" * 64]
        self.assertEqual(pipeline.pipeline_arguments(base).mode, "publish-candidate")
        for extra in (["--native-inputs", "inputs"], ["--native-inputs-sha256", "f" * 64]):
            with self.assertRaises(ValueError):
                pipeline.pipeline_arguments(base + extra)
        with self.assertRaises(ValueError):
            pipeline.pipeline_arguments(base[:-2])

    def test_native_original_file_tamper_after_prepare_precedes_sign_or_publish(self):
        world = self.world()
        prepared, signed = self.signed(world)
        document = pipeline.cr.parse_json(world.native_path.read_bytes())
        original = Path(document["inputs"]["inspection"]["file"])
        original.write_bytes(original.read_bytes() + b" ")
        before = sum(call[1] == "--distribution-acquisition-sign" for call in world.calls)
        with self.assertRaisesRegex(ValueError, "NATIVE_INPUT_PIN"):
            world.sign(prepared)
        with self.assertRaisesRegex(ValueError, "NATIVE_INPUT_PIN"):
            world.publish(prepared, signed)
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), before)
        self.assertEqual(world.remote.ref_updates, 0)

    def test_head_change_after_immutable_assets_before_cas_is_rejected(self):
        world = self.world()
        prepared, signed = self.signed(world)
        def change(remote):
            if remote.events[-1][1] == pipeline.API + "/git/commits":
                remote.change_after_write = None
                manifest = deepcopy(world.manifest)
                manifest.update(generation=6, assetGeneration=6)
                world.set_public(fake_envelope(pipeline.cr.json_bytes(manifest)), world.source_raw["index.json.gz"])
        world.remote.change_after_write = change
        with self.assertRaisesRegex(ValueError, "PUBLISH_STALE"):
            world.publish(prepared, signed)
        self.assertEqual(world.remote.ref_updates, 0)
        self.assertFalse(list(world.out.glob("candidate-publish-*.cas-intent.json")))

    def test_saved_cas_intent_checkpoint_never_reissues_cas(self):
        world = self.world()
        prepared, signed = self.signed(world)
        def stop(stage):
            if stage == "CAS_INTENT":
                raise ValueError("ARTIFICIAL_CAS_WINDOW_STOP")
        with self.assertRaisesRegex(ValueError, "CAS_WINDOW_STOP"):
            world.publish(prepared, signed, checkpoint=stop)
        writes = sum(event[0] != "GET" for event in world.remote.events)
        with self.assertRaisesRegex(ValueError, "CURRENT_CAS_OUTCOME_UNKNOWN"):
            world.publish(prepared, signed)
        self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), writes)
        self.assertEqual(world.remote.ref_updates, 0)

    def test_real_budget_type_binds_protected_output_before_any_child(self):
        world = self.world()
        prepared, signed = self.signed(world)
        inner = pipeline.Budget()
        def fake_child(budget, argv, *args, **kwargs):
            self.assertEqual(budget.directory, world.out)
            return world.run(argv, *args, **kwargs)
        with patch.object(pipeline.Budget, "run", autospec=True, side_effect=fake_child):
            self.assertEqual(world.publish(prepared, signed, budget=inner)["status"], "PUBLISHED")
        self.assertEqual(world.remote.ref_updates, 1)

    def test_exhausted_budget_and_durable_tamper_refuse_without_new_remote_writes(self):
        world = self.world()
        prepared, signed = self.signed(world)
        with patch.object(world, "remaining", side_effect=ValueError("TOTAL_TIMEOUT")), \
                self.assertRaisesRegex(ValueError, "TOTAL_TIMEOUT"):
            world.publish(prepared, signed)
        self.assertEqual(world.remote.ref_updates, 0)
        self.assertTrue(all(event[0] == "GET" for event in world.remote.events))
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        original = next(world.out.glob("candidate-publish-*.public-budget-00.intent.json"))
        original.write_bytes(original.read_bytes() + b" ")
        writes = sum(event[0] != "GET" for event in world.remote.events)
        with self.assertRaisesRegex(ValueError, "PUBLIC_BUDGET_JOURNAL"):
            world.publish(prepared, signed)
        self.assertEqual(sum(event[0] != "GET" for event in world.remote.events), writes)

    def test_main_dispatches_publish_with_real_budget_type_and_fixed_native_inputs(self):
        world = self.world()
        prepared, signed = self.signed(world)
        argv = ["daily_index_pipeline.py", "publish-candidate", str(world.base / "config.json"),
            "--candidate-head", str(world.head_path), "--candidate-head-sha256", world.head_hash,
            "--reservation-receipt", str(world.receipt_path), "--reservation-receipt-sha256", world.receipt_hash,
            "--claim", str(world.out / prepared["claimName"]), "--claim-sha256", prepared["claimSha256"],
            "--fingerprint", world.config["fingerprint"], "--envelope-sha256", signed["envelopeSha256"],
            "--native-inputs", str(world.native_path), "--native-inputs-sha256", world.native_selection[1]]
        def fake_child(budget, values, *args, **kwargs):
            self.assertEqual(budget.directory, world.out)
            return world.run(values, *args, **kwargs)
        output = io.StringIO()
        with patch.object(pipeline.sys, "argv", argv), \
                patch.object(pipeline, "load_config", return_value=(world.config, {}, world.config_hash)), \
                patch.object(pipeline, "GitHub", return_value=world.remote), \
                patch.object(pipeline.Budget, "run", autospec=True, side_effect=fake_child), redirect_stdout(output):
            self.assertEqual(pipeline.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "PUBLISHED")
        self.assertEqual(sum(call[1] == "--distribution-acquisition-sign" for call in world.calls), 1)

    def test_existing_native_audit_privacy_and_embedded_original_byte_pins_are_maintained(self):
        for variant in ("secret", "embedded-raw"):
            world = self.world()
            document = pipeline.cr.parse_json(world.native_path.read_bytes())
            entry = document["inputs"]["inspection" if variant == "secret" else "release"]
            path = Path(entry["file"])
            if variant == "secret":
                record = pipeline.cr.parse_json(path.read_bytes())
                record["infs"][0]["verifiedPublisher"] = "Artificial github_pat_example"
                path.write_bytes(pipeline.canonical(record))
            else:
                path.write_bytes(path.read_bytes() + b" ")
            entry["sha256"] = pipeline.sha(path.read_bytes())
            world.native_path.write_bytes(pipeline.canonical(document))
            world.native_selection = (world.native_path, pipeline.sha(world.native_path.read_bytes()))
            with self.subTest(variant=variant), self.assertRaisesRegex(ValueError,
                    "PUBLIC_PRIVACY_SECRET" if variant == "secret" else "TERMS_REVALIDATION_PIN"):
                world.prepare()
            self.assertEqual(world.remote.ref_updates, 0)


if __name__ == "__main__":
    unittest.main()
