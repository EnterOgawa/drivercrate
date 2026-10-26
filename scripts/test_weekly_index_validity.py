"""fresh発行24h・原8日期限と、週次の運用目標を別の境界として確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
完全人工観測/RAM remoteだけを使い、実署名・通信・運用stateを変更しない。
"""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import daily_index_pipeline as pipeline
import project_collected_native_index as projection
from test_candidate_publish_path import PublicationWorld
import test_project_collected_native_index as projection_fixture


class WeeklyValidityTests(unittest.TestCase):
    """原byteと期限を保持し、発行時と利用時の異なる時計を検査する。"""

    def world(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="dc-weekly-")))
        world = PublicationWorld(directory, include_native=False)
        self.addCleanup(world.close)
        return world

    def test_new_native_record_eight_days_and_fresh_twenty_four_hours_are_separate(self):
        fixture = projection_fixture.DailyDistributionProjectionTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        original = deepcopy((fixture.scope, fixture.receipt, fixture.release, fixture.inspection,
                             fixture.review, fixture.script))
        raw, packed, manifest, _ = fixture.project()
        document = pipeline.cr.parse_json(manifest)
        observed = datetime.fromtimestamp(fixture.receipt["lastSuccessfulValidationAt"], timezone.utc)
        expiry = pipeline.parse_time(document["expiresAtUtc"])
        self.assertEqual(expiry, observed + timedelta(days=8))
        candidate = {"index.json": raw, "index.json.gz": packed, "manifest.raw.json": manifest}
        with patch.object(pipeline, "utc", return_value=fixture.now):
            pipeline.candidate_publication_validity(candidate)
        self.assertLess(fixture.now + timedelta(days=7), expiry)
        before = observed + timedelta(days=1, seconds=-1)
        self.assertEqual(pipeline.cr.parse_json(fixture.project(now=before)[0])["records"],
                         pipeline.cr.parse_json(raw)["records"])
        with patch.object(pipeline, "utc", return_value=before):
            pipeline.candidate_publication_validity(candidate)
        with self.assertRaisesRegex(ValueError, "DAILY_OBSERVATION_TIME"):
            fixture.project(now=observed + timedelta(days=1))
        with patch.object(pipeline, "utc", return_value=observed + timedelta(days=1)):
            pipeline.candidate_publication_validity(candidate)
        with patch.object(pipeline, "utc", return_value=expiry), self.assertRaisesRegex(ValueError, "CANDIDATE_EXPIRED"):
            pipeline.candidate_publication_validity(candidate)
        self.assertLess(observed + timedelta(days=1), expiry)
        old_scope = dict(fixture.scope, projectionPolicyRevision=1)
        with self.assertRaisesRegex(ValueError, "DISTRIBUTION_SCOPE_TYPE"):
            fixture.project(scope=old_scope)
        with self.assertRaisesRegex(ValueError, "DAILY_OBSERVATION_TIME"):
            fixture.project(now=datetime.now(timezone.utc).replace(microsecond=0))
        self.assertEqual(original, (fixture.scope, fixture.receipt, fixture.release, fixture.inspection,
                                    fixture.review, fixture.script))

    def test_prepare_and_sign_accept_short_validity_and_reject_expiry_without_record_changes(self):
        for stage in ("prepare", "sign"):
            for remaining in (timedelta(days=7), timedelta(days=6), timedelta(seconds=1), timedelta(0)):
                world = self.world()
                raw = deepcopy(world.source_raw)
                prepared = world.prepare() if stage == "sign" else None
                expiry = pipeline.parse_time(pipeline.cr.parse_json(raw["manifest.raw.json"])["expiresAtUtc"])
                world.now = expiry - remaining
                with self.subTest(stage=stage, remaining=remaining):
                    if remaining > timedelta(0):
                        result = world.prepare() if stage == "prepare" else world.sign(prepared)
                        paths = pipeline.candidate_publication_paths(world.out, result["generation"])
                        self.assertEqual(result["generation"], world.generation + 1)
                        self.assertEqual(pipeline.cr.parse_json(paths["index.json"].read_bytes())["records"],
                                         pipeline.cr.parse_json(raw["index.json"])["records"])
                        self.assertEqual(pipeline.cr.parse_json(paths["manifest.raw.json"].read_bytes())["expiresAtUtc"],
                                         expiry.strftime("%Y-%m-%dT%H:%M:%SZ"))
                    else:
                        with self.assertRaisesRegex(ValueError, "CANDIDATE_(ORIGINAL_EXPIRY|EXPIRED)"):
                            world.prepare() if stage == "prepare" else world.sign(prepared)
                        self.assertEqual(sum(call[1].endswith("-sign") for call in world.calls), 0)
                self.assertEqual(world.source_raw, raw)
                self.assertTrue(all(event[0] == "GET" for event in world.remote.events))

    def test_publish_short_validity_and_expiry_preserve_original_signed_bundle(self):
        for remaining in (timedelta(days=7), timedelta(days=6), timedelta(seconds=1), timedelta(0)):
            world = self.world()
            prepared = world.prepare()
            signed = world.sign(prepared)
            paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
            envelope = paths["manifest.json"].read_bytes()
            raw = deepcopy(world.source_raw)
            expiry = pipeline.parse_time(pipeline.cr.parse_json(raw["manifest.raw.json"])["expiresAtUtc"])
            world.now = expiry - remaining
            with self.subTest(remaining=remaining):
                if remaining > timedelta(0):
                    self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
                else:
                    with self.assertRaisesRegex(ValueError, "CANDIDATE_EXPIRED"):
                        world.publish(prepared, signed)
                    self.assertEqual(world.remote.ref_updates, 0)
                    self.assertTrue(all(event[0] == "GET" for event in world.remote.events))
                    terminal = pipeline.cr.parse_json(next(world.out.glob("candidate-publish-*.terminal-*.json")).read_bytes())
                    self.assertEqual((terminal["status"], terminal["reason"]),
                                     ("UNKNOWN", "CANDIDATE_EXPIRED"))
            self.assertEqual(paths["manifest.json"].read_bytes(), envelope)
            self.assertEqual(world.source_raw, raw)
            self.assertEqual(sum(call[1].endswith("-sign") for call in world.calls), 1)

    def test_one_short_original_record_is_not_dropped_or_extended(self):
        world = self.world()
        raw = deepcopy(world.source_raw)
        index = pipeline.cr.parse_json(raw["index.json"])
        record = pipeline.cr.parse_json(base64.b64decode(index["records"][0]["recordBytesBase64"]))
        short_expiry = world.now + timedelta(seconds=1)
        record["acquisitionDescriptor"]["attestation"]["validUntilUtc"] = short_expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
        body = pipeline.canonical(record)
        index["records"][0] = {"recordBytesBase64": base64.b64encode(body).decode(), "recordSha256": pipeline.sha(body)}
        manifest = pipeline.cr.parse_json(raw["manifest.raw.json"])
        manifest["expiresAtUtc"] = record["acquisitionDescriptor"]["attestation"]["validUntilUtc"]
        expanded = pipeline.cr.json_bytes(index)
        packed = pipeline.candidate_publication_gzip(expanded)
        manifest["asset"].update(sizeBytes=len(packed), sha256=pipeline.sha(packed),
                                 tag="index-v1-20261024-" + pipeline.sha(packed))
        raw.update({"index.json": expanded, "index.json.gz": packed, "manifest.raw.json": pipeline.cr.json_bytes(manifest)})
        original = deepcopy(raw)
        pipeline.candidate_publication_validity(raw)
        world.source_raw = raw
        world.save_candidate()
        prepared = world.prepare()
        signed = world.sign(prepared)
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
        self.assertEqual(pipeline.cr.parse_json(paths["index.json"].read_bytes())["records"], index["records"])
        self.assertEqual(pipeline.cr.parse_json(paths["manifest.raw.json"].read_bytes())["expiresAtUtc"],
                         manifest["expiresAtUtc"])
        world.now = short_expiry
        with self.assertRaisesRegex(ValueError, "CANDIDATE_EXPIRED"):
            world.publish(prepared, signed)
        self.assertEqual(raw, original)
        self.assertEqual(len(pipeline.cr.parse_json(raw["index.json"])["records"]), 3)

    def test_expiry_after_immutable_upload_rejects_cas_and_keeps_signed_bytes(self):
        world = self.world()
        prepared = world.prepare()
        signed = world.sign(prepared)
        paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
        original = {name: paths[name].read_bytes() for name in ("manifest.json", "index.json.gz", "manifest.raw.json")}
        expiry = pipeline.parse_time(pipeline.cr.parse_json(original["manifest.raw.json"])["expiresAtUtc"])
        def expire(remote):
            if remote.events[-1][1] == pipeline.API + "/git/commits":
                remote.change_after_write = None
                world.now = expiry
        world.remote.change_after_write = expire
        with self.assertRaisesRegex(ValueError, "CANDIDATE_EXPIRED"):
            world.publish(prepared, signed)
        self.assertEqual(world.remote.ref_updates, 0)
        self.assertFalse(any(world.out.glob("candidate-publish-*.cas-intent.json")))
        self.assertEqual({name: paths[name].read_bytes() for name in original}, original)

    def test_current_clock_and_manifest_minimum_are_not_replaced_by_weekly_target(self):
        world = self.world()
        raw = deepcopy(world.source_raw)
        for now in (None, world.now.replace(tzinfo=None)):
            world.now = now
            with self.assertRaisesRegex(ValueError, "CANDIDATE_TIME_UNKNOWN"):
                pipeline.candidate_publication_validity(raw)
        manifest = pipeline.cr.parse_json(raw["manifest.raw.json"])
        world.now = pipeline.parse_time(manifest["publishedAtUtc"]) - timedelta(seconds=1)
        with self.assertRaisesRegex(ValueError, "CANDIDATE_EXPIRED"):
            pipeline.candidate_publication_validity(raw)
        world.now = pipeline.parse_time(manifest["publishedAtUtc"])
        manifest["expiresAtUtc"] = (world.now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        changed = dict(raw, **{"manifest.raw.json": pipeline.cr.json_bytes(manifest)})
        with self.assertRaisesRegex(ValueError, "CANDIDATE_MINIMUM_EXPIRY"):
            pipeline.candidate_publication_validity(changed)
        self.assertEqual(world.source_raw, raw)

    def test_original_signed_bundle_and_readback_only_keep_their_original_expiry(self):
        sign_world = self.world()
        sign_prepared = sign_world.prepare()
        sign_world.sign(sign_prepared)
        sign_expiry = pipeline.parse_time(pipeline.cr.parse_json(
            sign_world.source_raw["manifest.raw.json"])["expiresAtUtc"])
        sign_world.now = sign_expiry - timedelta(days=7)
        self.assertTrue(sign_world.sign(sign_prepared)["resumed"])
        self.assertEqual(sum(call[1].endswith("-sign") for call in sign_world.calls), 1)
        world = self.world()
        prepared = world.prepare()
        signed = world.sign(prepared)
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        paths = pipeline.candidate_publication_paths(world.out, prepared["generation"])
        original = {name: paths[name].read_bytes() for name in ("manifest.json", "index.json.gz", "manifest.raw.json")}
        expiry = pipeline.parse_time(pipeline.cr.parse_json(original["manifest.raw.json"])["expiresAtUtc"])
        world.now = expiry - timedelta(days=7)
        writes = [event for event in world.remote.events if event[0] != "GET"]
        self.assertEqual(world.publish(prepared, signed)["status"], "PUBLISHED")
        self.assertEqual([event for event in world.remote.events if event[0] != "GET"], writes)
        self.assertEqual(sum(call[1].endswith("-sign") for call in world.calls), 1)
        self.assertEqual({name: paths[name].read_bytes() for name in original}, original)
        world.now = expiry
        with self.assertRaisesRegex(ValueError, "CANDIDATE_EXPIRED"):
            world.publish(prepared, signed)


if __name__ == "__main__":
    unittest.main()
