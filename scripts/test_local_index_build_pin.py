"""同byte configure pinの決定的な正負と条件変更を検証する。実鍵を扱わない。"""

from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import local_index_build_pin as pin


class LocalIndexBuildPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.first = pin.PUBLIC_BLOB_PREFIX + bytes([0x81]) * 384
        self.other = self.first[:-1] + bytes([0x83])
        self.fingerprint = hashlib.sha256(self.first).hexdigest()
        self.absolute = Path("D:/synthetic-public-only.blob")

    def test_same_snapshot_supplies_hash_and_embedding(self) -> None:
        with patch.object(Path, "open", return_value=io.BytesIO(self.first)) as opened:
            result = pin.read_public_pin(self.absolute, self.fingerprint)
        opened.assert_called_once_with("rb")
        self.assertEqual(bytes.fromhex(result["hex"]), self.first)
        self.assertEqual(hashlib.sha256(bytes.fromhex(result["hex"])).hexdigest(), result["fingerprint"])

    def test_path_change_after_read_does_not_replace_verified_bytes(self) -> None:
        # stream.read返却後、hash開始前にpathを実際に別byteへ変更する。timingを使わない。
        with tempfile.TemporaryDirectory() as temporary:
            selected = Path(temporary) / "selected.blob"
            selected.write_bytes(self.first)
            original_sha256 = hashlib.sha256

            def change_path_before_hash(snapshot: bytes):
                selected.write_bytes(self.other)
                return original_sha256(snapshot)

            with patch.object(pin.hashlib, "sha256", side_effect=change_path_before_hash):
                result = pin.read_public_pin(selected, self.fingerprint)
            self.assertEqual(selected.read_bytes(), self.other)
            self.assertEqual(bytes.fromhex(result["hex"]), self.first)
            self.assertEqual(result["fingerprint"], self.fingerprint)

    def test_different_bytes_before_read_are_rejected(self) -> None:
        with patch.object(Path, "open", return_value=io.BytesIO(self.other)):
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                pin.read_public_pin(self.absolute, self.fingerprint)

    def test_wrong_full_fingerprint_is_rejected(self) -> None:
        with patch.object(Path, "open", return_value=io.BytesIO(self.first)):
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                pin.read_public_pin(self.absolute, "0" * 64)

    def test_wrong_lengths_and_shapes_are_rejected(self) -> None:
        cases = [self.first[:-1], self.first + b"\x00"]
        for offset in (0, 4, 8, 12, 16, 20, 24):
            changed = bytearray(self.first)
            changed[offset] ^= 1
            cases.append(bytes(changed))
        for snapshot in cases:
            with self.subTest(length=len(snapshot), prefix=snapshot[:27].hex()):
                with patch.object(Path, "open", return_value=io.BytesIO(snapshot)):
                    with self.assertRaises(ValueError):
                        pin.read_public_pin(self.absolute, hashlib.sha256(snapshot).hexdigest())

    def test_nonabsolute_and_noncanonical_fingerprint_are_rejected_before_read(self) -> None:
        for selected, expected in ((Path("relative.blob"), self.fingerprint),
                                   (self.absolute, self.fingerprint.upper()),
                                   (self.absolute, "0" * 63),
                                   (self.absolute, "g" * 64)):
            with self.subTest(selected=str(selected), expected=expected):
                with patch.object(Path, "open") as opened:
                    with self.assertRaises(ValueError):
                        pin.read_public_pin(selected, expected)
                    opened.assert_not_called()

    def test_read_is_bounded_to_exact_size_plus_one(self) -> None:
        stream = io.BytesIO(self.first + b"\x00" * 65536)
        with patch.object(stream, "read", wraps=stream.read) as bounded_read:
            with patch.object(Path, "open", return_value=stream):
                with self.assertRaises(ValueError):
                    pin.read_public_pin(self.absolute, self.fingerprint)
            bounded_read.assert_called_once_with(pin.PUBLIC_BLOB_BYTES + 1)


if __name__ == "__main__":
    unittest.main()
