"""Local acceptance configure専用。公開pinを一度読んだ不変byteへ結合する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


PUBLIC_BLOB_BYTES = 411
PUBLIC_BLOB_PREFIX = bytes.fromhex(
    "52534131000c000003000000800100000000000000000000010001"
)


def read_public_pin(public_blob: Path, fingerprint: str) -> dict[str, str]:
    """同じimmutable snapshotでshape・完全SHA-256・埋込みHEXを決定する。"""
    if not public_blob.is_absolute():
        raise ValueError("An explicit absolute public blob is required.")
    if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise ValueError("An exact lowercase SHA256 public fingerprint is required.")
    # 一つのhandleから上限+1を読み、巨大入力と余分なprivate fieldを拒否する。
    with public_blob.open("rb") as stream:
        snapshot = stream.read(PUBLIC_BLOB_BYTES + 1)
    if len(snapshot) != PUBLIC_BLOB_BYTES:
        raise ValueError("Only a complete RSA3072 public blob is allowed.")
    if not snapshot.startswith(PUBLIC_BLOB_PREFIX):
        raise ValueError("RSA3072, exponent65537 and no private fields are required.")
    actual_fingerprint = hashlib.sha256(snapshot).hexdigest()
    if actual_fingerprint != fingerprint:
        raise ValueError("Local public fingerprint does not match the reviewed pin.")
    return {"fingerprint": actual_fingerprint, "hex": snapshot.hex()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-blob", required=True, type=Path)
    parser.add_argument("--fingerprint", required=True)
    arguments = parser.parse_args()
    try:
        pin = read_public_pin(arguments.public_blob, arguments.fingerprint)
    except (OSError, ValueError) as error:
        print("Local public pin rejected: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(pin, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
