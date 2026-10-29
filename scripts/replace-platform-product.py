"""Replace one validated product extent in an isolated emulator disk image."""

import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path


SOURCE_SHA256 = "4806fbc745cd9abbfacc358496508f0ce420010e0ddaccef11e52e5da8e92f0a"
ORIGINAL_PRODUCT_SHA256 = "e091157520e9f7e892021dd49af10f6a31c84e0b6fad014686ddc9afc58b1415"
REPLACEMENT_SHA256 = {
    "6363b9fb0075dce5ade2bf517becd04e12f22a6cf6b647638620038772c874cb",
    "4549353f9413bf5a7933c65585423f78a1a3d5c8851fb4fb96cc7f495925b9bd",
}
SUPER_OFFSET = 2_097_152
PRODUCT_SECTOR = 2_070_528
PRODUCT_SIZE = 1_938_083_840
PRODUCT_OFFSET = SUPER_OFFSET + PRODUCT_SECTOR * 512


def digest(path, offset=0, size=None):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = path.stat().st_size - offset if size is None else size
        while remaining:
            chunk = stream.read(min(4 * 1024 * 1024, remaining))
            if not chunk:
                raise ValueError("Truncated image extent")
            result.update(chunk)
            remaining -= len(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("replacement", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if digest(args.source) != SOURCE_SHA256:
        raise ValueError("Unexpected platform disk image")
    if digest(args.source, PRODUCT_OFFSET, PRODUCT_SIZE) != ORIGINAL_PRODUCT_SHA256:
        raise ValueError("Unexpected original product extent")
    replacement_sha256 = digest(args.replacement)
    if replacement_sha256 not in REPLACEMENT_SHA256:
        raise ValueError("Unexpected replacement product image")
    with args.replacement.open("rb") as replacement:
        replacement.seek(1024)
        superblock = replacement.read(1024)
    blocks = struct.unpack_from("<I", superblock, 4)[0]
    if superblock[56:58] != b"\x53\xef" or blocks * 4096 != args.replacement.stat().st_size:
        raise ValueError("Replacement is not the expected resized ext4 filesystem")
    if args.replacement.stat().st_size > PRODUCT_SIZE:
        raise ValueError("Replacement exceeds the original product extent")

    with args.source.open("rb") as source, args.output.open("xb") as output:
        shutil.copyfileobj(source, output, 4 * 1024 * 1024)
    with args.output.open("r+b") as output, args.replacement.open("rb") as replacement:
        output.seek(PRODUCT_OFFSET)
        shutil.copyfileobj(replacement, output, 4 * 1024 * 1024)
        output.write(b"\0" * (PRODUCT_SIZE - args.replacement.stat().st_size))
    if digest(args.output, PRODUCT_OFFSET, args.replacement.stat().st_size) != replacement_sha256:
        raise ValueError("Written product extent differs from the replacement")
    print(json.dumps({"source_sha256": SOURCE_SHA256, "replacement_sha256": replacement_sha256,
                      "output": str(args.output), "output_sha256": digest(args.output),
                      "product_offset": PRODUCT_OFFSET, "product_extent_size": PRODUCT_SIZE}))


if __name__ == "__main__":
    main()
