"""Extract the API 34 Google Play vendor partition for isolated NUMA patching."""

import hashlib
from pathlib import Path


SOURCE = (
    Path.home()
    / "AppData/Local/Android/Sdk/system-images/android-34/google_apis_playstore/x86_64/system.img"
)
OUTPUT = (
    Path.home()
    / "AppData/Local/android-device-lab/playstore-numa-hybrid/vendor-stock-partition.img"
)
EXPECTED_SOURCE_SHA256 = "4c0231879770f9ef3a4f33ef317ccf6a123b16e198ecab0e9ce76b9efc1f7da0"
OFFSET = 875560960
SIZE = 95346688


def main():
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    with SOURCE.open("rb") as image:
        if hashlib.file_digest(image, "sha256").hexdigest() != EXPECTED_SOURCE_SHA256:
            raise ValueError("Unsupported Google Play system image revision")
        image.seek(OFFSET + 1080)
        if image.read(2) != b"\x53\xef":
            raise ValueError("Unexpected vendor partition offset")
        image.seek(OFFSET)
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT.open("wb") as partition:
            remaining = SIZE
            while remaining:
                chunk = image.read(min(4 * 1024 * 1024, remaining))
                if not chunk:
                    raise EOFError(SOURCE)
                partition.write(chunk)
                remaining -= len(chunk)
    print(OUTPUT)


if __name__ == "__main__":
    main()
