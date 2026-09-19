#!/bin/sh
# Fail when a binary asset has slipped into the tree.
#
# This repository ships code and documentation only. No images, audio, fonts,
# archives, compiled objects or saved data belong here, so the guard lists the
# extensions to reject and then sniffs every remaining file for binary bytes.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

pattern='\.(png|jpg|jpeg|gif|webp|bmp|ico|icns|svg|mp3|wav|ogg|flac|m4a|mp4|mkv|webm|avi|ttf|otf|woff|woff2|eot|zip|tar|gz|bz2|xz|7z|rar|jar|whl|so|dylib|dll|exe|bin|pyc|pyo|class|o|a|db|sqlite|sqlite3|pdf|docx|xlsx|pptx|epub|nes|nds|gba|sav)$'

found=$(find . -type f -not -path './.git/*' | grep -Ei "$pattern" || true)

if [ -n "$found" ]; then
    echo "check-no-media: these files must not be committed:" >&2
    echo "$found" >&2
    exit 1
fi

binary=$(find . -type f -not -path './.git/*' -size -2M -exec python3 -c '
import sys
for path in sys.argv[1:]:
    try:
        with open(path, "rb") as handle:
            blob = handle.read(4096)
    except OSError:
        continue
    if b"\x00" in blob:
        print(path)
' {} + || true)

if [ -n "$binary" ]; then
    echo "check-no-media: these files contain binary data:" >&2
    echo "$binary" >&2
    exit 1
fi

echo "check-no-media: clean"
