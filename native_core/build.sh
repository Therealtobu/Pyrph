#!/usr/bin/env bash
# Build pyrph_core.so for Linux x86_64 (Railway, Render, Fly.io compatible)
# Run this on your dev machine, then upload the .so with bot.py

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[pyrph] Building native core..."

# Build release binary
cargo build --release

# Find and copy the .so
SO_PATH=$(find target/release -name "pyrph_core*.so" -o \
                               -name "pyrph_core*.dylib" -o \
                               -name "pyrph_core*.pyd" 2>/dev/null | head -1)

if [ -z "$SO_PATH" ]; then
    echo "[pyrph] ERROR: no .so found in target/release/"
    exit 1
fi

DEST="../pyrph_core.so"
cp "$SO_PATH" "$DEST"
echo "[pyrph] Built: $DEST"
echo "[pyrph] Size: $(du -h $DEST | cut -f1)"
echo ""
echo "[pyrph] Upload pyrph_core.so alongside bot.py"
echo "[pyrph] The .so is statically linked — no Rust runtime needed on server"
