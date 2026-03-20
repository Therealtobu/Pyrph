# Pyrph — Python Obfuscation Engine

Multi-layer Python obfuscator with custom bytecode VM and native C runtime.

## Features

| Layer | Techniques |
|-------|-----------|
| **L1 Surface** | Strip comments, rename identifiers (random names), string vault (16-byte keystream), number encoding, anti-debug scatter, junk injection |
| **L2 AST** | Import obfuscation, Mixed Boolean-Arithmetic (MBA), Fermat opaque predicates, Control Flow Flattening (random state IDs + fake states), dead code injection |
| **L3 VM** | PolyVM custom bytecode with per-build randomised opcode mapping |
| **L4 Native** | AES-128-CTR + rolling XOR + byte-permutation → C runtime `.so` loaded via `memfd_create` (never hits disk). Whitebox key storage, LLVM IR passes, split key, anti-debug in C, anti-dump wipe |
| **L5 Chaos** | Semicolon collapsing, whitespace removal, unicode noise comments |

## Install

```bash
pip install -r requirements.txt
```

For native pack (recommended): needs `gcc` or `clang` + Python headers.

```bash
# Debian/Ubuntu
sudo apt install gcc python3-dev

# Termux
pkg install clang python
```

## CLI Usage

```bash
# Default (balanced: L1+2+Native)
python cli.py script.py

# Strongest — all layers + C VM
python cli.py script.py --profile vm_max

# Fast — surface only, no native
python cli.py script.py --profile fast

# Custom
python cli.py script.py --profile balanced --mba-depth 4 --n-stubs 6

# Show pipeline without running
python cli.py script.py --dry-run
```

### Profiles

| Profile | Layers | Speed |
|---------|--------|-------|
| `fast` | L1 only | ~0.1s |
| `balanced` | L1+2+Native | ~1s |
| `max` | L1+2+PolyVM+Native | ~3s |
| `stealth` | Balanced, smaller output | ~1s |
| `vm` | L1+2+C VM Native | ~2s |
| `vm_max` | All layers + C VM | ~5s |

## Discord Bot

```bash
cp .env.example .env
# Edit .env: DISCORD_TOKEN=your_token

python bot.py
```

Slash commands:
- `/obfuscate` — upload `.py` → receive obfuscated file
- `/pyrph_info` — show engine info
- `/ping` — latency check

## Project Structure

```
pyrph/
├── core/           # ObfResult, ObfPass, Pipeline
├── vm/             # Custom bytecode VM (opcodes, compiler, encryptor)
├── native/         # C runtime, builder, whitebox AES
├── transforms/     # All obfuscation passes
├── phases/         # Unified pipeline builder
├── cli.py          # CLI entry point
├── bot.py          # Discord bot
└── requirements.txt
```

## Push to GitHub (Termux)

```bash
cd ~/downloads
unzip pyrph.zip
cd pyrph
git init
git add .
git commit -m "init: Pyrph Python obfuscator"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/pyrph.git
git push -u origin main
```
