#!/usr/bin/env python3
"""
Pyrph — Python Obfuscation Engine
Entry point: python -m pyrph  OR  pyrph  (after pip install)
"""
import sys
import os
import ast
import time
from pathlib import Path


# ── ANSI colors ───────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; DIM="\033[2m"
CY="\033[36m"; GR="\033[32m"; YL="\033[33m"; RD="\033[31m"; PU="\033[35m"


def _c(s, *codes): return "".join(codes)+s+R


# ── Banner ────────────────────────────────────────────────────────────────
BANNER = f"""
{CY}{B}  ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗  ██╗
  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██║  ██║
  ██████╔╝ ╚████╔╝ ██████╔╝██████╔╝███████║
  ██╔═══╝   ╚██╔╝  ██╔══██╗██╔═══╝ ██╔══██║
  ██║        ██║   ██║  ██║██║     ██║  ██║
  ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝{R}
{DIM}  Python Obfuscation Engine · v1.0.0{R}
"""


def _print_banner():
    print(BANNER)


def _print_hwid_screen(hwid: str):
    print(_c("  ┌─────────────────────────────────────────┐", DIM))
    print(_c("  │           MACHINE IDENTIFIER            │", DIM))
    print(_c("  └─────────────────────────────────────────┘", DIM))
    print()
    print(f"  {DIM}Your HWID:{R}")
    print(f"  {CY}{B}{hwid}{R}")
    print()
    print(f"  {DIM}To use Pyrph, you need a key:{R}")
    print(f"  {GR}▸ Free key  {R}{DIM}→  Visit: {R}{CY}https://pyrph.vercel.app/getkey{R}")
    print(f"  {YL}▸ Paid key  {R}{DIM}→  Visit: {R}{CY}https://pyrph.vercel.app{R}")
    print()
    print(f"  {DIM}Already have a key? Run:{R}")
    print(f"  {CY}pyrph --activate <your-key>{R}")
    print()


def _print_tier_screen(tier: str, expires_at=None):
    if tier == "paid":
        icon  = f"{GR}●{R}"
        label = f"{GR}{B}PAID{R}"
        info  = f"{GR}Full access · Lifetime · Native + PolyVM + NestedVM{R}"
    else:
        icon  = f"{YL}●{R}"
        label = f"{YL}{B}FREE{R}"
        exp   = f" · Expires after this run" if expires_at else ""
        info  = f"{YL}Limited access · PolyVM only · 1 obfuscation{R}{exp}"

    print(f"  {icon} Status: {label}")
    print(f"  {DIM}{info}{R}")
    print()


def _prompt_file() -> str:
    print(f"  {DIM}Enter the Python file to obfuscate:{R}")
    try:
        path = input(f"  {CY}▸ File path: {R}").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sys.exit(0)
    return path


def _run_obf(filepath: str, tier: str, key: str):
    src_path = Path(filepath)

    if not src_path.exists():
        print(f"\n  {RD}✗ File not found: {filepath}{R}")
        sys.exit(1)

    if not filepath.endswith(".py"):
        print(f"\n  {RD}✗ Only .py files supported.{R}")
        sys.exit(1)

    size_kb = src_path.stat().st_size / 1024
    if tier == "free" and size_kb > 50:
        print(f"\n  {RD}✗ Free tier limited to 50KB. Your file: {size_kb:.1f}KB{R}")
        print(f"  {YL}Upgrade to paid for unlimited file size.{R}")
        sys.exit(1)

    # Determine profile and options based on tier
    if tier == "paid":
        profile = "balanced"
        opts = dict(native=True, use_vm=True, vm_mode=False)
    else:
        # Free: PolyVM only, no Nested, no Native
        profile = "balanced"
        opts = dict(native=False, use_vm=True, vm_mode=False,
                    layer2=True, cff=True, mba=True)

    print(f"\n  {DIM}Reading {src_path.name} ({size_kb:.1f}KB)...{R}")
    source = src_path.read_text(encoding="utf-8")

    print(f"  {DIM}Building pipeline [{profile}]...{R}\n")

    try:
        from pyrph.phases.unified import build_pipeline
        p       = build_pipeline(profile=profile, **opts)
        t0      = time.time()
        results = p.run(source)
        elapsed = time.time() - t0
        final   = results[-1].code
    except Exception as e:
        print(f"  {RD}✗ Obfuscation failed: {e}{R}")
        sys.exit(1)

    # Print pass results
    for r in results:
        icon = f"{GR}✓{R}" if r.success else f"{RD}✗{R}"
        msg  = f"{DIM}{r.message}{R}" if r.message else ""
        print(f"  {icon}  {r.pass_name:<22} {msg}")

    # Validate output
    try:
        ast.parse(final)
    except SyntaxError as e:
        print(f"\n  {RD}✗ Output syntax error: {e}{R}")
        sys.exit(1)

    # Save output
    out_path = src_path.with_stem(src_path.stem + "_obf")
    out_path.write_text(final, encoding="utf-8")

    in_l  = len(source.splitlines())
    out_l = len(final.splitlines())

    print(f"\n  {GR}✓ Done in {elapsed:.2f}s{R}")
    print(f"  {DIM}Lines: {in_l} → {out_l}  ·  Size: {size_kb:.1f}KB → {len(final.encode())/1024:.1f}KB{R}")
    print(f"  {CY}Saved: {out_path}{R}\n")

    # Mark free key as used (one-shot)
    if tier == "free":
        try:
            from pyrph.key.client import mark_used
            mark_used(key)
            print(f"  {YL}⚠ Free key expired. Get a new one at pyrph.vercel.app/getkey{R}\n")
        except Exception:
            pass


def main():
    _print_banner()

    args = sys.argv[1:]

    # ── --activate <key> ──────────────────────────────────────────────────
    if "--activate" in args or "-a" in args:
        try:
            idx = args.index("--activate") if "--activate" in args else args.index("-a")
            key = args[idx + 1]
        except IndexError:
            print(f"  {RD}Usage: pyrph --activate <key>{R}")
            sys.exit(1)

        print(f"  {DIM}Activating key...{R}")
        from pyrph.key.client import activate
        result = activate(key)
        if result.get("ok"):
            tier = result.get("tier", "free")
            print(f"  {GR}✓ Activated! Tier: {tier.upper()}{R}")
            if tier == "paid":
                print(f"  {GR}Full access unlocked. Run: pyrph{R}")
            else:
                print(f"  {YL}Free access. Run: pyrph{R}")
        else:
            print(f"  {RD}✗ {result.get('error') or result.get('detail', 'Activation failed')}{R}")
        sys.exit(0)

    # ── --getkey ──────────────────────────────────────────────────────────
    if "--getkey" in args:
        from pyrph.key.hwid import get_hwid
        from pyrph.key.client import getkey_request
        hwid = get_hwid()
        print(f"  {DIM}Requesting free key for HWID: {hwid[:16]}...{R}")
        result = getkey_request(hwid)
        if result.get("ok"):
            key = result["key"]
            print(f"  {GR}✓ Key generated:{R}")
            print(f"  {CY}{B}{key}{R}")
            print(f"\n  {DIM}Activate it:{R} {CY}pyrph --activate {key}{R}")
        else:
            print(f"  {RD}✗ {result.get('error','Failed')}{R}")
            print(f"  {DIM}Or visit: https://pyrph.vercel.app/getkey{R}")
        sys.exit(0)

    # ── --logout ──────────────────────────────────────────────────────────
    if "--logout" in args:
        from pyrph.key.client import delete_key
        delete_key()
        print(f"  {GR}✓ Key removed.{R}")
        sys.exit(0)

    # ── Main flow ─────────────────────────────────────────────────────────
    from pyrph.key.hwid    import get_hwid
    from pyrph.key.client  import verify, load_key

    hwid = get_hwid()
    key  = load_key() or os.environ.get("PYRPH_KEY")

    if not key:
        _print_hwid_screen(hwid)
        sys.exit(0)

    # Verify key
    print(f"  {DIM}Verifying key...{R}", end="", flush=True)
    result = verify(key)
    print(f"\r  ", end="")

    if not result.get("ok"):
        err = result.get("error", "unknown")
        if err == "offline":
            print(f"  {YL}⚠ Offline — using cached license.{R}")
        elif err in ("expired", "Key expired."):
            print(f"  {RD}✗ Key expired.{R}")
            from pyrph.key.client import delete_key
            delete_key()
            _print_hwid_screen(hwid)
            sys.exit(1)
        else:
            print(f"  {RD}✗ {err}{R}")
            _print_hwid_screen(hwid)
            sys.exit(1)
        # Try cached result
        result = {"ok": True, "tier": "free", "features": None}

    tier       = result.get("tier", "free")
    expires_at = result.get("expires_at")

    _print_tier_screen(tier, expires_at)

    # Prompt for file
    filepath = _prompt_file()
    if not filepath:
        print(f"  {RD}No file entered.{R}")
        sys.exit(1)

    _run_obf(filepath, tier, key)


if __name__ == "__main__":
    main()
