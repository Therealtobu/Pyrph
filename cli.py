#!/usr/bin/env python3
"""
Pyrph — Python Obfuscation Engine
==================================
Usage:
    python cli.py script.py
    python cli.py script.py --profile max
    python cli.py script.py --profile vm
    python cli.py script.py --profile fast --print
    python cli.py script.py -o output.py --profile balanced
    python cli.py script.py --dry-run
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from pyrph.phases.unified import build_pipeline


def _banner():
    print("\033[36m"
          "  ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗  ██╗\n"
          "  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██║  ██║\n"
          "  ██████╔╝ ╚████╔╝ ██████╔╝██████╔╝███████║\n"
          "  ██╔═══╝   ╚██╔╝  ██╔══██╗██╔═══╝ ██╔══██║\n"
          "  ██║        ██║   ██║  ██║██║     ██║  ██║\n"
          "  ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝\033[0m\n"
          "  \033[90mPython Obfuscation Engine · VM + Native + MBA\033[0m\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyrph",
        description="Pyrph — Python Obfuscation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("input", metavar="INPUT", help="Python source file to obfuscate")
    p.add_argument("-o","--output", metavar="OUTPUT", help="Output path (default: input_obf.py)")

    # Profile
    p.add_argument("--profile", default="balanced",
                   choices=["fast","balanced","max","stealth","vm","vm_max"],
                   help="Protection profile (default: balanced)")

    # Layer 1
    g1 = p.add_argument_group("Layer 1 — Surface")
    g1.add_argument("--no-strip",       dest="strip",       action="store_false", default=True)
    g1.add_argument("--no-rename",      dest="rename",      action="store_false", default=True)
    g1.add_argument("--no-numbers",     dest="number_enc",  action="store_false", default=True)
    g1.add_argument("--no-vault",       dest="string_vault",action="store_false", default=True)
    g1.add_argument("--no-anti-debug",  dest="anti_debug",  action="store_false", default=True)
    g1.add_argument("--no-junk",        dest="junk",        action="store_false", default=True)
    g1.add_argument("--no-scatter",     dest="scatter",     action="store_false", default=True)
    g1.add_argument("--n-stubs",        type=int, default=4, metavar="N")
    g1.add_argument("--n-sentinels",    type=int, default=3, metavar="N")
    g1.add_argument("--junk-density",   type=float, default=0.15, metavar="F")
    g1.add_argument("--number-density", type=float, default=0.85, metavar="F")
    g1.add_argument("--vault-min-len",  type=int,   default=3,    metavar="N")

    # Layer 2
    g2 = p.add_argument_group("Layer 2 — AST")
    g2.add_argument("--no-layer2",   dest="layer2",     action="store_false", default=True)
    g2.add_argument("--no-import",   dest="import_obf", action="store_false", default=True)
    g2.add_argument("--no-mba",      dest="mba",        action="store_false", default=True)
    g2.add_argument("--no-opaque",   dest="opaque",     action="store_false", default=True)
    g2.add_argument("--no-cff",      dest="cff",        action="store_false", default=True)
    g2.add_argument("--no-dead",     dest="dead_code",  action="store_false", default=True)
    g2.add_argument("--mba-depth",   type=int,   default=3,    metavar="N")
    g2.add_argument("--mba-density", type=float, default=0.55, metavar="F")
    g2.add_argument("--opaque-density", type=float, default=0.35, metavar="F")
    g2.add_argument("--dead-density",   type=float, default=0.25, metavar="F")
    g2.add_argument("--n-fake-states",  type=int,   default=2,    metavar="N")

    # Layer 3/4
    g4 = p.add_argument_group("Layer 3/4 — VM + Native")
    g4.add_argument("--vm-mode",   dest="vm_mode", action="store_true",  default=False,
                    help="Use C VM executor instead of PyEval_EvalCode")
    g4.add_argument("--use-vm",    dest="use_vm",  action="store_true",  default=False,
                    help="Compile through PolyVM before native pack")
    g4.add_argument("--no-native", dest="native",  action="store_false", default=True)
    g4.add_argument("--n-key-frags",type=int,  default=3, metavar="N")
    g4.add_argument("--fake-file", default="<frozen importlib._bootstrap>", metavar="S")
    g4.add_argument("--no-scrub",  dest="scrub_names", action="store_false", default=True)

    # Layer 5
    g5 = p.add_argument_group("Layer 5 — Chaos")
    g5.add_argument("--no-chaos",     dest="chaos",      action="store_false", default=True)
    g5.add_argument("--chaos-noise",  type=float, default=0.07, metavar="F")
    g5.add_argument("--chaos-len",    type=int,   default=180,  metavar="N")

    # Misc
    p.add_argument("--dry-run",   action="store_true", help="Show pipeline summary only")
    p.add_argument("--print",     dest="print_output", action="store_true")
    p.add_argument("--no-banner", dest="banner", action="store_false", default=True)
    p.add_argument("-q","--quiet", action="store_true")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.quiet and args.banner:
        _banner()

    opts = dict(
        profile=args.profile,
        strip=args.strip, rename=args.rename,
        number_enc=args.number_enc, number_density=args.number_density,
        string_vault=args.string_vault, vault_min_len=args.vault_min_len,
        anti_debug=args.anti_debug, n_stubs=args.n_stubs,
        scatter=args.scatter, n_sentinels=args.n_sentinels,
        junk=args.junk, junk_density=args.junk_density,
        layer2=args.layer2, import_obf=args.import_obf,
        mba=args.mba, mba_depth=args.mba_depth, mba_density=args.mba_density,
        mba_constants=True,
        opaque=args.opaque, opaque_density=args.opaque_density,
        dead_code=args.dead_code, dead_density=args.dead_density,
        cff=args.cff, n_fake_states=args.n_fake_states,
        vm_mode=args.vm_mode, use_vm=args.use_vm,
        native=args.native, n_key_frags=args.n_key_frags,
        fake_file=args.fake_file, scrub_names=args.scrub_names,
        chaos=args.chaos, chaos_noise=args.chaos_noise,
        chaos_max_len=args.chaos_len,
    )

    pipeline = build_pipeline(**opts)

    if args.dry_run:
        print(pipeline.summary()); sys.exit(0)

    try:
        source = Path(args.input).read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError) as e:
        print(f"\033[31m✗ {e}\033[0m"); sys.exit(1)

    if not args.quiet:
        print(f"\033[90m  Input : {args.input} ({len(source.splitlines())} lines)\033[0m")

    results = pipeline.run(source)
    final   = results[-1].code

    if not args.quiet:
        for r in results:
            icon = "\033[32m✓\033[0m" if r.success else "\033[31m✗\033[0m"
            print(f"  {icon}  \033[90m{r.pass_name:<20}\033[0m  {r.message}")
        in_l  = len(source.splitlines())
        out_l = len(final.splitlines())
        print(f"\n  \033[36m{in_l} → {out_l} lines  ({len(final):,} chars)\033[0m")

    out_path = (Path(args.output) if args.output
                else Path(args.input).with_stem(Path(args.input).stem + "_obf"))

    try:
        out_path.write_text(final, encoding="utf-8")
    except Exception as e:
        print(f"\033[31m✗ Write failed: {e}\033[0m"); sys.exit(1)

    if not args.quiet:
        print(f"  \033[32m✓ Saved: {out_path}\033[0m\n")

    if args.print_output:
        print("─"*60); print(final); print("─"*60)


if __name__ == "__main__":
    main()
