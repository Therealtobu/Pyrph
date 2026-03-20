"""
phases/unified.py
==================
Unified pipeline — all protection layers in one call.

Profiles
--------
  fast      Layer 1 only (surface transforms, no VM/native)
  balanced  Layer 1+2 + Native (default)
  max       Layer 1+2 + PolyVM + Native
  stealth   balanced, smaller output
  vm        Layer 1+2 + C VM native (no marshal)
  vm_max    Layer 1+2 + PolyVM + C VM native

Layers
------
  1 — Surface   : strip, rename, string_vault, number_enc, anti_debug, junk
  2 — AST       : import_obf, mba, opaque, cff, dead_code
  3 — VM        : PolyVM bytecode compilation
  4 — Native    : AES+XOR+perm encrypt → C runtime .so via memfd_create
  5 — Chaos     : visual chaos formatting (always last)
"""
from __future__ import annotations
import ast
import base64
import random
from typing import Optional

from ..core.pipeline import Pipeline
from ..transforms import (
    StripPass, RenamePass, StringVaultPass, NumberEncPass,
    AntiDebugPass, AntiDumpPass, JunkPass, ImportObfPass, MBAPass,
    OpaquePass, CFFPass, DeadCodePass, ExprExplodePass, ChaosPass,
)


_PROFILES = {
    "fast":    dict(use_vm=False, native=False, layer2=False, vm_mode=False),
    "balanced":dict(use_vm=False, native=True,  layer2=True,  vm_mode=False),
    "max":     dict(use_vm=True,  native=True,  layer2=True,  vm_mode=False),
    "stealth": dict(use_vm=False, native=True,  layer2=True,  vm_mode=False,
                    junk_density=0.05, n_stubs=2, mba_density=0.3,
                    opaque_density=0.15, dead_density=0.10),
    "vm":      dict(use_vm=False, native=True,  layer2=True,  vm_mode=True),
    "vm_max":  dict(use_vm=True,  native=True,  layer2=True,  vm_mode=True),
}


def _obf_str(s: str, rng: random.Random) -> str:
    raw  = s.encode()
    mask = [rng.randint(1,254) for _ in raw]
    xord = [b^m for b,m in zip(raw,mask)]
    return f"bytes(a^b for a,b in zip({mask},{xord})).decode()"


def _make_enc_obj_lines(obj, varname: str, b64_mod: str, rng: random.Random) -> list:
    raw   = repr(obj).encode("utf-8")
    key   = [rng.randint(1,254) for _ in raw]
    enc   = bytes(b^k for b,k in zip(raw,key))
    b64   = base64.b64encode(enc).decode("ascii")
    f1    = [rng.randint(0,255) for _ in key]
    f2    = [key[i]^f1[i] for i in range(len(key))]
    vb = "_"+_rn(); vf1="_"+_rn(); vf2="_"+_rn()
    vk = "_"+_rn(); vr = "_"+_rn()
    return [
        f"{vb}={repr(b64)}",
        f"{vf1}={repr(f1)}",
        f"{vf2}={repr(f2)}",
        f"{vk}=[_x^_y for _x,_y in zip({vf1},{vf2})]",
        f"{vr}=bytes(_b^_k for _b,_k in zip({b64_mod}.b64decode({vb}),{vk})).decode('utf-8')",
        f"{varname}=eval({vr})",
    ]


def _rn(n=7) -> str:
    import string
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0,n-1)
    return raw[:pos]+random.choice(letters)+raw[pos:]


def _so_sha256(so_b64: str) -> str:
    import base64, hashlib
    return hashlib.sha256(base64.b64decode(so_b64)).hexdigest()


def _split_list(lst, n, rng):
    size=max(1,len(lst)//n); parts=[]
    for i in range(n):
        s=i*size; e=s+size if i<n-1 else len(lst)
        parts.append(lst[s:e])
    return [p for p in parts if p]


def _gen_launcher(enc_b64, so_b64, frags, step, inv_perm, orig_len,
                  nonce, fake_file, seed, n_stubs,
                  extra_lines=None, call_fn="decrypt_exec",
                  extra_call="") -> str:
    rng  = random.Random(seed)
    vb64 = "_"+_rn(); vct = "_"+_rn(); vos = "_"+_rn()
    vsys = "_"+_rn(); vim = "_"+_rn(); vmach = "_"+_rn()
    vso  = "_"+_rn(); venc = "_"+_rn()
    vfd  = "_"+_rn(); vpath = "_"+_rn(); vspec = "_"+_rn()
    vmod = "_"+_rn(); vglobs = "_"+_rn()
    vstep= "_"+_rn(); volen = "_"+_rn(); vperm = "_"+_rn()
    vnonce= "_"+_rn(); vraw = "_"+_rn()

    kfvars  = ["_"+_rn() for _ in frags]
    psplit  = _split_list(inv_perm, 3, rng)
    pfvars  = ["_"+_rn() for _ in psplit]

    # obfuscated sensitive strings
    libc_e  = _obf_str("libc.so.6",    rng)
    mfd_e   = _obf_str("memfd_create", rng)
    pfd_e   = _obf_str("/proc/self/fd/", rng)
    mod_e   = _obf_str("_pyrph",       rng)
    tag_e   = _obf_str("_p",           rng)

    # nonce XOR mask
    mask    = bytes(rng.randint(0,255) for _ in range(16))
    xored   = bytes(a^b for a,b in zip(nonce, mask))
    vmask   = "_"+_rn(); vxor = "_"+_rn()

    # so hash
    so_hash = _so_sha256(so_b64)

    vlibc   = "_"+_rn(); vlibcn = "_"+_rn(); vmfdn = "_"+_rn()

    lines = [
        f"import base64 as {vb64},ctypes as {vct},os as {vos},"
        f"sys as {vsys},importlib.util as {vim},"
        f"importlib.machinery as {vmach}",
    ]

    for _ in range(n_stubs):
        vt = "_"+_rn()
        lines.append(
            f"try:\n import sys as {vt}\n"
            f" if {vt}.gettrace() is not None:raise RuntimeError()\n"
            f"except RuntimeError:raise\nexcept:pass"
        )

    for var,frag in zip(kfvars,frags): lines.append(f"{var}={repr(frag)}")
    for var,part in zip(pfvars,psplit): lines.append(f"{var}={repr(part)}")
    lines.append(f"{vperm}={'+'.join(pfvars)}")
    lines += [
        f"{vmask}=bytes({list(mask)})",
        f"{vxor}=bytes({list(xored)})",
        f"{vnonce}=bytes(a^b for a,b in zip({vmask},{vxor}))",
        f"{vstep}={repr(step)}",
        f"{volen}={repr(orig_len)}",
        f"{venc}={vb64}.b64decode({repr(enc_b64)})",
        f"{vraw}={vb64}.b64decode({repr(so_b64)})",
        # integrity check
        f"_vh={_obf_str(so_hash, rng)}",
        f"_vg=__import__('hashlib').sha256({vraw}).hexdigest()",
        f"if _vg!=_vh:raise ImportError({_obf_str('cannot import', rng)})",
        # load via memfd
        f"{vlibcn}={libc_e}",
        f"{vlibc}={vct}.CDLL({vlibcn})",
        f"{vmfdn}={mfd_e}",
        f"getattr({vlibc},{vmfdn}).restype={vct}.c_int",
        f"getattr({vlibc},{vmfdn}).argtypes=[{vct}.c_char_p,{vct}.c_uint]",
        f"{vfd}=getattr({vlibc},{vmfdn})({tag_e}.encode(),1)",
        f"{vos}.write({vfd},{vraw})",
        f"_pfd={pfd_e}",
        f"{vpath}=_pfd+str({vfd})",
        f"_mn={mod_e}",
        f"{vspec}={vim}.spec_from_loader(_mn,{vmach}.ExtensionFileLoader(_mn,{vpath}))",
        f"{vmod}={vim}.module_from_spec({vspec})",
        f"{vspec}.loader.exec_module({vmod})",
        f"{vglobs}=(__builtins__ if isinstance(__builtins__,dict) else vars(__builtins__)).copy()",
        f"{vglobs}['__name__']=__name__",
        f"{vglobs}['__file__']={repr(fake_file)}",
    ]

    if extra_lines:
        lines.extend(extra_lines)

    call = (
        f"{vmod}.{call_fn}("
        f"{venc},[{','.join(kfvars)}],{vstep},{vperm},{volen},{vnonce}"
        f"{','+extra_call if extra_call else ''},"
        f"{repr(fake_file)},{vglobs})"
    )
    lines += [call, f"try: {vos}.close({vfd})", "except: pass"]
    return "\n".join(lines)+"\n"


def build_pipeline(**opts) -> Pipeline:
    """
    Build and return a Pipeline configured according to opts.
    See module docstring for available profile/option keys.
    """
    profile = _PROFILES.get(opts.get("profile","balanced"), _PROFILES["balanced"]).copy()
    o = {**profile, **opts}
    def flag(k, default=True): return o.get(k, default)

    p = Pipeline()

    # Layer 1
    p.add(StripPass(enabled=flag("strip")))
    p.add(RenamePass(enabled=flag("rename"), prefix=o.get("prefix","_")))
    p.add(NumberEncPass(enabled=flag("number_enc"), density=o.get("number_density",0.85)))
    p.add(StringVaultPass(enabled=flag("string_vault"), min_len=o.get("vault_min_len",3)))
    p.add(AntiDebugPass(
        enabled=flag("anti_debug"),
        n_stubs=o.get("n_stubs",4),
        wrap_try=o.get("wrap_try",True),
        scatter=o.get("scatter",True),
        n_sentinels=o.get("n_sentinels",3),
        scatter_prob=o.get("scatter_prob",0.7),
    ))
    p.add(JunkPass(enabled=flag("junk"), density=o.get("junk_density",0.15)))

    # Layer 2
    if flag("layer2"):
        p.add(ImportObfPass(enabled=flag("import_obf")))
        p.add(MBAPass(enabled=flag("mba"), density=o.get("mba_density",0.55),
                      max_depth=o.get("mba_depth",3), constants=o.get("mba_constants",True)))
        p.add(OpaquePass(enabled=flag("opaque"), density=o.get("opaque_density",0.35)))
        p.add(ExprExplodePass(enabled=flag("expr_explode"), density=o.get("explode_density",0.35),
                              max_depth=o.get("explode_depth",3)))
        p.add(DeadCodePass(enabled=flag("dead_code"), density=o.get("dead_density",0.25)))
        p.add(CFFPass(enabled=flag("cff"), n_fake_states=o.get("n_fake_states",2)))
        p.add(AntiDumpPass(enabled=flag("anti_dump"),
                           checks=o.get("anti_dump_checks",["modules","emulation","dis"])))

    # Layer 3 (PolyVM compilation) — done inside native pass if vm_mode=True
    # See NativePackPass logic below

    # Layer 4 (native)
    if flag("native"):
        from ..transforms.native_pack import NativePackPass
        p.add(NativePackPass(
            enabled=True,
            n_key_frags=o.get("n_key_frags", 3),
            fake_file=o.get("fake_file","<frozen importlib._bootstrap>"),
            scrub_names=flag("scrub_names"),
            vm_mode=flag("vm_mode", False),
            use_vm=flag("use_vm", False),
        ))

    # Layer 5 (chaos — always last)
    p.add(ChaosPass(
        enabled=flag("chaos"),
        max_line_len=o.get("chaos_max_len", 180),
        noise_density=o.get("chaos_noise", 0.07),
    ))

    return p
