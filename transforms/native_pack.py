"""
transforms/native_pack.py
==========================
NativePackPass — the final and strongest protection layer.

Modes
-----
  vm_mode=False (default): compile Python → marshal bytecode →
      AES+XOR+perm encrypt → embed in launcher .py with C runtime .so

  vm_mode=True: compile Python → Pyrph PolyVM bytecode →
      AES+XOR+perm encrypt → embed in launcher .py with C VM runtime

In both modes the .so is:
  - Compiled fresh per-build (unique binary every time)
  - AES key stored via whitebox scattering in .so (never plaintext)
  - Loaded via memfd_create (never written to disk)
  - Verified by SHA256 before loading
  - XOR key split into N fragments (never whole in Python)
  - All sensitive strings (libc.so.6, memfd_create, etc.) obfuscated

Fallback: if no C compiler is available, falls back to MarshalPackPass.
"""
from __future__ import annotations
import ast
import base64
import marshal
import random
import string
from pathlib import Path

from ..core.base   import ObfPass
from ..core.result import ObfResult


def _rn(n=7) -> str:
    letters = "abcefghjkmnpqrstuvwxy"
    raw = "".join(random.choices(string.hexdigits[:16], k=n))
    pos = random.randint(0,n-1)
    return "_"+raw[:pos]+random.choice(letters)+raw[pos:]


def _scrub_code(co, fake_file: str, rng: random.Random):
    new_consts = []
    for c in co.co_consts:
        if hasattr(c,"co_code"):
            new_consts.append(_scrub_code(c, fake_file, rng))
        else:
            new_consts.append(c)
    new_name = co.co_name
    if co.co_name in ("<module>","<lambda>"):
        new_name = _rn(8)
    try:
        return co.replace(co_filename=fake_file, co_name=new_name,
                          co_consts=tuple(new_consts))
    except Exception:
        return co


class NativePackPass(ObfPass):
    name        = "native_pack"
    phase       = 4
    description = "AES+XOR+perm → C runtime .so via memfd_create (WB-key, LLVM, anti-dump)"

    def run(self, code: str) -> ObfResult:
        if not self.enabled: return self._skip(code)

        # Check native available
        try:
            from ..native.builder import build_b64, is_available
            native_ok = is_available()
        except Exception:
            native_ok = False

        if not native_ok:
            return self._fallback_marshal(code)

        try:
            try: ast.parse(code)
            except SyntaxError as e: return self._err(code, e)

            seed        = self.opts.get("seed",      None)
            n_frags     = self.opts.get("n_key_frags", 3)
            fake_file   = self.opts.get("fake_file",
                             "<frozen importlib._bootstrap>")
            scrub       = self.opts.get("scrub_names", True)
            vm_mode     = self.opts.get("vm_mode",  False)
            use_vm      = self.opts.get("use_vm",   False)
            n_stubs     = self.opts.get("n_stubs",  4)

            rng = random.Random(seed)

            from ..native.builder import build_b64
            from ..vm.encryptor   import encrypt_bytecode

            so_b64, aes_key = build_b64(seed=rng.randint(0,0xFFFF))

            # ── Payload ──────────────────────────────────────────────────
            if vm_mode or use_vm:
                try:
                    from ..vm.compiler import compile_source
                    from ..vm.opcodes  import OpcodeMap
                    from ..vm.compiler import _bc_to_spec
                    om  = OpcodeMap.generate()
                    bc  = compile_source(code, opcode_map=om, use_regs=True)
                    payload    = bc.instructions
                    opmap_bytes= om.to_translation_table()
                    consts_ser = _bc_to_spec(bc)[3]   # serialised constants
                    names_ser  = bc.names
                    ep = encrypt_bytecode(payload, aes_key,
                                          n_key_frags=n_frags, seed=seed)
                    enc_b64 = base64.b64encode(ep.ciphertext).decode("ascii")
                    launcher = self._gen_vm_launcher(
                        enc_b64, so_b64, ep, fake_file,
                        rng.randint(0,0xFFFF), n_stubs,
                        opmap_bytes, consts_ser, names_ser, rng)
                except Exception:
                    # VM compile failed — fall through to marshal
                    vm_mode = False; use_vm = False

            if not vm_mode and not use_vm:
                try:
                    co = compile(code, fake_file, "exec", optimize=0)
                except SyntaxError as e:
                    return self._err(code, e)
                if scrub: co = _scrub_code(co, fake_file, rng)
                payload = marshal.dumps(co)
                ep = encrypt_bytecode(payload, aes_key,
                                      n_key_frags=n_frags, seed=seed)
                enc_b64  = base64.b64encode(ep.ciphertext).decode("ascii")
                launcher = self._gen_legacy_launcher(
                    enc_b64, so_b64, ep, fake_file,
                    rng.randint(0,0xFFFF), n_stubs, rng)

            try: ast.parse(launcher)
            except SyntaxError as e:
                return self._err(code, RuntimeError(f"launcher syntax error: {e}"))

            mode_str = "vm" if (vm_mode or use_vm) else "marshal"
            return self._ok(launcher,
                message=(f"native packed {len(payload)}B ({mode_str}) "
                         f"· AES+XOR+perm · WB-key · memfd · "
                         f"key split {n_frags}-ways"),
                payload_bytes=len(payload), mode=mode_str)

        except Exception as exc:
            return self._err(code, exc)

    # ── launcher generators ───────────────────────────────────────────────

    def _gen_legacy_launcher(self, enc_b64, so_b64, ep, fake_file,
                              seed, n_stubs, rng) -> str:
        from ..phases.unified import _gen_launcher
        from ..vm.encryptor   import split_key as _sk

        frags = ep.xor_key_frags
        return _gen_launcher(
            enc_b64, so_b64, frags, ep.xor_step, ep.inv_perm,
            ep.orig_len, ep.aes_nonce, fake_file, seed, n_stubs,
        )

    def _gen_vm_launcher(self, enc_b64, so_b64, ep, fake_file,
                          seed, n_stubs, opmap_bytes, consts_ser,
                          names_ser, rng) -> str:
        from ..phases.unified import _gen_launcher, _make_enc_obj_lines, _rn as _r

        vb64 = "_"+_r(); vop = "_"+_r(); vc = "_"+_r(); vn = "_"+_r()
        extra = [f"import base64 as {vb64}", f"{vop}=bytes({list(opmap_bytes)})"]
        extra += _make_enc_obj_lines(consts_ser, vc, vb64, rng)
        extra += _make_enc_obj_lines(names_ser,  vn, vb64, rng)

        return _gen_launcher(
            enc_b64, so_b64, ep.xor_key_frags, ep.xor_step, ep.inv_perm,
            ep.orig_len, ep.aes_nonce, fake_file, seed, n_stubs,
            extra_lines=extra,
            call_fn="decrypt_exec_vm",
            extra_call=f"{vop},{vc},{vn}",
        )

    # ── marshal fallback ──────────────────────────────────────────────────

    def _fallback_marshal(self, code: str) -> ObfResult:
        """Pure-Python fallback when no C compiler is available."""
        try:
            import base64, marshal, random as rnd, ast
            try: ast.parse(code)
            except SyntaxError as e: return self._err(code, e)

            fake_file = self.opts.get("fake_file",
                            "<frozen importlib._bootstrap>")
            try:
                co = compile(code, fake_file, "exec", optimize=0)
            except SyntaxError as e:
                return self._err(code, e)

            bc     = marshal.dumps(co)
            key    = [rnd.randint(1,254) for _ in range(32)]
            step   = rnd.choice([1,3,5,7])
            enc    = bytearray(bc)
            ki = 0
            for i in range(len(enc)):
                enc[i] ^= key[ki]; ki=(ki+step)%len(key)
            enc_b64= base64.b64encode(bytes(enc)).decode()

            vk=_rn(); vm=_rn(); vb=_rn(); vd=_rn(); vi=_rn(); vbc=_rn()
            vg=_rn(); vs=_rn()
            launcher = (
                f"import base64 as {vb},marshal as {vm}\n"
                f"{vk}={key!r}\n"
                f"{vs}={step!r}\n"
                f"{vd}=bytearray({vb}.b64decode({enc_b64!r}))\n"
                f"{vi}=0\n"
                f"for _i in range(len({vd})):\n"
                f"    {vd}[_i]^={vk}[{vi}];{vi}=({vi}+{vs})%len({vk})\n"
                f"{vbc}=bytes({vd})\n"
                f"{vg}=(__builtins__ if isinstance(__builtins__,dict) else vars(__builtins__)).copy()\n"
                f"{vg}['__name__']=__name__\n"
                f"{vg}['__file__']={fake_file!r}\n"
                f"exec({vm}.loads({vbc}),{vg})\n"
            )
            return self._ok(launcher,
                message=f"(native unavailable) marshal fallback · "
                        f"{len(bc)}B bytecode encrypted")
        except Exception as exc:
            return self._err(code, exc)
