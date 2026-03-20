"""
StringFragmenter – phá string literals thành byte fragments rải rác.

Vấn đề:
    __STRTAB = {"password": 0, "secret_key": 1}
    → strings xuất hiện nguyên vẹn trong source → grep được

Giải pháp:
    Mỗi string bị tách thành N fragments (2-4 bytes mỗi phần).
    Fragments lưu dưới dạng bytes literals, rải rác trong source,
    cách nhau bởi dummy fragments của strings khác.
    Reconstruct chỉ xảy ra tại runtime khi VM cần string đó.

    Fragment table:
        __FRAGS = [b'\x68\x65', b'\x77\x6f', b'\x6c\x6c', ...]
    Index table (encrypted với MCP key):
        __FIDX = {str_id: [frag_idx, frag_idx, ...]}

    Runtime reconstruct:
        b''.join(__FRAGS[i] for i in __FIDX[str_id]).decode('utf-8')

Compile-time: StringFragmenter.fragment(string_table) → emittable data
Runtime: _SR class inlined vào output
"""
from __future__ import annotations
import os
import random


class StringFragmenter:

    def __init__(self, frag_size: int = 3):
        self._frag_size = frag_size   # bytes per fragment

    def fragment(self, string_table: dict[str, int]
                 ) -> tuple[list[bytes], dict[int, list[int]]]:
        """
        Returns:
            frags    : flat list of byte fragments (includes dummy fragments)
            fidx     : {str_id → [frag_indices]} – reassembly map
        """
        frags: list[bytes] = []
        fidx:  dict[int, list[int]] = {}

        all_strings = list(string_table.items())   # (str, id)

        for s, sid in all_strings:
            raw     = s.encode("utf-8")
            indices = []
            offset  = 0
            while offset < len(raw):
                chunk = raw[offset:offset + self._frag_size]
                idx   = len(frags)
                frags.append(chunk)
                indices.append(idx)
                offset += self._frag_size
                # Insert 1-2 dummy fragments from OTHER strings between real ones
                if offset < len(raw) and len(all_strings) > 1:
                    other = random.choice([t for t in all_strings if t[0] != s])
                    dummy_raw   = other[0].encode("utf-8")
                    dummy_start = random.randint(0, max(0, len(dummy_raw)-2))
                    dummy_chunk = dummy_raw[dummy_start:dummy_start+self._frag_size]
                    if dummy_chunk:
                        frags.append(dummy_chunk)   # dummy – NOT added to indices
            fidx[sid] = indices

        # Shuffle the frag list while updating fidx accordingly
        perm = list(range(len(frags)))
        random.shuffle(perm)
        inv  = [0] * len(perm)
        for new_pos, old_pos in enumerate(perm):
            inv[old_pos] = new_pos

        frags_shuffled = [frags[perm[i]] for i in range(len(frags))]
        fidx_remapped  = {sid: [inv[i] for i in idxs]
                          for sid, idxs in fidx.items()}

        return frags_shuffled, fidx_remapped

    @staticmethod
    def emit_runtime() -> str:
        return r'''
class _SR:
    """String reconstructor – runtime. Reassembles fragmented strings."""
    def __init__(self, frags: list, fidx: dict):
        self._f = frags
        self._i = fidx
        self._cache: dict = {}

    def get(self, str_id: int) -> str:
        if str_id in self._cache:
            return self._cache[str_id]
        indices = self._i.get(str_id)
        if indices is None:
            return ""
        result = b"".join(self._f[i] for i in indices).decode("utf-8", errors="replace")
        self._cache[str_id] = result
        return result
'''
