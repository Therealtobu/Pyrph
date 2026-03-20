"""
TBL – Temporal Binding Layer

Kết quả phụ thuộc vào timeline.
Time component: low bits of perf_counter_ns (~4us window)
History component: XOR with result from N calls ago
"""
from __future__ import annotations


class TBLEmitter:

    @staticmethod
    def emit_runtime(time_mask: int = 0xFFF, hist_depth: int = 4) -> str:
        lines = [
            f"_TBL_TMASK  = {time_mask}",
            f"_TBL_HDEPTH = {hist_depth}",
            "_TBL_HIST   = []",
            "_TBL_MASK32 = 0xFFFFFFFF",
            "",
            "def __tbl_bind(result, use_time=True):",
            "    global _TBL_HIST",
            "    if not isinstance(result, int):",
            "        _TBL_HIST.append(hash(str(result)) & _TBL_MASK32)",
            "        if len(_TBL_HIST) > _TBL_HDEPTH + 4:",
            "            _TBL_HIST = _TBL_HIST[-(  _TBL_HDEPTH + 4):]",
            "        return result",
            "    t_component = 0",
            "    if use_time:",
            "        try:",
            "            import time as _t",
            "            t_component = _t.perf_counter_ns() & _TBL_TMASK",
            "        except Exception:",
            "            pass",
            "    h_component = _TBL_HIST[-_TBL_HDEPTH] if len(_TBL_HIST) >= _TBL_HDEPTH else 0",
            "    bound = (result ^ t_component ^ h_component) & _TBL_MASK32",
            "    _TBL_HIST.append(result & _TBL_MASK32)",
            "    if len(_TBL_HIST) > _TBL_HDEPTH + 4:",
            "        _TBL_HIST = _TBL_HIST[-(  _TBL_HDEPTH + 4):]",
            "    return bound",
            "",
            "def __tbl_unbind(bound, hist_snapshot, t_snapshot=0):",
            "    if not isinstance(bound, int):",
            "        return bound",
            "    h_component = hist_snapshot[-_TBL_HDEPTH] if len(hist_snapshot) >= _TBL_HDEPTH else 0",
            "    return (bound ^ t_snapshot ^ h_component) & _TBL_MASK32",
            "",
            "def __tbl_apply(result, vm_state):",
            "    import copy as _copy",
            "    hist_snap = _copy.copy(_TBL_HIST)",
            "    try:",
            "        import time as _t",
            "        t_snap = _t.perf_counter_ns() & _TBL_TMASK",
            "    except Exception:",
            "        t_snap = 0",
            "    bound   = __tbl_bind(result, use_time=True)",
            "    unbound = __tbl_unbind(bound, hist_snap, t_snap)",
            "    return unbound if isinstance(unbound, int) else result",
        ]
        return "\n".join(lines) + "\n"
