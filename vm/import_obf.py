"""
ImportObfuscator – encrypt module + attribute names trong IMPORT instructions.

Vấn đề:
    IR IMPORT instruction lưu:
        src=[IROperand("const", "requests")]
    → String "requests" xuất hiện plaintext trong bytecode stream JSON

Giải pháp:
    1. Tất cả module names + attribute names được intern vào string table
    2. String table bị fragment bởi StringFragmenter
    3. IMPORT operand chỉ lưu str_id (integer) → không có plaintext
    4. Runtime: _SR.get(str_id) → reconstruct module name → __import__()

    Thêm một lớp nữa: module name bị split thành prefix + suffix:
        "os.path" → ("os", "path") → stored separately → joined at runtime
        Static analysis chỉ thấy hai integer IDs

Compile-time: ImportObfuscator.process(ir_module) → mutates operands in-place
Runtime: không cần thêm class riêng – dùng _SR đã có
"""
from __future__ import annotations
from ..ir.nodes import IROp, IRModule, IROperand


class ImportObfuscator:
    """
    Pass chạy SAU IRBuilder, TRƯỚC SemanticFingerprintPass.
    Thay thế string operands trong IMPORT / IMPORT_FROM bằng str_id references.
    """

    def run(self, module: IRModule) -> IRModule:
        for fn in module.functions:
            for block in fn.blocks:
                for instr in block.instructions:
                    if instr.op == IROp.IMPORT:
                        self._obf_import(instr, module)
                    elif instr.op == IROp.IMPORT_FROM:
                        self._obf_import_from(instr, module)
        return module

    def _obf_import(self, instr, module: IRModule):
        """IMPORT src=[const("requests")] → src=[str_ref(id)]"""
        new_src = []
        for op in instr.src:
            if op.kind == "const" and isinstance(op.value, str):
                sid = module.intern_string(op.value)
                new_src.append(IROperand("str_ref", sid))
            else:
                new_src.append(op)
        instr.src = new_src

    def _obf_import_from(self, instr, module: IRModule):
        """IMPORT_FROM src=[const("os"), const("path")] → str_refs"""
        new_src = []
        for op in instr.src:
            if op.kind == "const" and isinstance(op.value, str):
                # Split dotted names: "os.path" → intern "os" + "path" separately
                parts = str(op.value).split(".")
                if len(parts) > 1:
                    # Store as tuple of IDs → reconstruct with "." join at runtime
                    part_ids = [module.intern_string(p) for p in parts]
                    new_src.append(IROperand("str_ref_join", part_ids))
                else:
                    sid = module.intern_string(op.value)
                    new_src.append(IROperand("str_ref", sid))
            else:
                new_src.append(op)
        instr.src = new_src
