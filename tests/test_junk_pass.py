import ast
import random
import sys
import types
from pathlib import Path

sys.path.insert(0, ".")
if "pyrph" not in sys.modules:
    pkg = types.ModuleType("pyrph")
    pkg.__path__ = [str(Path(__file__).resolve().parents[1])]
    sys.modules["pyrph"] = pkg

from pyrph.transforms.junk import JunkPass


def test_junk_pass_preserves_decorator_syntax_under_random_injection():
    src = """
def tag(fn):
    return fn

@tag
@tag
def decorated(x):
    return x + 1

@tag
class C:
    @tag
    def m(self):
        return decorated(3)

print(C().m())
""".strip() + "\n"

    for seed in range(80):
        random.seed(seed)
        p = JunkPass(enabled=True, density=0.9)
        r = p.run(src)
        assert r.success, r.message
        ast.parse(r.code)
