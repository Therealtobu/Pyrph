import random

from vm.const_pool import MutatingConstPool, POOL_RUNTIME


def _runtime_ns(exported: dict) -> dict:
    ns: dict = {}
    exec(POOL_RUNTIME, ns)
    ns["_CP_STATE"] = exported["state"]
    ns["_CP_SLOTS"] = {
        int(k): [v["e"], v["m"]]
        for k, v in exported["slots"].items()
    }
    return ns


def test_bool_values_roundtrip_in_runtime_pool():
    pool = MutatingConstPool({0: True, 1: False, 2: 7}, seed=0x1234)
    runtime = _runtime_ns(pool.export())
    get = runtime["_cp_get"]

    for _ in range(5):
        assert get(0) is True
        assert get(1) is False
        assert get(2) == 7


def test_order_variation_preserves_values_after_many_mutations():
    consts = {i: (i * 17) ^ 0x55AA for i in range(32)}
    pool = MutatingConstPool(consts, seed=0xBEEF)

    rnd = random.Random(1337)
    for _ in range(300):
        i = rnd.randrange(0, 32)
        assert pool.get(i) == consts[i]


def test_runtime_pool_matches_python_pool_under_random_access():
    consts = {0: True, 1: False, 2: 99, 3: "x", 4: None, 5: -7}
    py_pool = MutatingConstPool(consts, seed=0xCAFE)
    rt_pool = _runtime_ns(py_pool.export())
    rt_get = rt_pool["_cp_get"]

    rnd = random.Random(7)
    for _ in range(120):
        idx = rnd.randrange(0, 6)
        assert py_pool.get(idx) == rt_get(idx)
