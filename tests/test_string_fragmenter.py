import sys; sys.path.insert(0, '.')
import unittest
from ..vm.string_fragmenter import StringFragmenter

exec(StringFragmenter.emit_runtime())   # defines _SR  # noqa


class TestStringFragmenter(unittest.TestCase):

    def _make_pool(self, strtab: dict, frag_size=3):
        sf = StringFragmenter(frag_size=frag_size)
        frags, fidx = sf.fragment(strtab)
        return _SR(frags, fidx)  # noqa

    def test_single_string_roundtrip(self):
        pool = self._make_pool({"hello": 0})
        self.assertEqual(pool.get(0), "hello")

    def test_multiple_strings(self):
        strtab = {"alpha": 0, "beta": 1, "gamma": 2, "delta": 3}
        pool   = self._make_pool(strtab)
        for s, sid in strtab.items():
            self.assertEqual(pool.get(sid), s, f"str_id={sid}")

    def test_empty_string(self):
        pool = self._make_pool({"": 0})
        self.assertEqual(pool.get(0), "")

    def test_unicode_string(self):
        strtab = {"xin chào": 0, "日本語": 1, "emoji🔥": 2}
        pool   = self._make_pool(strtab)
        for s, sid in strtab.items():
            self.assertEqual(pool.get(sid), s, f"unicode str_id={sid}")

    def test_long_string(self):
        s    = "the quick brown fox jumps over the lazy dog " * 5
        pool = self._make_pool({s: 0})
        self.assertEqual(pool.get(0), s)

    def test_cache_works(self):
        """Calling get() twice returns same result (uses cache)."""
        pool = self._make_pool({"cached": 0})
        r1   = pool.get(0)
        r2   = pool.get(0)
        self.assertEqual(r1, r2)
        self.assertIs(r1, r2, "should be exact same object from cache")

    def test_raw_fragments_not_plaintext(self):
        """No single fragment should equal the full original string."""
        sf    = StringFragmenter(frag_size=2)
        frags, fidx = sf.fragment({"secret": 0})
        plain = b"secret"
        for frag in frags:
            self.assertNotEqual(frag, plain,
                "full string should not appear as a single fragment")

    def test_shuffle_different_each_run(self):
        """Two fragment() calls on same input produce different fragment order."""
        import random
        random.seed(1)
        sf1 = StringFragmenter()
        f1, _ = sf1.fragment({"hello world": 0})
        random.seed(999)
        sf2 = StringFragmenter()
        f2, _ = sf2.fragment({"hello world": 0})
        self.assertNotEqual(f1, f2, "fragment order should differ between runs")

    def test_missing_id_returns_empty(self):
        pool = self._make_pool({"x": 0})
        self.assertEqual(pool.get(99), "")

    def test_large_table(self):
        import string as _string, random
        strtab = {
            ''.join(random.choices(_string.ascii_lowercase, k=8)): i
            for i in range(30)
        }
        pool = self._make_pool(strtab)
        for s, sid in strtab.items():
            self.assertEqual(pool.get(sid), s, f"large table sid={sid}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
