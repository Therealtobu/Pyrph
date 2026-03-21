"""Module runner for `python -m pyrph` from source checkouts."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def main():
    root_main = Path(__file__).resolve().parent.parent / "__main__.py"
    spec = spec_from_file_location("pyrph_root_main", root_main)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Pyrph entrypoint")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()


if __name__ == "__main__":
    main()
