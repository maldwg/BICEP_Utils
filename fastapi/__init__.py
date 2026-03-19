from importlib.machinery import PathFinder
from pathlib import Path
import sys

# fastapi package name can lead to collision with real fastapi package
# Therfor, following logic: 
if __name__ == "fastapi":
    repo_root = Path(__file__).resolve().parent.parent
    search_paths = [
        path_entry
        for path_entry in sys.path
        if Path(path_entry or ".").resolve() != repo_root
    ]

    spec = PathFinder.find_spec(__name__, search_paths)
    if spec is None or spec.loader is None:
        raise ImportError("Could not resolve the third-party 'fastapi' package.")

    module = sys.modules[__name__]
    module.__file__ = spec.origin
    module.__loader__ = spec.loader
    module.__package__ = __name__
    if spec.submodule_search_locations is not None:
        module.__path__ = list(spec.submodule_search_locations)
    module.__spec__ = spec
    spec.loader.exec_module(module)
