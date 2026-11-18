import shutil
from pathlib import Path


SCAN_DIR = Path("scan")
FIXED_DIR = Path("fixed")


def reset_runtime_dirs():
    for directory in (SCAN_DIR, FIXED_DIR):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        (directory / ".gitkeep").touch()
