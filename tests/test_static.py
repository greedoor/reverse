#!/usr/bin/env python3
from pathlib import Path


def test_required_files_exist():
    root = Path(__file__).resolve().parents[1]
    for rel in [
        "build.sh",
        "tools/ravtools.py",
        "author/reconstruct_reference.py",
        "author/verify_challenge.py",
        "player/README.NFO",
        "player/FILE_ID.DIZ",
        "src/main.cpp",
        "src/trace.cpp",
        "src/validation.cpp",
    ]:
        assert (root / rel).exists(), rel


def test_player_text_has_no_spoilers():
    root = Path(__file__).resolve().parents[1]
    text = ((root / "player/README.NFO").read_text() + "\n" +
            (root / "player/FILE_ID.DIZ").read_text()).lower()
    for bad in ["traitor", "location", "securinets_fst{", "pdb"]:
        assert bad not in text


if __name__ == "__main__":
    test_required_files_exist()
    test_player_text_has_no_spoilers()
