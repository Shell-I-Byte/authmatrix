#!/usr/bin/env python3
"""Offline black-box schema falsification probes; no network access or target scanning."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    checks = [
        ("null", None, 2, None),
        ("true", True, 0, "match"),
        ("false", False, 0, "inconclusive"),
        ("missing", "missing", 0, "inconclusive"),
        ("number", 1, 2, None),
        ("string", "true", 2, None),
        ("object", {}, 2, None),
        ("array", [], 2, None),
    ]
    with tempfile.TemporaryDirectory(prefix="authmatrix-093-") as td:
        f = Path(td) / "input.json"
        for name, control, rc, verdict in checks:
            data = {
                "schema": "authmatrix.matrix/v1",
                "authorization": {"approved": True, "origin": "synthetic", "scope": "nonsecret"},
                "cases": [{"id": "secret-identifier", "kind": "horizontal", "expected": "deny", "observed_status": 404}],
            }
            if name != "missing":
                data["cases"][0]["positive_control_confirmed"] = control
            f.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
            p = subprocess.run([str(binary), "evaluate", "-in", str(f)], capture_output=True, timeout=5)
            assert p.returncode == rc, (name, p.returncode, rc, p.stderr[:150])
            assert b"secret-identifier" not in (p.stdout + p.stderr), name
            assert b"nonsecret" not in (p.stdout + p.stderr), name
            assert b"\x1b" not in (p.stdout + p.stderr), name
            if verdict:
                report = json.loads(p.stdout)
                assert report["schema"] == "authmatrix.result/v1", name
                assert report["evidence"][0]["verdict"] == verdict, name
                assert report["evidence"][0]["confidence"] == "observation-only", name
            else:
                assert not p.stdout, name
            print(f"PASS {name}: rc={p.returncode}, verdict={verdict or 'rejected'}")
    print(f"PASS: {len(checks)} independent CLI validation/redaction controls")


if __name__ == "__main__":
    main()
