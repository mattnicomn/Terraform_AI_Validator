#!/usr/bin/env python3
"""
Deterministic Lambda packaging for AI Validator.

Builds reproducible ZIP artifacts from the authoritative source under src/:
  src/prompt_handler/lambda_function.py -> dist/prompt_handler.zip
  src/processor/lambda_function.py      -> dist/processor.zip

Each ZIP contains lambda_function.py at the ROOT (handler
lambda_function.lambda_handler). No tests, __pycache__, .pyc, vendored deps,
credentials, or nested ZIPs are included.

Determinism: fixed member order, fixed ZIP timestamp, fixed permissions, and
fixed compression so identical source yields byte-identical archives.

Third-party dependencies: NONE (handlers use only stdlib + Lambda-runtime boto3),
so nothing is vendored.

Local build only. Does NOT upload to AWS. Writes dist/ (git-ignored) and
dist/manifest.json (no secrets).

Usage (from repo root C:\\USMISSIONHERO\\products\\ai):
    py scripts/build_lambdas.py
"""

import hashlib
import json
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
DIST = REPO_ROOT / "dist"

# Fixed timestamp for determinism: ZIP epoch floor (1980-01-01 00:00:00).
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)

# Package definitions: name -> (source file, handler, runtime target).
PACKAGES = {
    "prompt_handler": {
        "source": SRC / "prompt_handler" / "lambda_function.py",
        "handler": "lambda_function.lambda_handler",
        "runtime": "python3.12",
    },
    "processor": {
        "source": SRC / "processor" / "lambda_function.py",
        "handler": "lambda_function.lambda_handler",
        "runtime": "python3.11",
    },
}


def _add_deterministic(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o644 & 0xFFFF) << 16  # -rw-r--r--
    info.create_system = 0  # normalize (0 = MS-DOS/FAT) for cross-platform reproducibility
    zf.writestr(info, data)


def build_package(name: str, spec: dict) -> dict:
    source: Path = spec["source"]
    if not source.is_file():
        raise FileNotFoundError(f"Source not found for '{name}': {source}")

    # ZIP root member is always lambda_function.py
    data = source.read_bytes()
    out = DIST / f"{name}.zip"

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        _add_deterministic(zf, "lambda_function.py", data)

    zip_bytes = out.read_bytes()
    return {
        "artifact": out.name,
        "source_file": str(source.relative_to(REPO_ROOT)).replace("\\", "/"),
        "handler": spec["handler"],
        "runtime": spec["runtime"],
        "sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "size_bytes": len(zip_bytes),
        "contained_files": ["lambda_function.py"],
    }


def main() -> int:
    DIST.mkdir(parents=True, exist_ok=True)
    manifest = {"packages": []}
    for name, spec in PACKAGES.items():
        entry = build_package(name, spec)
        manifest["packages"].append(entry)
        print(f"built {entry['artifact']}  sha256={entry['sha256']}  size={entry['size_bytes']}")

    (DIST / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"manifest -> {DIST / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
