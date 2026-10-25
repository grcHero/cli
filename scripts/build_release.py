"""Build release files for the one-line installer.

Writes into ``--out``:

* ``grchero.pyz``: a single-file app for any system with Python 3.11+ (no install step).
* ``grchero-<os>-<arch>[.exe]``: a native program with no Python needed, when
  ``--native`` is given and PyInstaller is installed (build tool only, never a runtime
  dependency). Build each platform on that platform.
* ``VERSION``, ``SHA256SUMS`` and ``manifest.json``, merged with what is already in
  ``--out`` so files built on several machines can be collected in one folder.

``--deployment`` stamps the deployment's public sign-in values (see
``grchero_cli/deployment.py``) so ``grchero login`` needs no flags. Values are read from
a JSON file with ``api_url``, ``issuer_url``, ``client_id`` and ``audience``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grchero_cli import __version__  # noqa: E402
from grchero_cli.deployment import FIELDS  # noqa: E402

ENTRY = "import sys\nfrom grchero_cli.main import main\n\nsys.exit(main())\n"


def platform_name() -> str:
    system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}[platform.system()]
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}[machine]
    suffix = ".exe" if system == "windows" else ""
    return f"grchero-{system}-{arch}{suffix}"


def stage(deployment: Path | None, workdir: Path) -> Path:
    """Copy the package (sources only) and stamp the deployment values."""
    target = workdir / "app"
    shutil.copytree(
        ROOT / "grchero_cli",
        target / "grchero_cli",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "deployment.json"),
    )
    if deployment is not None:
        values = json.loads(deployment.read_text("utf-8"))
        missing = [field for field in FIELDS if not values.get(field)]
        if missing:
            raise SystemExit(f"{deployment} is missing: {', '.join(missing)}")
        stamped = {field: str(values[field]) for field in FIELDS}
        (target / "grchero_cli" / "deployment.json").write_text(
            json.dumps(stamped, indent=2) + "\n", "utf-8"
        )
    (target / "__main__.py").write_text(ENTRY, "utf-8")
    return target


def build_pyz(app: Path, out: Path) -> Path:
    target = out / "grchero.pyz"
    zipapp.create_archive(app, target, interpreter="/usr/bin/env python3", compressed=True)
    return target


def build_native(app: Path, out: Path, workdir: Path) -> Path:
    name = platform_name()
    separator = ";" if platform.system() == "Windows" else ":"
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--name",
        name.removesuffix(".exe"),
        "--distpath",
        str(out),
        "--workpath",
        str(workdir / "build"),
        "--specpath",
        str(workdir),
        "--paths",
        str(app),
    ]
    stamped = app / "grchero_cli" / "deployment.json"
    if stamped.exists():
        command += ["--add-data", f"{stamped}{separator}grchero_cli"]
    subprocess.run([*command, str(app / "__main__.py")], check=True)
    return out / name


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(out: Path, built: list[Path]) -> None:
    manifest_path = out / "manifest.json"
    files: dict[str, dict[str, object]] = {}
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text("utf-8"))
        if previous.get("version") == __version__:
            files = previous.get("files", {})
    for path in built:
        files[path.name] = {"sha256": sha256(path), "size": path.stat().st_size}
    manifest = {"version": __version__, "python": ">=3.11", "files": dict(sorted(files.items()))}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", "utf-8")
    (out / "VERSION").write_text(__version__ + "\n", "utf-8")
    (out / "SHA256SUMS").write_text(
        "".join(f"{entry['sha256']}  {name}\n" for name, entry in manifest["files"].items()),
        "utf-8",
    )


def main() -> None:
    args = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    args.add_argument("--out", type=Path, default=ROOT / "dist" / "release")
    args.add_argument("--deployment", type=Path, help="JSON file with public sign-in values")
    args.add_argument("--native", action="store_true", help="Also build a native program")
    args.add_argument(
        "--include",
        type=Path,
        action="append",
        default=[],
        help="Add a native program built elsewhere (copied into --out); repeatable",
    )
    options = args.parse_args()
    options.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        workdir = Path(temporary)
        app = stage(options.deployment, workdir)
        built = [build_pyz(app, options.out)]
        if options.native:
            built.append(build_native(app, options.out, workdir))
    for extra in options.include:
        target = options.out / extra.name
        if extra.resolve() != target.resolve():
            shutil.copy2(extra, target)
        built.append(target)
    write_manifest(options.out, built)
    for path in built:
        print(f"built {path.name}")


if __name__ == "__main__":
    main()
