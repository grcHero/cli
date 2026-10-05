"""Bounded filesystem collection; never follow symlinks or execute project code."""

import fnmatch
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

DEFAULT_INCLUDE = [
    "Dockerfile",
    "**/Dockerfile",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
]
EXCLUDED_DIRECTORIES = {
    ".git",
    "node_modules",
    ".venv",
    ".venv-cli",
    "venv",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".local",
    "graphify-out",
}
MAX_FILES = 40
MAX_FILE_BYTES = 262_144
MAX_TOTAL_BYTES = 1_048_576


class CliError(Exception):
    """An actionable, safe error suitable for terminal output."""


@dataclass(frozen=True)
class LocalFile:
    path: str
    content: str


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def validate_patterns(patterns: object) -> None:
    if (
        not isinstance(patterns, list)
        or len(patterns) > 100
        or not all(
            isinstance(pattern, str)
            and pattern
            and len(pattern) <= 300
            and not pattern.startswith(("/", "\\"))
            and ".." not in pattern.split("/")
            and "\\" not in pattern
            and ":" not in pattern
            and not any(ord(character) < 32 for character in pattern)
            for pattern in patterns
        )
    ):
        raise CliError("Include/exclude must contain relative patterns using forward slashes.")


def read_text(file: Path, limit: int) -> str:
    """Bound reads even if a file grows; reject nonregular files and final symlinks."""
    if file.is_symlink():
        raise CliError("Selected file must not be a symlink.")
    descriptor = os.open(
        file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CliError("Selected file must be regular text.")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise CliError("Selected file exceeds its size limit. Narrow include patterns.")
    return content.decode("utf-8")


def walk_error(error: OSError) -> None:
    raise CliError(
        "Cannot read a project folder. Check permissions or scan a smaller folder."
    ) from error


def load_configuration(root: Path) -> tuple[list[str], list[str]]:
    config = root / ".grchero.json"
    if not config.exists():
        return DEFAULT_INCLUDE.copy(), []
    if not config.is_file() or config.is_symlink() or config.stat().st_size > 16_384:
        raise CliError(".grchero.json must be a regular file smaller than 16 KiB.")
    try:
        value = json.loads(read_text(config, 16_384))
    except (OSError, UnicodeError, ValueError) as cause:
        raise CliError("Cannot read .grchero.json. Use a valid UTF-8 JSON object.") from cause
    if not isinstance(value, dict) or set(value) - {"include", "exclude"}:
        raise CliError(".grchero.json accepts only include and exclude arrays.")
    include = value.get("include", DEFAULT_INCLUDE.copy())
    exclude = value.get("exclude", [])
    validate_patterns(include)
    validate_patterns(exclude)
    return include, exclude


def collect(root: Path, include: list[str], exclude: list[str]) -> list[LocalFile]:
    validate_patterns(include)
    validate_patterns(exclude)
    result: list[LocalFile] = []
    total = 0
    visited = 0
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in EXCLUDED_DIRECTORIES
            and not (Path(directory) / name).is_symlink()
            and not matches((Path(directory) / name).relative_to(root).as_posix(), exclude)
        )
        for name in sorted(names):
            visited += 1
            if visited > 100_000:
                raise CliError(
                    "Project exceeds the 100,000-file traversal limit. Scan a smaller folder."
                )
            file = Path(directory) / name
            relative = file.relative_to(root).as_posix()
            if file.is_symlink() or not matches(relative, include) or matches(relative, exclude):
                continue
            lower = relative.lower()
            if not (
                lower.rsplit("/", 1)[-1] == "dockerfile"
                or lower.endswith((".env", ".env.production", ".env.prod", ".env.local"))
                or (".github/workflows/" in f"/{lower}" and lower.endswith((".yml", ".yaml")))
                or lower.endswith((".py", ".js", ".jsx", ".ts", ".tsx"))
            ):
                raise CliError(
                    "Scope contains unsupported files. Select Dockerfiles, "
                    "environment files, GitHub Actions workflows, or supported source files."
                )
            if not file.is_file() or file.resolve().parent != file.parent.resolve():
                raise CliError("Selected file is not a regular project file.")
            if len(result) >= MAX_FILES or file.stat().st_size > MAX_FILE_BYTES:
                raise CliError(
                    "Review limits exceeded: at most 40 files, 256 KiB per file. "
                    "Narrow include patterns."
                )
            try:
                content = read_text(file, MAX_FILE_BYTES)
            except (OSError, UnicodeError) as cause:
                raise CliError(
                    "A selected file cannot be read as UTF-8 text. Narrow include patterns."
                ) from cause
            size = len(content.encode("utf-8"))
            total += size
            if total > MAX_TOTAL_BYTES:
                raise CliError("Selected files exceed 1 MiB. Narrow include patterns.")
            if "\x00" in content:
                raise CliError(
                    "A selected file contains binary content. Exclude it from this review."
                )
            if len(relative) > 300 or any(ord(character) < 32 for character in relative):
                raise CliError(
                    "Selected filenames must be printable relative paths of at most 300 characters."
                )
            result.append(LocalFile(relative, content))
    return sorted(result, key=lambda file: file.path)
