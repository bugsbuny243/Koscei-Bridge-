#!/usr/bin/env python3
"""Consolidate Koschei Web3 public styles into one stylesheet.

This migration helper is intentionally deterministic and limited to koschei/api.
It preserves every existing CSS rule, rewrites internal /css/*.css references to
/css/koschei.css?v=1, and removes the superseded CSS source files.
"""
from __future__ import annotations

import re
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ROOT = API_ROOT / "public"
CSS_ROOT = PUBLIC_ROOT / "css"
TARGET = CSS_ROOT / "koschei.css"
SINGLE_REF = "/css/koschei.css?v=1"

# Base rules first, presentation layers later. Files not named here are kept in
# deterministic lexical order between the base and late presentation layers.
BASE_ORDER = [
    "koschei.css",
    "koschei-global-shell.css",
    "koschei-modern.css",
    "koschei-product-v2.css",
    "public-safety-surfaces-v2.css",
    "unified-live-evidence-card.css",
    "verdict-card-evidence-refs.css",
]
LATE_ORDER = [
    "koschei-universe-v1.css",
    "koschei-arvis-command-v1.css",
    "koschei-arvis-command-v2.css",
    "koschei-home-command-environment-v1.css",
    "koschei-home-orbit-fix-v3.css",
    "koschei-home-structural-mesh-v1.css",
    "koschei-home-universe-v2.css",
    "koschei-home-universe-motion-v1.css",
    "dossier-print.css",
]

TEXT_EXTENSIONS = {".html", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".sh", ".md"}
CSS_PATH_RE = re.compile(r"/css/[A-Za-z0-9_.-]+\.css(?:\?[^\"'\s<>)]*)?")
STYLESHEET_LINK_RE = re.compile(
    r"<link\b(?=[^>]*\brel=[\"']stylesheet[\"'])[^>]*\bhref=[\"']/css/[A-Za-z0-9_.-]+\.css(?:\?[^\"']*)?[\"'][^>]*>\s*",
    re.IGNORECASE,
)


def ordered_css_files() -> list[Path]:
    files = {p.name: p for p in CSS_ROOT.glob("*.css") if p.is_file()}
    ordered: list[Path] = []
    seen: set[str] = set()
    for name in BASE_ORDER:
        if name in files and name not in seen:
            ordered.append(files[name]); seen.add(name)
    late = {name for name in LATE_ORDER if name in files}
    for name in sorted(files):
        if name not in seen and name not in late:
            ordered.append(files[name]); seen.add(name)
    for name in LATE_ORDER:
        if name in files and name not in seen:
            ordered.append(files[name]); seen.add(name)
    return ordered


def build_bundle(files: list[Path]) -> str:
    parts = [
        "/* KOSCHEI WEB3 — canonical public stylesheet.\n"
        "   Generated from the former public/css modules without dropping rules.\n"
        "   Do not split public presentation back into versioned CSS fragments. */\n"
    ]
    for path in files:
        source = path.read_text(encoding="utf-8").strip()
        if not source:
            continue
        parts.append(f"\n/* ===== source: {path.name} ===== */\n{source}\n")
    return "".join(parts)


def rewrite_html_stylesheets(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    matches = list(STYLESHEET_LINK_RE.finditer(text))
    if not matches:
        return False
    first = matches[0]
    replacement = f'<link rel="stylesheet" href="{SINGLE_REF}">\n'
    pieces: list[str] = []
    cursor = 0
    inserted = False
    for match in matches:
        pieces.append(text[cursor:match.start()])
        if not inserted:
            pieces.append(replacement)
            inserted = True
        cursor = match.end()
    pieces.append(text[cursor:])
    new_text = "".join(pieces)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def rewrite_remaining_internal_refs(path: Path, retired_names: set[str]) -> bool:
    text = path.read_text(encoding="utf-8")

    def repl(match: re.Match[str]) -> str:
        ref = match.group(0)
        name = ref.split("/css/", 1)[1].split("?", 1)[0]
        return SINGLE_REF if name in retired_names else ref

    new_text = CSS_PATH_RE.sub(repl, text)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def main() -> None:
    files = ordered_css_files()
    if not files or TARGET.name not in {p.name for p in files}:
        raise SystemExit("canonical koschei.css is missing")

    retired = {p.name for p in files if p.name != TARGET.name}
    TARGET.write_text(build_bundle(files), encoding="utf-8")

    html_changed = 0
    for path in sorted(PUBLIC_ROOT.rglob("*.html")):
        html_changed += int(rewrite_html_stylesheets(path))

    ref_changed = 0
    for path in sorted(API_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        if CSS_ROOT in path.parents:
            continue
        ref_changed += int(rewrite_remaining_internal_refs(path, retired))

    for path in files:
        if path.name != TARGET.name:
            path.unlink()

    remaining = sorted(p.name for p in CSS_ROOT.glob("*.css"))
    if remaining != [TARGET.name]:
        raise SystemExit(f"expected one CSS file, found: {remaining}")

    stale: list[str] = []
    for path in sorted(API_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name in retired:
            if f"/css/{name}" in text:
                stale.append(f"{path.relative_to(API_ROOT)} -> {name}")
    if stale:
        raise SystemExit("stale retired CSS references remain:\n" + "\n".join(stale))

    print(f"bundled {len(files)} CSS files into {TARGET.relative_to(API_ROOT)}")
    print(f"retired {len(retired)} CSS files")
    print(f"rewrote stylesheet links in {html_changed} HTML files")
    print(f"updated CSS references in {ref_changed} API text files")


if __name__ == "__main__":
    main()
