#!/usr/bin/env python3
"""Glassworm Invisible Unicode Supply Chain Attack Detector.

Scans directories for Unicode variation selectors (U+FE00–U+FE0F,
U+E0100–U+E01EF) used to hide executable payloads in source code,
and for eval/exec decoder patterns that execute the hidden bytes.

Reference: https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode

Author: iodeslykos (https://github.com/iodeslykos)
Date:   2026-03-18
"""

import argparse
import os
import platform
import sys
import zipfile

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# UTF-8 byte sequences for variation selectors.
# Range 1: ef b8 [80-8f]
# Range 2: f3 a0 [84-87] [80-bf*] (*af when third byte is 87)

# Signatures are split so the detector doesn't flag itself.
# The Glassworm decoder is a specific composite pattern: a function
# that maps variation selectors to byte values via codePointAt with
# 0xFE00/0xE0100 subtraction, feeding into eval(Buff er.from(...)).
# Individual atoms (codePointAt, 0xFE00, eval) appear everywhere in
# legitimate code. Only the combination is an IoC.

# Composite decoder: the range-check arithmetic unique to Glassworm.
# Variable-name-agnostic; covers both spaced and minified forms.
GLASSWORM_DECODER_SIGS = [
    b"- 0x" + b"FE" + b"00",  # range 1 decode subtraction
    b"-0x" + b"FE" + b"00",  # range 1 decode (minified)
    b"- 0x" + b"E01" + b"00 + 16",  # range 2 decode subtraction
    b"-0x" + b"E01" + b"00+16",  # range 2 decode (minified)
]

# Eval on decoded buffer — the execution sink.
GLASSWORM_EVAL_SIGS = [
    b"eval(Bu" + b"ffer" + b".from",
    b"eval(Bu" + b"ffer" + b".from(s(",
]

# Solana wallet addresses used as C2 dead drops.
GLASSWORM_SOLANA = [
    b"BjVeAjPrSKFiingBn4vZvghsGj" + b"9KCE8AJVtbc9S8o8SC",
    b"6YGcuyFRJKZtcaYCCFba9fScNUv" + b"PkGXodXE1mJiSzqDJ",
]

# C2 infrastructure.
GLASSWORM_C2 = [
    b"45.32.150" + b".251",
    b"45.32.151" + b".157",
    b"70.34.242" + b".255",
]

# Embedded crypto material.
GLASSWORM_CRYPTO = [
    b"wDO6YyTm6DL0T0zJ0SXh" + b"Uql5Mo0pdlSz",
    b"c4b9a3773e9dced6015a67" + b"0855fd32b",
]

# Solana memo program.
GLASSWORM_MEMO = [
    b"MemoSq4gqABAXKb96qnH8Tys" + b"NcWxMyWCqXgDLGmfcHr",
]

# Solana RPC methods used for C2 resolution.
GLASSWORM_RPC = [
    b"getSignatures" + b"ForAddress",
]

# Suspicious npm lifecycle hooks (package.json context).
GLASSWORM_LIFECYCLE_HOOKS = [
    b'"pre' + b'install"',
    b'"post' + b'install"',
]

# javascript-obfuscator _0x identifier prefix threshold.
OBFUSCATION_THRESHOLD = 20

SOURCE_EXTS = {
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".mts",
    ".cts",
    ".jsx",
    ".tsx",
    ".vue",
    ".svelte",
    ".py",
    ".rb",
    ".sh",
    ".bash",
    ".zsh",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".terraform",
    ".tofu",
    "dist",
    "build",
    "out",
    ".cache",
    "target",
}

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------


def has_invisible_chars(data: bytes) -> list[int]:
    """Return byte offsets where variation selectors appear.

    Single variation selectors adjacent to visible characters are
    legitimate emoji presentation modifiers (e.g. U+FE0F after ⚠).
    Glassworm payloads use clusters of consecutive selectors to encode
    hidden bytes. We only flag files with 3+ selectors to avoid false
    positives on emoji-containing source files.
    """
    hits = []
    i = 0
    n = len(data)
    while i < n:
        # U+FE00–U+FE0F: ef b8 [80-8f]
        if (
            i + 2 < n
            and data[i] == 0xEF
            and data[i + 1] == 0xB8
            and 0x80 <= data[i + 2] <= 0x8F
        ):
            hits.append(i)
            i += 3
        # U+E0100–U+E01EF: f3 a0 [84-87] [80-bf*]
        # *fourth byte capped at af only when third byte is 87
        elif (
            i + 3 < n
            and data[i] == 0xF3
            and data[i + 1] == 0xA0
            and 0x84 <= data[i + 2] <= 0x87
            and 0x80 <= data[i + 3] <= (0xAF if data[i + 2] == 0x87 else 0xBF)
        ):
            hits.append(i)
            i += 4
        else:
            i += 1
    # Fewer than 3 selectors is almost certainly emoji, not a payload.
    return hits if len(hits) >= 3 else []


def has_decoder_pattern(data: bytes) -> list[str]:
    """Return matched Glassworm decoder signatures."""
    return [sig.decode() for sig in GLASSWORM_DECODER_SIGS if sig in data]


def has_eval_pattern(data: bytes) -> list[str]:
    """Return matched Glassworm eval/execution signatures."""
    return [sig.decode() for sig in GLASSWORM_EVAL_SIGS if sig in data]


def has_infrastructure_iocs(data: bytes) -> list[str]:
    """Return matched Glassworm infrastructure IoCs (Solana, C2, crypto)."""
    all_sigs = (
        GLASSWORM_SOLANA
        + GLASSWORM_C2
        + GLASSWORM_CRYPTO
        + GLASSWORM_MEMO
        + GLASSWORM_RPC
    )
    return [sig.decode() for sig in all_sigs if sig in data]


def has_obfuscation_markers(data: bytes) -> int:
    """Return count of javascript-obfuscator _0x identifiers, 0 if below threshold."""
    count = data.count(b"_0x")
    return count if count >= OBFUSCATION_THRESHOLD else 0


def has_lifecycle_hooks(data: bytes) -> list[str]:
    """Return matched npm lifecycle hook patterns."""
    return [sig.decode() for sig in GLASSWORM_LIFECYCLE_HOOKS if sig in data]


def _scan_bytes(data: bytes) -> dict:
    """Core scan logic on raw bytes. Returns findings dict (may be empty)."""
    findings = {}
    infra = has_infrastructure_iocs(data)
    if infra:
        findings["infrastructure"] = infra
    decoders = has_decoder_pattern(data)
    if decoders:
        findings["decoder_patterns"] = decoders
    evals = has_eval_pattern(data)
    if evals:
        findings["eval_patterns"] = evals
    if b"\xef\xb8" in data or b"\xf3\xa0" in data:
        offsets = has_invisible_chars(data)
        if offsets:
            if decoders or evals or infra:
                findings["invisible_chars"] = len(offsets)
            elif len(offsets) >= 50:
                findings["invisible_chars"] = len(offsets)
                findings["note"] = "high count without decoder — verify manually"
    obf_count = has_obfuscation_markers(data)
    if obf_count:
        findings["obfuscation"] = obf_count
        if not (decoders or evals or infra):
            findings["note"] = (
                "javascript-obfuscator patterns without other IoCs — verify manually"
            )
    return findings


def scan_file(path: str) -> dict | None:
    """Scan a single file. Returns findings dict or None."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return None
    findings = _scan_bytes(data)
    if findings:
        findings["path"] = path
        return findings
    return None


def scan_vsix(path: str) -> list[dict]:
    """Scan a .vsix or .crx (zip) archive for suspicious extension code."""
    results = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                ext = os.path.splitext(name)[1].lower()
                if ext not in SOURCE_EXTS:
                    continue
                data = zf.read(name)
                findings = _scan_bytes(data)
                if findings:
                    findings["path"] = f"{path}!{name}"
                    results.append(findings)
    except (zipfile.BadZipFile, OSError):
        pass
    return results


def walk_and_scan(
    root: str, include_node_modules: bool = False, quiet: bool = False
) -> list[dict]:
    """Walk directory tree, scan source files and vsix archives."""
    results = []
    scanned = 0
    show_progress = not quiet and sys.stderr.isatty()
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIRS and (include_node_modules or d != "node_modules")
        ]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            ext = os.path.splitext(fname)[1].lower()

            if fname == "init.json":
                r = scan_file(fpath)
                if r:
                    r["init_json"] = True
                    results.append(r)
                scanned += 1
                continue

            if fname == "package.json":
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                except (OSError, PermissionError):
                    scanned += 1
                    continue
                findings = _scan_bytes(data)
                hooks = has_lifecycle_hooks(data)
                if hooks:
                    findings["lifecycle_hooks"] = hooks
                    if not (
                        findings.get("decoder_patterns")
                        or findings.get("eval_patterns")
                        or findings.get("infrastructure")
                    ):
                        findings.setdefault(
                            "note",
                            "npm lifecycle hooks — verify manually",
                        )
                if findings:
                    findings["path"] = fpath
                    findings["package_json"] = True
                    results.append(findings)
                scanned += 1
                continue

            if ext in (".vsix", ".crx"):
                results.extend(scan_vsix(fpath))
                scanned += 1
                continue

            if ext in SOURCE_EXTS:
                r = scan_file(fpath)
                if r:
                    results.append(r)
                scanned += 1

            if show_progress and scanned % 100 == 0:
                print(f"\r  scanned {scanned} files...", end="", file=sys.stderr)

    if show_progress:
        print(f"\r  scanned {scanned} files.   ", file=sys.stderr)
    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

NO_COLOR = os.environ.get("NO_COLOR") is not None


def _c(code: str, text: str) -> str:
    if NO_COLOR or not sys.stdout.isatty() or platform.system() == "Windows":
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t):
    return _c("1;31", t)


def yellow(t):
    return _c("1;33", t)


def green(t):
    return _c("1;32", t)


def dim(t):
    return _c("2", t)


def _is_warn(r: dict) -> bool:
    """True if finding is warn-only (high char count, no hard IoC)."""
    return (
        bool(r.get("note"))
        and not r.get("decoder_patterns")
        and not r.get("eval_patterns")
        and not r.get("infrastructure")
    )


def print_results(results: list[dict], show_warnings: bool = False) -> None:
    hits = [r for r in results if not _is_warn(r)]
    warns = [r for r in results if _is_warn(r)]

    if not hits and not warns:
        print(green("Don't shatter, you're free of glassworm."))
        print(dim("You may continue your day with newfound vigilance."))
        return

    if hits:
        print(red(f"{'=' * 60}"))
        print(red(f" GLASSWORM INDICATORS: {len(hits)} finding(s)"))
        print(red(f"{'=' * 60}"))
        print(
            red(
                "This is not a drill. The following files contain indicators of the Glassworm invisible code attack."
            )
        )
        for r in hits:
            path = r["path"]
            parts = []
            if "infrastructure" in r:
                parts.append(red(f"infrastructure={r['infrastructure']}"))
            if "invisible_chars" in r:
                parts.append(red(f"invisible_chars={r['invisible_chars']}"))
            if "decoder_patterns" in r:
                parts.append(red(f"decoders={r['decoder_patterns']}"))
            if "eval_patterns" in r:
                parts.append(red(f"eval={r['eval_patterns']}"))
            if "obfuscation" in r:
                parts.append(red(f"obfuscation=_0x×{r['obfuscation']}"))
            if "lifecycle_hooks" in r:
                parts.append(red(f"lifecycle_hooks={r['lifecycle_hooks']}"))
            if r.get("init_json"):
                parts.append(yellow("init.json"))
            if r.get("package_json"):
                parts.append(yellow("package.json"))
            print(f"  {red('[HIT]')} {path}")
            for p in parts:
                print(f"         {p}")
        print(red(f"{'=' * 60}"))
        print("Report this output to one or more of the following:")
        print("  - Your security team (they get paid for this).")
        print("  - Your system administrator (they also get paid for this).")
        print(
            "  - That family member who is your free tech support (don't get paid by you, so buy them dinner)."
        )
        print("Do NOT delete the files yet. You need the evidence.")
        print(
            "Copy this output, save it, screenshot it, read it aloud to someone — whatever works."
        )
    else:
        print(green("No confirmed Glassworm IoCs found."))

    if warns:
        if show_warnings:
            print(yellow(f"{'=' * 60}"))
            print(
                yellow(
                    f" WARNINGS: {len(warns)} file(s) with low-confidence indicators"
                )
            )
            print(yellow(f"{'=' * 60}"))
            for r in warns:
                print(f"  {yellow('[WARN]')} {r['path']}")
                if "invisible_chars" in r:
                    count = r["invisible_chars"]
                    print(f"         {yellow(f'invisible_chars={count}')}")
                if "obfuscation" in r:
                    count = r["obfuscation"]
                    print(f"         {yellow(f'obfuscation=_0x×{count}')}")
                if "lifecycle_hooks" in r:
                    hooks = r["lifecycle_hooks"]
                    print(f"         {yellow(f'lifecycle_hooks={hooks}')}")
                if "note" in r:
                    print(f"         {dim(r['note'])}")
        else:
            print(
                dim(
                    f"{len(warns)} file(s) with low-confidence indicators suppressed. Use --show-warnings to see them."
                )
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Detect Glassworm invisible Unicode supply chain attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""detects:
  - Glassworm decoder pattern (variation selector to byte subtraction arithmetic)
  - Eval execution sinks paired with decoder
  - Glassworm infrastructure IoCs (Solana wallets, C2 IPs, RPC methods, crypto material)
  - Invisible Unicode variation selectors (when paired with decoder/eval)
  - javascript-obfuscator patterns (_0x identifier density)
  - Suspicious npm lifecycle hooks in package.json (preinstall/postinstall)
  - init.json files containing any of the above
  - Suspicious code inside .vsix archives

reference:
  https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode

author:
  iodeslykos — https://github.com/iodeslykos
""",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=[os.path.expanduser("~")],
        help="Directories or files to scan (default: ~/)",
    )
    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Include node_modules in scan (slow)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress progress indicator",
    )
    parser.add_argument(
        "--show-warnings",
        action="store_true",
        help="Show low-confidence findings (high variation selector counts without decoder)",
    )
    args = parser.parse_args()

    print(dim(f"Platform: {platform.system()} {platform.release()}"))
    print(dim(f"Python:   {platform.python_version()}"))
    print(dim(f"Scanning: {', '.join(args.paths)}"))

    all_results = []
    for path in args.paths:
        if os.path.isfile(path):
            r = scan_file(path)
            if r:
                all_results.append(r)
        elif os.path.isdir(path):
            all_results.extend(
                walk_and_scan(path, args.include_node_modules, args.quiet)
            )
        else:
            print(yellow(f"Skipping (not found): {path}"), file=sys.stderr)

    print_results(all_results, args.show_warnings)
    hits = [r for r in all_results if not _is_warn(r)]
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
