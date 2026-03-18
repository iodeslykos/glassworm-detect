# glassworm-detect

You can't see it. That's the point.

> **Disclaimer.** This script was hastily written as a best-effort response to an active threat. It is not a replacement for a proper security audit. PRs are welcome, Issues ain't.

## What this is

In March 2026, a group called Glassworm started uploading malicious packages to GitHub, npm, and the VS Code marketplace. Over 151 of them. The packages look normal — clean code, realistic commits, documentation tweaks, version bumps. The kind of stuff that passes code review without a second glance.

The payload is hidden in Unicode variation selectors. These are characters that every editor, every terminal, and every code review tool renders as absolutely nothing. Blank lines. Whitespace. Invisible. But when a JavaScript runtime hits them, a small decoder unpacks the hidden bytes and feeds them straight to `eval()`. Your machine runs code that no human ever saw.

This script finds the specific Glassworm attack signatures in your source code. Zero dependencies. Stdlib Python. Runs on anything.

## What it catches

- The Glassworm decoder pattern (the specific arithmetic that maps variation selectors back to byte values).
- `eval(Buffer.from(...))` execution sinks paired with the decoder.
- Glassworm infrastructure IoCs (Solana wallet addresses, C2 IPs, embedded crypto material).
- Invisible Unicode variation selectors when paired with decoder/eval patterns.
- Suspicious code inside `.vsix` archives (VS Code extensions are just zips).

Files with high variation selector counts but no decoder (like emoji data files) are treated as warnings, not hits. They're suppressed by default because they're almost certainly not Glassworm.

## How to run it

By default, it scans your entire home directory. No arguments needed.

### The way you should do it

```bash
uvx --from git+https://github.com/iodeslykos/glassworm-detect glassworm-detect
```

That's it. No clone, no install, no venv. `uv` handles everything. If you don't have `uv`, get it:

```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Clone it and run it

```bash
git clone https://github.com/iodeslykos/glassworm-detect
cd glassworm-detect
uv run glassworm-detect
```

### You don't have uv and you don't want uv

Fine. Python 3.10+ and nothing else.

```bash
python3 glassworm_detect.py
```

### Scan specific directories instead

```bash
uv run glassworm-detect ~/Projects ~/node_projects /opt/extensions
```

### Scan node_modules too

This is slow. You've been warned.

```bash
uv run glassworm-detect --include-node-modules /path/to/project
```

### Show low-confidence warnings

Files with high variation selector counts but no decoder pattern (emoji data, Unicode tables, etc.) are suppressed by default. If you want to see them:

```bash
uv run glassworm-detect --show-warnings
```

## What the output looks like

### Clean

```
Platform: Linux 6.1.0
Python:   3.14.3
Scanning: /home/you
Don't shatter, you're free of glassworm.
You may continue your day with newfound vigilance.
```

### Clean, with suppressed warnings

```
Platform: Linux 6.1.0
Python:   3.14.3
Scanning: /home/you
No confirmed Glassworm IoCs found.
40 file(s) with high variation selector counts suppressed (likely emoji data). Use --show-warnings to see them.
```

### Not clean

```
Platform: Linux 6.1.0
Python:   3.14.3
Scanning: /home/you
============================================================
 GLASSWORM INDICATORS: 1 finding(s)
============================================================
This is not a drill. The following files contain indicators of the Glassworm invisible code attack.
  [HIT] /home/you/project/node_modules/sketchy-pkg/index.js
         invisible_chars=847
         decoders=['w - 0xFE00']
         eval=['eval(Buffer.from']
============================================================
Report this output to one or more of the following:
  - Your security team (they get paid for this).
  - Your system administrator (they also get paid for this).
  - That family member who is your free tech support (don't get paid by you, so buy them dinner).
Do NOT delete the files yet. You need the evidence.
Copy this output, save it, screenshot it, read it aloud to someone — whatever works.
```

Exit code `0` means clean (warnings don't count). Exit code `1` means confirmed hits. Either way, the output tells you what to do next.

## Cross-platform

Linux, macOS, Windows. Detects the platform at startup. No external tools, no compiled extensions, no nonsense. If Python runs on it, this runs on it.

## If it finds something

1. Don't delete anything yet.
2. Copy the output.
3. Figure out which package brought it in (`npm ls <package>`, check your lockfile, etc.).
4. Report it to whoever handles security where you are.
5. Report the package to the registry (GitHub, npm, VS Code marketplace).
6. Then remove it.

## Why this exists

Because invisible code that passes every review tool is the kind of thing that keeps people up at night. And because the best defense against supply chain attacks is knowing they're there before they execute.

## References

- [Aikido Security — Glassworm Returns](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode).
- [Socket.dev — Transitive Glassworm Campaign](https://socket.dev/blog/open-vsx-transitive-glassworm-campaign).
- [Ars Technica — Supply-chain attack using invisible code](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/).
- [Unicode Variation Selectors](https://en.wikipedia.org/wiki/Variation_Selectors_(Unicode_block)).

## Author

[@iodeslykos](https://github.com/iodeslykos)
