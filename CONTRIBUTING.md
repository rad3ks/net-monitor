# Contributing to Net Monitor

## Project overview

Single-file Python CLI tool (`net_monitor.py`), zero pip dependencies. Uses system tools: `traceroute`, `ping`, `curl`. Data stored in `~/.net_monitor/`.

## Setup

```bash
git clone https://github.com/rad3ks/net-monitor.git
cd net-monitor

# macOS / Linux — requires sudo for raw socket access
sudo python3 net_monitor.py

# Windows — run PowerShell as Administrator
python net_monitor.py
```

## Testing

Before submitting a PR:

```bash
# Syntax check
python -m py_compile net_monitor.py

# Lint (matches CI config)
pip install flake8
flake8 net_monitor.py --max-line-length=120 --ignore=E501,W503,W504,E226,E231,E305,E402,E722,F541,F841

# Manual: run monitoring for a few cycles
sudo python3 net_monitor.py

# Manual: check dashboard renders correctly
sudo python3 net_monitor.py --live
```

There are no automated tests. Verify changes manually by running monitoring and checking the dashboard.

## Code style

- Max line length: 120
- Match existing patterns in the file
- No new pip dependencies — system tools only
- All HTML/CSS/JS for the dashboard is embedded in `_build_dashboard_html()`
- Escape all user-controllable strings in innerHTML with `escHtml()`
- i18n: add both EN and PL translations in `I18N` object

## Commit conventions

Follow existing style from the git log:

```
feat: add new feature description
fix: what was broken and how it's fixed
```

- Prefix: `feat:`, `fix:`, `docs:`, `refactor:`
- Imperative mood, English, lowercase after prefix
- Short first line (<70 chars), details in body if needed

## PR workflow

1. Branch from `main`
2. Make changes, test locally
3. Push and open PR — lint CI runs automatically
4. Claude Code Action runs on new PRs and responds to `@claude` mentions in comments

## AI-assisted development

This repo is set up for AI-assisted engineering:

- **Claude Code** reads `CLAUDE.md` for project context
- **Cursor** reads `.cursorrules` (same content as `CLAUDE.md`)
- **GitHub CI** runs [Claude Code Action](https://github.com/anthropics/claude-code-action) on PRs — mention `@claude` in PR comments for automated review/fixes
- `analyze_prompt.md` contains the prompt for AI-driven network quality analysis

When updating project context (architecture, data format, etc.), update both `CLAUDE.md` and `.cursorrules` to keep them in sync.
