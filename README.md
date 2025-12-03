# Pathfinder

Simple Python scanner that:
- Resolves a domain (and common TLDs when none given)
- Brute-forces subdomains
- Brute-forces common paths (with extensions)
- Crawls pages and scrapes in-scope links/JS endpoints

## Run
```bash
python pathfinder.py example.com
```
(Runs the full “all” profile by default.)

Common flags:
- `--threads 40` adjust concurrency
- `--timeout 5` adjust timeouts
- `--no-color` disable ANSI color
- `--output-json results.json` save results

No external deps (standard library only).
