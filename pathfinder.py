#!/usr/bin/env python3
"""
Lightweight subdomain and path enumerator that works on Linux and Windows.

It performs:
- DNS-based brute force against a wordlist to find subdomains.
- HTTP probing against a list of common paths for the target domain (or each
  discovered subdomain when asked).

Only the Python standard library is used so the script runs without extra
packages. Keep wordlists small when you don't want to make lots of requests.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import random
import socket
import string
import sys
import threading
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib import error, request
from urllib.parse import urljoin, urlparse

# Built-in, intentionally short wordlists to avoid noisy scans by default.
DEFAULT_SUBDOMAIN_WORDS: Sequence[str] = (
    "www",
    "api",
    "app",
    "shop",
    "store",
    "static",
    "cdn",
    "img",
    "files",
    "assets",
    "admin",
    "portal",
    "blog",
    "news",
    "status",
    "support",
    "help",
    "dev",
    "stage",
    "test",
    "beta",
    "m",
    "mail",
    "secure",
    "vpn",
)

DEFAULT_PATH_WORDS: Sequence[str] = (
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "wp-json",
    "admin",
    "admin/login",
    "admin.php",
    "wp-admin",
    "wp-login.php",
    "login.php",
    "logout",
    "auth",
    "login",
    "signup",
    "account",
    "settings",
    "profile",
    "dashboard",
    "portal",
    "status",
    "support",
    "help",
    "about",
    "contact",
    "blog",
    "news",
    "docs",
    "developers",
    "download",
    "downloads",
    "release",
    "releases",
    "static",
    "assets",
    "images",
    "js",
    "css",
    "store",
    "shop",
    "products",
    "pricing",
    "careers",
    "partners",
    "security",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    ".well-known/assetlinks.json",
    ".well-known/apple-app-site-association",
    ".env",
    "config",
    "config.php",
    "phpinfo.php",
    "status",
    "server-status",
    "actuator/health",
    "health",
    "healthz",
    "ready",
    "readyz",
    "search",
)

DEFAULT_TLDS: Sequence[str] = (
    "com",
    "org",
    "net",
    "io",
    "co",
    "dev",
    "app",
    "ai",
    "info",
    "biz",
    "us",
    "uk",
    "ca",
    "de",
    "xyz",
    "co.uk",
)

DEFAULT_EXTENSIONS: Sequence[str] = ("", ".php", ".html", ".htm", ".json", ".txt", ".xml")

PROFILES: Dict[str, Dict[str, object]] = {
    "quick": {
        "description": "Fast: paths on base only, no crawl.",
        "paths_on_subdomains": False,
        "crawl": False,
        "crawl_on_subdomains": False,
        "crawl_depth": 1,
        "crawl_pages": 50,
        "soft404_samples": 2,
        "extensions": ",".join(ext for ext in DEFAULT_EXTENSIONS if ext),
        "include_server_errors": False,
    },
    "deep": {
        "description": "Deeper: paths on subs, crawl base, JS scrape.",
        "paths_on_subdomains": True,
        "crawl": True,
        "crawl_on_subdomains": False,
        "crawl_depth": 2,
        "crawl_pages": 200,
        "soft404_samples": 3,
        "extensions": ".php,.html,.json,.txt,.xml",
        "include_server_errors": False,
    },
    "all": {
        "description": "All-in: paths on subs, crawl subs, more pages.",
        "paths_on_subdomains": True,
        "crawl": True,
        "crawl_on_subdomains": True,
        "crawl_depth": 3,
        "crawl_pages": 400,
        "soft404_samples": 4,
        "extensions": ".php,.html,.htm,.json,.txt,.xml",
        "include_server_errors": True,
    },
}

class Color:
    """Minimal ANSI color helper with opt-out."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, text: str, code: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}\033[0m"

    def green(self, text: str) -> str:
        return self._wrap(text, "\033[32m")

    def yellow(self, text: str) -> str:
        return self._wrap(text, "\033[33m")

    def red(self, text: str) -> str:
        return self._wrap(text, "\033[31m")

    def blue(self, text: str) -> str:
        return self._wrap(text, "\033[34m")

    def cyan(self, text: str) -> str:
        return self._wrap(text, "\033[36m")

    def magenta(self, text: str) -> str:
        return self._wrap(text, "\033[35m")

    def dim(self, text: str) -> str:
        return self._wrap(text, "\033[90m")


# Global color helper, configured in main.
COLOR = Color(False)


def fmt_status(status: object) -> str:
    try:
        code = int(status)
    except Exception:
        return str(status)
    if 200 <= code < 300:
        return COLOR.green(str(code))
    if 300 <= code < 400:
        return COLOR.cyan(str(code))
    if 400 <= code < 500:
        return COLOR.yellow(str(code))
    return COLOR.red(str(code))


def fmt_url(url: str) -> str:
    return COLOR.blue(url)


ASSET_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".webp",
    ".avif",
    ".tif",
    ".tiff",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".map",
    ".mjs",
    ".cjs",
    ".wasm",
    ".webmanifest",
    ".mp3",
    ".mp4",
    ".m4a",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
}

SKIP_ENDPOINT_EXTENSIONS = {
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".webp",
    ".avif",
    ".tif",
    ".tiff",
    ".mp3",
    ".mp4",
    ".m4a",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".json",
    ".xml",
}

SKIP_ENDPOINT_NAMES = {
    "javascript",
    "json",
    "xml",
    "svg",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "ico",
    "webp",
    "css",
    "js",
    "map",
    "manifest",
    "video",
    "audio",
    "image",
    "label",
    "option",
    "select",
    "textarea",
    "text",
    "table",
    "tbody",
    "thead",
    "tr",
    "td",
    "th",
    "div",
    "span",
    "form",
    "input",
    "button",
    "footer",
    "header",
    "nav",
    "article",
    "section",
    "iframe",
    "script",
    "style",
    "font",
    "filter",
    "canvas",
    "svg",
    "defs",
    "rect",
    "path",
    "clipPath",
    "polyline",
    "linearGradient",
    "metadata",
    "source",
    "unsafe",
    "commonjs",
    "octet-stream",
}


def is_asset(url: str, content_type: Optional[str]) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in ASSET_EXTENSIONS:
        if path.endswith(ext):
            return True
    if content_type:
        ct = content_type.lower()
        if ct.startswith(("image/", "video/", "audio/", "font/")):
            return True
        if ct.startswith(("text/css", "application/javascript", "text/javascript", "application/x-javascript")):
            return True
        if ct.startswith("application/octet-stream"):
            return True
        if "font-woff" in ct or "font/woff" in ct:
            return True
    return False


def filter_js_endpoints(endpoints: set[str]) -> List[str]:
    """Remove obvious noise and assets from JS-extracted endpoints."""
    cleaned: List[str] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        path = parsed.path or "/"
        if path in ("/", ""):
            continue
        if any(ch.isspace() for ch in endpoint):
            continue
        if "%" in endpoint or "=" in path:
            continue
        if len(endpoint) > 180:
            continue
        if not any(ch.isalpha() for ch in path):
            continue
        if is_asset(endpoint, None):
            continue
        segments = [seg for seg in path.split("/") if seg]
        if not segments:
            continue
        last_seg = segments[-1].lower()
        if last_seg in SKIP_ENDPOINT_NAMES:
            continue
        if all(seg.lower() in SKIP_ENDPOINT_NAMES for seg in segments):
            continue
        if all(len(seg) < 3 for seg in segments):
            continue
        if re.fullmatch(r"[0-9._-]+", last_seg):
            continue
        # Drop domain-like paths embedded in the path.
        if re.search(r"/[A-Za-z0-9-]+\.[A-Za-z]{2,}(/|$)", path):
            continue
        ext = parsed.path.lower().rsplit(".", 1)
        if len(ext) == 2 and f".{ext[1]}" in SKIP_ENDPOINT_EXTENSIONS:
            continue
        if not re.search(r"[A-Za-z]{3,}", path):
            continue
        if re.fullmatch(r"[0-9._/-]+", path.strip("/")):
            continue
        if endpoint not in seen:
            seen.add(endpoint)
            cleaned.append(endpoint)
    return sorted(cleaned)


def validate_js_endpoints(endpoints: List[str], timeout: float) -> List[str]:
    """Keep only endpoints that respond with non-error HTML/JSON/XML/plain."""
    validated: List[str] = []
    seen: set[str] = set()
    for url in endpoints:
        if url in seen:
            continue
        seen.add(url)
        status, content_type, _ = fetch_page(url, timeout=timeout, max_bytes=1024)
        if status is None or status == 404 or status >= 500:
            continue
        ct_lower = (content_type or "").lower()
        if ct_lower and not any(t in ct_lower for t in ("html", "json", "xml", "plain")):
            continue
        validated.append(url)
    return validated

class Progress:
    """Simple stdout progress bar using only the standard library."""

    def __init__(self, prefix: str, total: int, width: int = 28) -> None:
        self.prefix = prefix
        self.total = max(1, total)
        self.width = width
        self.current = 0
        self.lock = threading.Lock()

    def render(self, current: Optional[int] = None, final: bool = False) -> None:
        val = self.current if current is None else current
        filled = int(self.width * min(val, self.total) / self.total)
        bar = COLOR.green("#" * filled) + COLOR.dim("-" * (self.width - filled))
        end = "\n" if final else "\r"
        prefix = COLOR.cyan(self.prefix)
        print(f"{prefix} [{bar}] {val}/{self.total}", end=end, flush=True)

    def increment(self, step: int = 1) -> None:
        with self.lock:
            self.current += step
            final = self.current >= self.total
            self.render(self.current, final=final)

    def finish(self) -> None:
        if self.current < self.total:
            self.render(self.total, final=True)


class LinkExtractor(HTMLParser):
    """Extract href/src values from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.script_src: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        for attr, value in attrs:
            if attr in ("href", "src") and value:
                self.links.append(value)
            if tag.lower() == "script" and attr == "src" and value:
                self.script_src.append(value)


class TitleExtractor(HTMLParser):
    """Extract the text inside <title>."""

    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)

    def get_title(self) -> Optional[str]:
        text = " ".join(self.parts).strip()
        return text or None
def load_wordlist(path: Optional[Path], built_ins: Sequence[str]) -> List[str]:
    """Merge built-ins with optional file input, keeping only unique entries."""
    combined: List[str] = list(built_ins)
    if path:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            combined.append(item)
    seen: set[str] = set()
    unique: List[str] = []
    for word in combined:
        if word not in seen:
            unique.append(word)
            seen.add(word)
    return unique


def has_wildcard(domain: str) -> bool:
    """Detect wildcard DNS by resolving a random hostname."""
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    probe_host = f"{token}.{domain}"
    try:
        socket.getaddrinfo(probe_host, None)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def resolve_host(host: str) -> Tuple[str, List[str]]:
    """Attempt to resolve a host, returning resolved addresses on success."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.timeout):
        return host, []

    addresses = sorted({info[4][0] for info in infos if info and info[4]})
    return host, addresses


def enumerate_subdomains(
    domain: str,
    words: Sequence[str],
    threads: int,
    ignore_wildcard: bool,
) -> List[Dict[str, object]]:
    subdomains: List[Dict[str, object]] = []

    if ignore_wildcard and has_wildcard(domain):
        print(f"[!] Wildcard DNS detected for {domain}; skipping subdomain brute force.")
        return subdomains

    total = len(words)
    if total == 0:
        return subdomains

    progress = Progress(prefix=f"Subdomains {domain}", total=total)
    progress.render(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_host, f"{word.strip()}.{domain}"): word
            for word in words
        }
        for future in concurrent.futures.as_completed(futures):
            host, addresses = future.result()
            if addresses:
                subdomains.append({"host": host, "addresses": addresses})
            progress.increment()

    progress.finish()

    return sorted(subdomains, key=lambda entry: entry["host"])  # type: ignore[arg-type]


def fetch_url(url: str, timeout: float) -> Tuple[Optional[int], Optional[str]]:
    headers = {"User-Agent": "Pathfinder/1.0 (+https://example.com)"}
    req = request.Request(url, headers=headers, method="HEAD")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type")
    except error.HTTPError as http_err:
        # Many servers reject HEAD; retry with GET on 405 to reduce false negatives.
        if http_err.code == 405:
            return fetch_url_get(url, timeout, headers)
        return http_err.code, http_err.headers.get("Content-Type")
    except (error.URLError, socket.timeout):
        return None, None


def fetch_url_get(url: str, timeout: float, headers: Dict[str, str]) -> Tuple[Optional[int], Optional[str]]:
    req = request.Request(url, headers=headers, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type")
    except error.HTTPError as http_err:
        return http_err.code, http_err.headers.get("Content-Type")
    except (error.URLError, socket.timeout):
        return None, None


def fetch_page(url: str, timeout: float, max_bytes: int = 512_000) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """GET a URL and return (status, content_type, body_str<=max_bytes)."""
    headers = {"User-Agent": "Pathfinder/1.0 (+https://example.com)"}
    req = request.Request(url, headers=headers, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type")
            body_bytes = resp.read(max_bytes)
            try:
                body = body_bytes.decode("utf-8", errors="ignore")
            except Exception:
                body = None
            return status, content_type, body
    except error.HTTPError as http_err:
        return http_err.code, http_err.headers.get("Content-Type"), None
    except (error.URLError, socket.timeout, ValueError, http.client.InvalidURL):
        return None, None, None


def extract_title(html: str) -> Optional[str]:
    parser = TitleExtractor()
    try:
        parser.feed(html)
        return parser.get_title()
    except Exception:
        return None


def make_soft_404_signatures(base_url: str, timeout: float, samples: int = 2) -> List[Dict[str, object]]:
    """Probe random paths to build soft-404 signatures for a host."""
    signatures: List[Dict[str, object]] = []
    for _ in range(max(1, samples)):
        token = "__pf_notfound_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        probe_url = f"{base_url.rstrip('/')}/{token}"
        status, content_type, body = fetch_page(probe_url, timeout=timeout)
        if status is None or status == 404:
            continue

        norm_ct = content_type.split(";")[0].strip().lower() if content_type else None
        length = len(body) if body else 0
        title = extract_title(body) if body else None
        fingerprint = hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest() if body else None

        signatures.append(
            {
                "status": status,
                "content_type": norm_ct,
                "length": length,
                "title": title.lower() if title else None,
                "fingerprint": fingerprint,
            }
        )

    return signatures


def is_soft_404(
    status: Optional[int],
    content_type: Optional[str],
    body: Optional[str],
    signatures: List[Dict[str, object]],
) -> bool:
    if not signatures or status is None:
        return False

    # status must match one of the fingerprints to be considered.
    if all(sig.get("status") != status for sig in signatures):
        return False

    norm_ct = content_type.split(";")[0].strip().lower() if content_type else None
    length = len(body) if body else 0
    fingerprint = hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest() if body else None
    title = extract_title(body) if body else None

    for sig in signatures:
        sig_ct = sig.get("content_type")
        if sig_ct and norm_ct and sig_ct != norm_ct:
            continue

        sig_status = sig.get("status")
        if sig_status and status != sig_status:
            continue

        sig_length = int(sig.get("length", 0))
        tolerance = max(800, int(sig_length * 0.15))
        if sig_length and abs(length - sig_length) > tolerance:
            continue

        if fingerprint and sig.get("fingerprint") and fingerprint == sig.get("fingerprint"):
            return True

        if title and sig.get("title") and title.lower() == sig.get("title"):
            return True

        if sig_ct and norm_ct and sig_ct == norm_ct:
            return True

    return False


def enumerate_paths(
    base_url: str,
    words: Sequence[str],
    threads: int,
    timeout: float,
    include_server_errors: bool,
    soft404_signatures: List[Dict[str, object]],
    extensions: Sequence[str],
    js_endpoints: set[str],
) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []

    targets: List[str] = []
    target_seen: set[str] = set()
    for word in words:
        clean = word.strip()
        if not clean:
            continue
        has_ext = "." in clean.rsplit("/", 1)[-1]
        if has_ext:
            if clean not in target_seen:
                targets.append(clean)
                target_seen.add(clean)
        else:
            used_exts = extensions or [""]
            for ext in used_exts:
                ext_clean = ext.strip()
                if ext_clean and not ext_clean.startswith("."):
                    ext_clean = "." + ext_clean
                candidate = f"{clean}{ext_clean}"
                if candidate not in target_seen:
                    targets.append(candidate)
                    target_seen.add(candidate)

    total = len(targets)
    if total == 0:
        return results

    progress = Progress(prefix=f"Paths {base_url}", total=total)
    progress.render(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(fetch_page, f"{base_url.rstrip('/')}/{target.lstrip('/')}", timeout): target
            for target in targets
        }
        seen_urls: set[str] = set()
        for future in concurrent.futures.as_completed(futures):
            status, content_type, body = future.result()
            url = f"{base_url.rstrip('/')}/{futures[future].lstrip('/')}"
            if status is None:
                progress.increment()
                continue
            if status == 404:
                progress.increment()
                continue
            if is_soft_404(status, content_type, body, soft404_signatures):
                progress.increment()
                continue
            if status >= 500 and not include_server_errors:
                progress.increment()
                continue
            title = extract_title(body) if body else None
            if body and content_type and ("html" in content_type.lower() or "javascript" in content_type.lower()):
                for endpoint in extract_js_endpoints(body, url, allowed_host=urlparse(base_url).netloc):
                    js_endpoints.add(endpoint)
            if url not in seen_urls:
                seen_urls.add(url)
                results.append({"url": url, "status": status, "content_type": content_type, "title": title})
            progress.increment()

    progress.finish()

    return sorted(results, key=lambda entry: entry["url"])  # type: ignore[arg-type]


def normalize_link(root: str, current_url: str, link: str, allowed_host: str) -> Optional[str]:
    """Resolve a discovered link to an absolute URL on the same host."""
    link = link.strip()
    if not link or link.startswith("#"):
        return None
    # Drop links with control characters or spaces to avoid InvalidURL errors.
    if any(ch.isspace() for ch in link) or any(ord(ch) < 32 for ch in link):
        return None
    lower = link.lower()
    if lower.startswith(("javascript:", "mailto:", "tel:")):
        return None

    joined = urljoin(current_url, link)
    parsed = urlparse(joined)
    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.netloc != allowed_host:
        return None
    # Normalize by stripping fragments.
    cleaned = parsed._replace(fragment="").geturl()
    return cleaned


def extract_js_endpoints(text: str, base_url: str, allowed_host: str) -> List[str]:
    """Extract candidate endpoints from JS or HTML text."""
    import re

    skip_tags = {
        "html",
        "head",
        "body",
        "title",
        "style",
        "script",
        "iframe",
        "link",
        "meta",
        "h1",
        "h2",
        "h3",
        "div",
        "span",
        "form",
        "input",
        "button",
        "nav",
        "footer",
        "header",
        "section",
        "article",
        "p",
        "img",
        "svg",
    }

    candidates = re.findall(
        r"(https?://[^\s'\"<>]+|/[A-Za-z0-9_\-/\.?=&%#]+)",
        text,
        re.IGNORECASE,
    )
    normalized: List[str] = []
    seen: set[str] = set()
    for cand in candidates:
        url = urljoin(base_url, cand)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc != allowed_host:
            continue
        if parsed.path.lstrip("/").lower() in skip_tags:
            continue
        url = parsed._replace(fragment="").geturl()
        if url not in seen:
            seen.add(url)
            normalized.append(url)
    return normalized


def crawl_site(
    base_url: str,
    max_depth: int,
    max_pages: int,
    timeout: float,
    include_server_errors: bool,
    soft404_signatures: List[Dict[str, object]],
    js_endpoints: set[str],
) -> List[Dict[str, object]]:
    """Lightweight crawl within the same host, discovering linked pages."""
    results: List[Dict[str, object]] = []
    visited: set[str] = set()
    seen_hashes: set[str] = set()
    queue: List[Tuple[str, int]] = [(base_url.rstrip("/"), 0)]
    if max_pages <= 0:
        return results

    host = urlparse(base_url).netloc
    progress = Progress(prefix=f"Crawl {base_url}", total=max_pages)
    progress.render(0)

    while queue and len(results) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        status, content_type, body = fetch_page(url, timeout=timeout)
        if status is None or status == 404:
            progress.increment()
            continue
        if is_soft_404(status, content_type, body, soft404_signatures):
            progress.increment()
            continue
        if status >= 500 and not include_server_errors:
            progress.increment()
            continue

        title = extract_title(body) if body else None
        body_hash = hashlib.sha1((body or "").encode("utf-8", errors="ignore")).hexdigest() if body else None
        if body_hash and body_hash in seen_hashes:
            progress.increment()
            continue
        if body_hash:
            seen_hashes.add(body_hash)

        results.append({"url": url, "status": status, "content_type": content_type, "title": title})
        progress.increment()

        if depth >= max_depth:
            continue

        if body and content_type and "html" in content_type.lower():
            extractor = LinkExtractor()
            extractor.feed(body)
            for link in extractor.links:
                normalized = normalize_link(base_url, url, link, allowed_host=host)
                if not normalized or normalized in visited:
                    continue
                queue.append((normalized, depth + 1))
            # Collect JS endpoints from HTML and linked JS files on the same host.
            for endpoint in extract_js_endpoints(body, url, allowed_host=host):
                js_endpoints.add(endpoint)
            for script_src in extractor.script_src:
                normalized = normalize_link(base_url, url, script_src, allowed_host=host)
                if not normalized:
                    continue
                s_status, s_ct, s_body = fetch_page(normalized, timeout=timeout, max_bytes=256_000)
                if s_status and not is_soft_404(s_status, s_ct, s_body, soft404_signatures):
                    if s_body:
                        for endpoint in extract_js_endpoints(s_body, normalized, allowed_host=host):
                            js_endpoints.add(endpoint)

    progress.finish()
    return sorted(results, key=lambda entry: entry["url"])  # type: ignore[arg-type]


def sanitize_domain_input(raw: str) -> str:
    """Strip scheme and path components to leave only the host-like portion."""
    cleaned = raw.strip()
    if not cleaned:
        return ""

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        host = parsed.netloc or parsed.path
    else:
        host = cleaned

    if "/" in host:
        host = host.split("/")[0]

    return host.lstrip(".").strip().lower()


def build_candidate_domains(user_input: str, tlds: Sequence[str]) -> List[str]:
    """Return domains to probe. If input has no dot, append common TLDs."""
    if "." in user_input:
        return [user_input]
    return [f"{user_input}.{tld.lstrip('.')}" for tld in tlds]


def resolve_domains(domains: Sequence[str], prefix: str = "TLD check") -> List[Dict[str, object]]:
    """Resolve a list of domains and return only the ones that work."""
    resolved: List[Dict[str, object]] = []
    if not domains:
        return resolved

    total = len(domains)
    progress = Progress(prefix=prefix, total=total)
    progress.render(0)

    for domain in domains:
        _, addresses = resolve_host(domain)
        if addresses:
            resolved.append({"domain": domain, "addresses": addresses})
        progress.increment()

    progress.finish()
    return resolved


def is_subdomain(domain: str, tlds: Sequence[str]) -> bool:
    """Return True if the domain looks like it already includes a subdomain."""
    labels = domain.split(".")
    if len(labels) < 3:
        return False

    # Try to match the longest known TLD first (handles co.uk, etc.).
    sorted_tlds = sorted(tlds, key=lambda t: -len(t))
    for tld in sorted_tlds:
        tld_labels = tld.split(".")
        if labels[-len(tld_labels):] == tld_labels:
            return len(labels) - len(tld_labels) > 1

    return len(labels) > 2


def print_report(results: Dict[str, Dict[str, object]]) -> None:
    """Emit a final report after all work completes."""
    print(COLOR.magenta("\n=== Report ==="))
    if not results:
        print("No results.")
        return

    for domain, info in results.items():
        addresses = info.get("addresses") or []
        subdomains = info.get("subdomains") or []
        paths = info.get("paths") or []
        sub_scan_skipped = info.get("subdomain_scan_skipped", False)
        crawled = info.get("crawled") or []
        js_endpoints = info.get("js_endpoints") or []

        print(f"\n{COLOR.magenta(domain)}")
        print(
            COLOR.dim(
                f"  Summary: {len(addresses)} addr, {len(subdomains)} subs, {len(paths)} paths, {len(crawled)} crawled"
            )
        )
        if addresses:
            print(f"  Addresses: {', '.join(addresses)}")
        else:
            print("  Addresses: none")

        if sub_scan_skipped:
            print("  Subdomains: skipped (input includes subdomain or disabled)")
        elif subdomains:
            print("  Subdomains:")
            for entry in subdomains:  # type: ignore[assignment]
                host = entry.get("host", "?")
                addrs = entry.get("addresses") or []
                addr_str = ", ".join(addrs) if addrs else "no A/AAAA"
                print(f"    - {host} -> {addr_str}")
        else:
            print("  Subdomains: none")

        filtered_paths = []
        seen_path_urls: set[str] = set()
        for entry in paths:  # type: ignore[assignment]
            url = entry.get("url", "?")
            status = entry.get("status", 0)
            ctype = (entry.get("content_type") or "").lower()
            if status not in (200, 201, 204, 301, 302, 307, 308, 401):
                continue
            if ctype and not any(t in ctype for t in ("html", "json", "xml", "plain")):
                continue
            if is_asset(url, entry.get("content_type")):
                continue
            if url in seen_path_urls:
                continue
            seen_path_urls.add(url)
            filtered_paths.append(entry)

        if filtered_paths:
            print("  Paths (404s filtered):")
            for entry in filtered_paths:
                url = entry.get("url", "?")
                status = entry.get("status", "?")
                ctype = entry.get("content_type")
                title = entry.get("title")
                extra = f" ({ctype})" if ctype else ""
                ttl = f" | {title}" if title else ""
                print(f"    - {fmt_url(url)} -> HTTP {fmt_status(status)}{extra}{ttl}")
        else:
            print("  Paths: none")

        filtered_crawl = []
        seen_crawl_urls: set[str] = set()
        for entry in crawled:  # type: ignore[assignment]
            url = entry.get("url", "?")
            status = entry.get("status", 0)
            if is_asset(url, entry.get("content_type")):
                continue
            if status not in (200, 201, 204, 301, 302, 307, 308, 401):
                continue
            ctype_lower = (entry.get("content_type") or "").lower()
            if ctype_lower and not any(t in ctype_lower for t in ("html", "json", "xml", "plain")):
                continue
            if url in seen_crawl_urls:
                continue
            seen_crawl_urls.add(url)
            filtered_crawl.append(entry)

        if filtered_crawl:
            print("  Crawled URLs:")
            for entry in filtered_crawl:
                url = entry.get("url", "?")
                status = entry.get("status", "?")
                ctype = entry.get("content_type")
                title = entry.get("title")
                extra = f" ({ctype})" if ctype else ""
                ttl = f" | {title}" if title else ""
                print(f"    - {fmt_url(url)} -> HTTP {fmt_status(status)}{extra}{ttl}")
        else:
            print("  Crawled URLs: none")

        if js_endpoints:
            print("  JS endpoints:")
            for url in filter_js_endpoints(set(js_endpoints)):  # type: ignore[assignment]
                print(f"    - {fmt_url(url)}")
        else:
            print("  JS endpoints: none")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Brute force subdomains and probe common paths for a domain."
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domain to inspect (with or without TLD). If omitted, you will be prompted.",
    )
    parser.add_argument(
        "--scheme",
        default="https",
        choices=("http", "https"),
        help="Scheme to use when probing paths (default: https).",
    )
    parser.add_argument(
        "--sub-wordlist",
        type=Path,
        help="Optional subdomain wordlist file (one entry per line).",
    )
    parser.add_argument(
        "--path-wordlist",
        type=Path,
        help="Optional path wordlist file (one entry per line).",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES.keys()),
        help="Preset scan profile (quick, deep, all). If not set and no flags are provided, you will be prompted.",
    )
    parser.add_argument(
        "--extensions",
        type=str,
        default=",".join(ext for ext in DEFAULT_EXTENSIONS if ext),
        help="Comma-separated extensions to try for paths without an extension (default: .php,.html,.htm,.json,.txt,.xml). Use empty string to disable.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Maximum concurrent lookups/requests (default: 20).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Network timeout in seconds for DNS and HTTP (default: 3.0).",
    )
    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Skip subdomain enumeration.",
    )
    parser.add_argument(
        "--no-paths",
        action="store_true",
        help="Skip path probing.",
    )
    parser.add_argument(
        "--paths-on-subdomains",
        action="store_true",
        help="Probe paths against each discovered subdomain as well as the base domain.",
    )
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Crawl target(s) for additional URLs within the same host.",
    )
    parser.add_argument(
        "--crawl-depth",
        type=int,
        default=1,
        help="Maximum crawl depth (default: 1).",
    )
    parser.add_argument(
        "--crawl-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl per host (default: 50).",
    )
    parser.add_argument(
        "--crawl-on-subdomains",
        action="store_true",
        help="Also crawl each discovered subdomain when crawling is enabled.",
    )
    parser.add_argument(
        "--soft404-samples",
        type=int,
        default=2,
        help="Number of random missing pages to fingerprint for soft-404 detection (default: 2).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in output.",
    )
    parser.add_argument(
        "--keep-wildcard",
        action="store_true",
        help="Continue subdomain brute force even if wildcard DNS is detected.",
    )
    parser.add_argument(
        "--include-server-errors",
        action="store_true",
        help="Keep HTTP 5xx responses in the output (default: drop them).",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Write results to a JSON file in addition to stdout.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    global COLOR
    COLOR = Color(enabled=not args.no_color and sys.stdout.isatty())

    socket.setdefaulttimeout(args.timeout)

    sub_words = load_wordlist(args.sub_wordlist, DEFAULT_SUBDOMAIN_WORDS)
    path_words = load_wordlist(args.path_wordlist, DEFAULT_PATH_WORDS)

    user_supplied = args.domain
    if not user_supplied:
        try:
            user_supplied = input("Enter a domain: ").strip()
        except EOFError:
            user_supplied = ""

    domain_input = sanitize_domain_input(user_supplied or "")
    if not domain_input:
        print("[!] No domain provided. Exiting.")
        return

    def apply_profile(name: str, a: argparse.Namespace) -> None:
        profile = PROFILES.get(name)
        if not profile:
            return
        a.paths_on_subdomains = bool(profile.get("paths_on_subdomains", a.paths_on_subdomains))
        a.crawl = bool(profile.get("crawl", a.crawl))
        a.crawl_on_subdomains = bool(profile.get("crawl_on_subdomains", a.crawl_on_subdomains))
        a.crawl_depth = int(profile.get("crawl_depth", a.crawl_depth))
        a.crawl_pages = int(profile.get("crawl_pages", a.crawl_pages))
        a.soft404_samples = int(profile.get("soft404_samples", a.soft404_samples))
        a.extensions = str(profile.get("extensions", a.extensions))
        a.include_server_errors = bool(profile.get("include_server_errors", a.include_server_errors))

    apply_profile(args.profile or "all", args)

    input_is_subdomain = is_subdomain(domain_input, DEFAULT_TLDS)
    has_tld = "." in domain_input
    candidates = [domain_input] if has_tld else build_candidate_domains(domain_input, DEFAULT_TLDS)

    if has_tld:
        print("[*] Resolving provided domain...")
        domains = resolve_domains(candidates, prefix="Resolve")
    else:
        print("[*] Checking common TLDs...")
        domains = resolve_domains(candidates, prefix="TLD check")
    if not domains:
        print("[!] No resolvable domains found from the input.")
        return

    ext_list_raw = [item.strip() for item in args.extensions.split(",")] if args.extensions is not None else []
    extensions = [ext for ext in ext_list_raw if ext or ext == ""]
    if not extensions:
        extensions = [""]
    if "" not in extensions:
        extensions.insert(0, "")

    results: Dict[str, Dict[str, object]] = {}

    for domain_entry in domains:
        domain = str(domain_entry["domain"])
        print(f"\n[>] Processing {domain}")
        results[domain] = {
            "addresses": domain_entry.get("addresses", []),
            "subdomains": [],
            "paths": [],
            "subdomain_scan_skipped": input_is_subdomain or args.no_subdomains,
            "crawled": [],
            "js_endpoints": [],
        }

        if not args.no_subdomains and not input_is_subdomain:
            print(f"[*] Enumerating subdomains for {domain}")
            subdomains = enumerate_subdomains(
                domain=domain,
                words=sub_words,
                threads=args.threads,
                ignore_wildcard=not args.keep_wildcard,
            )
            results[domain]["subdomains"] = subdomains
        else:
            if input_is_subdomain:
                print("[*] Input includes a subdomain; skipping subdomain brute force.")
            else:
                print("[*] Skipping subdomain enumeration.")
            subdomains = []

        base_url = f"{args.scheme}://{domain}"
        targets: List[str] = [base_url]
        if subdomains and args.paths_on_subdomains:
            targets.extend(f"{args.scheme}://{entry['host']}" for entry in subdomains)

        if not args.no_paths:
            js_endpoints: set[str] = set()
            for target in targets:
                print(f"[*] Probing paths on {target}")
                soft404_sigs = make_soft_404_signatures(
                    target, timeout=args.timeout, samples=max(1, args.soft404_samples)
                )
                results[domain]["paths"].extend(
                    enumerate_paths(
                        base_url=target,
                        words=path_words,
                        threads=args.threads,
                        timeout=args.timeout,
                        include_server_errors=args.include_server_errors,
                        soft404_signatures=soft404_sigs,
                        extensions=extensions,
                        js_endpoints=js_endpoints,
                    )
                )
            filtered = filter_js_endpoints(js_endpoints)
            results[domain]["js_endpoints"] = validate_js_endpoints(filtered, timeout=args.timeout)
        else:
            print("[*] Skipping path probing.")

        if args.crawl:
            crawl_targets: List[str] = [base_url]
            if args.crawl_on_subdomains and subdomains:
                crawl_targets.extend(f"{args.scheme}://{entry['host']}" for entry in subdomains)

            js_endpoints: set[str] = set()
            for target in crawl_targets:
                print(f"[*] Crawling {target}")
                soft404_sigs = make_soft_404_signatures(
                    target, timeout=args.timeout, samples=max(1, args.soft404_samples)
                )
                results[domain]["crawled"].extend(
                    crawl_site(
                        base_url=target,
                        max_depth=max(0, args.crawl_depth),
                        max_pages=max(1, args.crawl_pages),
                        timeout=args.timeout,
                        include_server_errors=args.include_server_errors,
                        soft404_signatures=soft404_sigs,
                        js_endpoints=js_endpoints,
                    )
                )
            combined_endpoints = set(results[domain].get("js_endpoints", [])) | js_endpoints
            filtered = filter_js_endpoints(combined_endpoints)
            results[domain]["js_endpoints"] = validate_js_endpoints(filtered, timeout=args.timeout)
        else:
            print("[*] Skipping crawl.")

    print_report(results)

    if args.output_json:
        args.output_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"[*] Results written to {args.output_json}")


if __name__ == "__main__":
    main()
