#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
import threading
import time
from datetime import timedelta
from typing import Dict, List, Optional
import urllib.parse
from pathlib import Path

import pyfiglet
import requests
from bs4 import BeautifulSoup
from termcolor import colored

# Try import serpapi client library; if not available we'll fallback to REST API
try:
    from serpapi import GoogleSearch  # type: ignore
    SERPAPI_AVAILABLE = True
except Exception:
    SERPAPI_AVAILABLE = False

# sensitive_config is expected to exist with SENSITIVE_KEYWORDS, SEVERITY_COLOR, SEVERITY_MAP
try:
    from sensitive_config import SENSITIVE_KEYWORDS, SEVERITY_COLOR, SEVERITY_MAP
except Exception:
    # Minimal fallback so the script remains runnable for testing
    SENSITIVE_KEYWORDS = ["password", "passwd", ".sql", ".env", "secret", "api_key", "token", "private_key"]
    SEVERITY_COLOR = {"critical": ("red", ["bold"]), "high": "red", "low": "yellow", "medium": "magenta"}
    SEVERITY_MAP = {}

STOP_REQUESTED = False

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def get_user_config_path() -> Path:
    """
    Returns the user-level configuration path to store persistent settings like SerpAPI key.
    Linux/macOS: ~/.config/DorkDigger/config.json
    Windows: %APPDATA%/DorkDigger/config.json
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "DorkDigger" / "config.json"
    else:
        return Path.home() / ".config" / "DorkDigger" / "config.json"

def load_user_config() -> Dict[str, str]:
    cfg_path = get_user_config_path()
    try:
        if cfg_path.exists():
            return json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def save_user_config(cfg: Dict[str, str]) -> None:
    cfg_path = get_user_config_path()
    try:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        # Non-fatal; just proceed without persistence
        pass

def _read_key_from_file_if_exists(filename: str) -> Optional[str]:
    """
    Read a single-line KEY=VALUE style file and return VALUE for SERPAPI_KEY=...
    """
    try:
        p = Path(filename)
        if not p.exists():
            return None
        txt = p.read_text(encoding="utf-8", errors="ignore")
        for ln in txt.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("SERPAPI_KEY="):
                return s.split("=", 1)[1].strip()
        return None
    except Exception:
        return None

def _resolve_serpapi_key(cli_key: Optional[str]) -> Optional[str]:
    """
    Resolve the SerpAPI key from multiple sources and persist it for future runs if provided via CLI.
    Priority:
      1) CLI flag --serpapi-key
      2) Environment variable SERPAPI_KEY
      3) Local file SERPAPI_KEY.env (same dir)
      4) User-level config file (persisted key)
    If CLI key is provided, it will be stored in user-level config for future runs.
    """
    # 1) CLI flag
    if cli_key and cli_key.strip():
        key = cli_key.strip()
        cfg = load_user_config()
        cfg["SERPAPI_KEY"] = key
        save_user_config(cfg)
        return key

    # 2) Environment
    env_key = os.environ.get("SERPAPI_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    # 3) Local file SERPAPI_KEY.env
    file_key = _read_key_from_file_if_exists("SERPAPI_KEY.env")
    if file_key and file_key.strip():
        return file_key.strip()

    # 4) User-level config
    cfg = load_user_config()
    cfg_key = cfg.get("SERPAPI_KEY")
    if cfg_key and cfg_key.strip():
        return cfg_key.strip()

    return None

def load_hide_keywords(path: str = "hide_keywords.txt") -> List[str]:
    if os.path.exists(path):
        items: List[str] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for ln in fh:
                    s = ln.strip()
                    if not s or s.startswith("#"):
                        continue
                    items.append(s.lower())
        except Exception:
            return []
        return items
    return [
        "microsoft.com", "sqlshack.com", "hasura.io", "tutorialspoint.com",
        "morningstar.com", "monnit.com", "reddit.com", "getfishtank.com",
        "linkedin.com", "youtube.com", "geeksforgeeks.org", "stackoverflow.com",
        "learn",
    ]

HIDE_KEYWORDS = load_hide_keywords()

def build_query(dork: str, site: Optional[str] = None, inurl_terms: Optional[List[str]] = None,
                intext: Optional[str] = None, filetype: Optional[str] = None, intitle: Optional[str] = None) -> str:
    parts: List[str] = []
    if site:
        parts.append(f"site:{site}")
    if intext:
        parts.append(f"intext:{intext}")
    if intitle:
        parts.append(f"intitle:{intitle}")
    if filetype:
        ft = filetype
        if ft.startswith("filetype:"):
            parts.append(ft)
        else:
            parts.append(f"filetype:{ft}")
    if dork:
        parts.append(dork)
    if inurl_terms:
        for t in inurl_terms:
            parts.append(f"inurl:{t}")
    return " ".join(parts)

def extract_ddg_real_url(href: str) -> Optional[str]:
    if not href:
        return None
    if href.startswith("/l/?kh=") and "uddg=" in href:
        try:
            part = href.split("uddg=", 1)[1]
            return urllib.parse.unquote(part)
        except Exception:
            return None
    if href.startswith("http"):
        return href
    return None

def search_duckduckgo_html(query: str, max_results: int = 25, sleep: float = 1.0, timeout: int = 10) -> List[str]:
    time.sleep(sleep)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) dork-monitor/1.0"}
    data = {"q": query}
    try:
        r = requests.post("https://html.duckduckgo.com/html/", data=data, headers=headers, timeout=timeout)
        r.raise_for_status()
    except Exception:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    results: List[str] = []
    for a in soup.find_all("a", {"class": "result__a"}, href=True):
        real = extract_ddg_real_url(a["href"])
        if real:
            results.append(real)
        if len(results) >= max_results:
            break
    if len(results) < max_results:
        for a in soup.find_all("a", href=True):
            real = extract_ddg_real_url(a["href"])
            if real and real.startswith("http") and real not in results:
                results.append(real)
            if len(results) >= max_results:
                break
    return results[:max_results]

def search_serpapi(query: str, serpapi_key: str, engine_name: str = "google",
                   max_results: int = 25, sleep: float = 1.0, site_filter: Optional[str] = None) -> List[str]:
    """
    Search SerpAPI and return list of links.

    This function will:
      - use the serpapi Python client if installed
      - otherwise fallback to the SerpAPI HTTP endpoint (requests)
    """
    time.sleep(sleep)
    if SERPAPI_AVAILABLE:
        try:
            params = {"engine": engine_name, "q": query, "api_key": serpapi_key, "num": max_results}
            search = GoogleSearch(params)
            results = search.get_dict() or {}
        except Exception:
            results = {}
        raw_links: List[str] = []
        if isinstance(results.get("organic_results"), list):
            for r in results["organic_results"]:
                if isinstance(r, dict) and r.get("link"):
                    raw_links.append(r["link"])
                    if len(raw_links) >= max_results:
                        break
        if len(raw_links) < max_results:
            for v in results.values():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and item.get("link"):
                            raw_links.append(item["link"])
                            if len(raw_links) >= max_results:
                                break
                if len(raw_links) >= max_results:
                    break
        filtered: List[str] = []
        for link in raw_links:
            if not isinstance(link, str):
                continue
            l = link.strip()
            if not l.startswith(("http://", "https://")):
                continue
            low = l.lower()
            if "google.com/search" in low or "bing.com/search" in low:
                continue
            if site_filter and site_filter.lower() not in low:
                continue
            if l not in filtered:
                filtered.append(l)
            if len(filtered) >= max_results:
                break
        return filtered
    else:
        url = "https://serpapi.com/search.json"
        params = {"engine": engine_name, "q": query, "api_key": serpapi_key, "num": max_results}
        try:
            r = requests.get(url, params=params, timeout=15, headers={"User-Agent": "dork-monitor/1.0"})
            r.raise_for_status()
            data = r.json()
        except Exception:
            return []
        raw_links: List[str] = []
        if isinstance(data.get("organic_results"), list):
            for ritem in data["organic_results"]:
                if isinstance(ritem, dict) and ritem.get("link"):
                    raw_links.append(ritem["link"])
                    if len(raw_links) >= max_results:
                        break
        if len(raw_links) < max_results:
            for v in data.values():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and item.get("link"):
                            raw_links.append(item["link"])
                            if len(raw_links) >= max_results:
                                break
                if len(raw_links) >= max_results:
                    break
        filtered: List[str] = []
        for link in raw_links:
            if not isinstance(link, str):
                continue
            l = link.strip()
            if not l.startswith(("http://", "https://")):
                continue
            low = l.lower()
            if "google.com/search" in low or "bing.com/search" in low:
                continue
            if site_filter and site_filter.lower() not in low:
                continue
            if l not in filtered:
                filtered.append(l)
            if len(filtered) >= max_results:
                break
        return filtered

def is_real_http_link(link: str) -> bool:
    if not link or not link.startswith(("http://", "https://")):
        return False
    low = link.lower()
    if "google.com/search" in low or "bing.com/search" in low:
        return False
    return True

def is_sensitive_link(link: str, keywords: Optional[List[str]] = None,
                      timeout: int = 10, max_bytes: int = 200000) -> Optional[str]:
    if not keywords:
        keywords = SENSITIVE_KEYWORDS
    low_link = (link or "").lower()
    for kw in keywords:
        if kw.lower() in low_link:
            return kw
    if not link or not link.startswith(("http://", "https://")):
        return None
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) dork-monitor/1.0"}
    try:
        resp = requests.get(link, headers=headers, timeout=timeout, stream=True)
        resp.raise_for_status()
    except Exception:
        return None
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if ("image/" in content_type) or ("video/" in content_type) or ("application/octet-stream" in content_type):
        lower_url = link.lower()
        if not lower_url.endswith((".sql", ".txt", ".env", ".log", ".csv", ".json", ".xml", ".php", ".ini", ".conf")):
            return None
    try:
        chunks = []
        read = 0
        for chunk in resp.iter_content(chunk_size=4096, decode_unicode=True):
            if not chunk:
                break
            if isinstance(chunk, bytes):
                try:
                    chunk = chunk.decode(errors="replace")
                except Exception:
                    chunk = chunk.decode("utf-8", errors="replace")
            chunks.append(chunk); read += len(chunk)
            if read >= max_bytes:
                break
        text = "".join(chunks).lower()
    except Exception:
        try:
            text = resp.text.lower()
        except Exception:
            return None
    for kw in keywords:
        if kw.lower() in text:
            return kw
    return None

def alert_type_from_keyword(keyword: str, link: str) -> str:
    k = (keyword or "").lower()
    l = (link or "").lower()
    if any(x in l or x in k for x in [".sql","dump.sql","backup.sql","database.sql","db.sql","sql"]):
        return "sql"
    if ".env" in l or ".env" in k:
        return "env"
    if any(x in k for x in ["password","passwd","pwd","pass","credential","credentials","auth","token","bearer","jwt"]):
        return "credentials"
    if any(x in k for x in ["aws_","gcp","service-account","master.key","secret_key_base","google_api_key","azure_"]):
        return "cloud-keys"
    if any(x in k for x in ["id_rsa","private_key","ssh","pem","ppk","server.key","tls.key","key.pem","private.pem"]):
        return "keys"
    if any(x in k for x in ["log","trace","stacktrace","core",".log","debug"]):
        return "logs"
    if any(x in k for x in ["docker","kubernetes","k8s","helm","jenkins",".gitlab-ci",".travis","azure-pipelines","circleci"]):
        return "ci-cd"
    if any(x in k for x in ["config","settings","application.properties","application.yml","web.config","wp-config.php"]):
        return "config"
    if any(x in k for x in ["backup","dump","archive","staging","old"]):
        return "backup"
    return "general"

def classify_severity(keyword: str, link: str = "") -> str:
    k = (keyword or "").lower()
    if k in SEVERITY_MAP:
        return SEVERITY_MAP[k]
    l = (link or "").lower()
    if any(x in l for x in [".sql","dump.sql","backup.sql","database.sql","db.sql"]):
        return "high"
    if ".env" in l:
        return "critical"
    if any(x in k for x in ["password","passwd","credentials","auth","token","jwt"]):
        return "high"
    if any(x in k for x in ["log","trace","debug"]):
        return "low"
    return "low"

def save_outputs(alerts: List[Dict], all_found: List[str], out_prefix: str):
    txt_path = f"{out_prefix}.txt"
    with open(txt_path, "w", encoding="utf-8") as tf:
        for line in all_found:
            tf.write(line + "\n")
    json_path = f"{out_prefix}.json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(alerts, jf, ensure_ascii=False, indent=2)
    csv_path = f"{out_prefix}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["timestamp","dork","query","found_link","reason_keyword","type","severity"])
        for a in alerts:
            writer.writerow([
                a.get("timestamp"), a.get("dork"), a.get("query"),
                a.get("link"), a.get("keyword"), a.get("type"), a.get("severity")
            ])

def end_progress_line():
    try:
        sys.stdout.write("\n")
        sys.stdout.flush()
    except Exception:
        pass

def print_progress(done: int, total: int, extra: str = ""):
    pct = (done / total * 100) if total else 0
    msg = f"[>] Searching ({done}/{total}) {pct:.0f}% {extra}"
    try:
        sys.stdout.write("\r" + msg + " " * 20)
        sys.stdout.flush()
    except Exception:
        pass

def _keypress_watcher():
    global STOP_REQUESTED
    try:
        import sys, tty, termios, select
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1)
                    if ch.lower() == 'q':
                        STOP_REQUESTED = True
                        break
                if STOP_REQUESTED:
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        return

def start_key_listener():
    t = threading.Thread(target=_keypress_watcher, daemon=True)
    t.start()

def load_dorks_from_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as inf:
            items: List[str] = []
            for line in inf:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
                    s = s[1:-1]
                items.append(s)
            return items
    except Exception:
        return []

def main(
    dorks: List[str],
    site: Optional[str] = None,
    inurl: Optional[str] = None,
    intext: Optional[str] = None,
    filetype: Optional[str] = None,
    intitle: Optional[str] = None,
    max_results: int = 25,
    sleep: float = 1.0,
    out_prefix: str = "alerts",
    engine: str = "duckduckgo",
    serpapi_key: Optional[str] = None,
    serpapi_engine_name: str = "google"
):
    inurl_terms: List[str] = []
    if inurl:
        inurl_terms = [t.strip() for t in inurl.split(",") if t.strip()]

    all_alerts: List[Dict] = []
    all_found_links: List[str] = []

    start_time = time.time()
    print(f"[+] Starting scan at {now_iso()} — engine={engine} (serpapi engine={serpapi_engine_name})", flush=True)

    # Normalize dorks input
    if isinstance(dorks, str):
        if os.path.exists(dorks):
            dorks = load_dorks_from_file(dorks) or []
        else:
            dorks = [dorks]
    dorks = [d.strip() for d in dorks if isinstance(d, str) and d.strip()]
    total_dorks = len(dorks)
    print(f"[+] Loaded {total_dorks} dorks (not displayed)", flush=True)

    # Resolve SerpAPI key if using serpapi
    resolved_key = None
    if engine == "serpapi":
        resolved_key = _resolve_serpapi_key(serpapi_key)
        if not resolved_key:
            print("[!] SerpAPI engine requested but no API key found. Provide --serpapi-key once; it will be saved for future runs.", flush=True)
            return []

        if not SERPAPI_AVAILABLE:
            print("[!] Note: serpapi python client not installed. Falling back to SerpAPI REST HTTP calls.", flush=True)
            print("[!] To use the SerpAPI client library install: pip install google-search-results", flush=True)

    start_key_listener()

    completed = 0
    # initial progress
    print_progress(0, total_dorks, extra="starting")

    for idx, dork in enumerate(dorks, start=1):
        if STOP_REQUESTED:
            print("\n[!] Stop requested by user (q). Ending scan early...", flush=True)
            break

        q = build_query(dork, site=site, inurl_terms=inurl_terms, intext=intext, filetype=filetype, intitle=intitle)

        # show progress for this dork (do NOT display the dork itself)
        print_progress(idx - 1, total_dorks, extra=f"searching ({idx}/{total_dorks})")

        try:
            if engine == "serpapi":
                results = search_serpapi(
                    q, serpapi_key=resolved_key or "", engine_name=serpapi_engine_name,
                    max_results=max_results, sleep=sleep, site_filter=site
                )
            else:
                results = search_duckduckgo_html(q, max_results=max_results, sleep=sleep)
        except Exception as e:
            print(f"\n[!] Search error for dork #{idx}: {str(e)}", flush=True)
            results = []

        per_dork_results: List[str] = []
        per_dork_alerts: List[Dict] = []

        for link in results:
            if not is_real_http_link(link):
                continue
            low_link = link.lower()
            if any(hk in low_link for hk in HIDE_KEYWORDS):
                continue
            if inurl_terms:
                match_all = True
                for term in inurl_terms:
                    if term.lower() not in low_link:
                        match_all = False
                        break
                if not match_all:
                    continue
            kw = is_sensitive_link(link)
            all_found_links.append(link)
            per_dork_results.append(link)
            if kw:
                a_type = alert_type_from_keyword(kw, link)
                severity = classify_severity(kw, link)
                alert = {
                    "timestamp": now_iso(),
                    "dork": dork,
                    "query": q,
                    "link": link,
                    "keyword": kw,
                    "type": a_type,
                    "severity": severity,
                }
                all_alerts.append(alert)
                per_dork_alerts.append(alert)

        # finished this dork search
        completed = idx
        print_progress(completed, total_dorks, extra=f"done ({completed}/{total_dorks})")

        if STOP_REQUESTED:
            print("\n[!] Stop requested by user (q). Ending scan early...", flush=True)
            break

    end_progress_line()
    end_progress_line()

    save_outputs(all_alerts, all_found_links, out_prefix)
    print(f"[+] Saved: {out_prefix}.txt, {out_prefix}.json, {out_prefix}.csv", flush=True)

    unique_links: List[str] = []
    for l in all_found_links:
        if l not in unique_links:
            unique_links.append(l)

    print("[>] Results:")
    if not unique_links:
        print("    - No results found during the scan.")
    else:
        for link in unique_links:
            print(f"    -> {link}")

    if all_alerts:
        print("[+] Alerts summary:")
        for a in all_alerts:
            sev = a.get("severity", "low")
            color = SEVERITY_COLOR.get(sev, "white")
            attrs = []
            try:
                if isinstance(color, tuple):
                    color_name, attrs = color
                else:
                    color_name = color
            except Exception:
                color_name = "white"
                attrs = []
            kw = a.get("keyword", "")
            a_type = a.get("type", "general")
            link = a.get("link", "")
            msg = f"⚠ Sensitive ({a_type}) -> {link} (matched '{kw}', severity={sev})"
            try:
                print(colored(msg, color_name, attrs=attrs))
            except Exception:
                print(msg)
    else:
        print("[+] No alerts found.")

    elapsed_seconds = max(0, int(time.time() - start_time))
    elapsed_str = str(timedelta(seconds=elapsed_seconds))
    print(f"[+] Finished at {now_iso()} (elapsed: {elapsed_str})", flush=True)

    return all_alerts

if __name__ == "__main__":
    ascii_banner = pyfiglet.figlet_format("DORK DIGGER")
    try:
        print(colored(ascii_banner, 'red'))
    except Exception:
        print(ascii_banner)
    print(colored("Welcome to Dork Digger Tool!", 'yellow'))
    print(colored("Author: Hesham Khaled | GitHub: HeshamKhaled1 | Linkedin: linkedin.com/in/deebo000", 'cyan'))
    print(colored("Press 'q' at any time to stop the scan early.\n", 'green'))

    parser = argparse.ArgumentParser(description="Dork monitoring tool (duckduckgo or serpapi).")
    parser.add_argument("--dorks-file", "-f", help="Path to a file with dorks (one per line).")
    parser.add_argument("--site", "-s", help="Optional site to prepend as site:example.com")
    parser.add_argument("--inurl", "-u", help='Optional inurl terms (comma-separated). Example: ".eg,.sa"')
    parser.add_argument("--intext", help='Optional intext term to include in queries. Example: "\"password\""')
    parser.add_argument("--filetype", help='Optional filetype to include in queries. Example: "sql" or "filetype:sql"')
    parser.add_argument("--intitle", help='Optional intitle term to include in queries. Example: "\"index of\""')
    parser.add_argument("--max-results", "-m", type=int, default=25, help="Max results per dork")
    parser.add_argument("--sleep", type=float, default=1.0, help="Seconds between searches (throttle)")
    parser.add_argument("--out-prefix", default="alerts", help="Prefix for alerts TXT/JSON/CSV output")
    parser.add_argument("--engine", choices=["duckduckgo", "serpapi"], default="duckduckgo", help="Search engine to use")
    parser.add_argument("--serpapi-key", help="SerpAPI key (optional, provide once; will be saved for future runs)")
    parser.add_argument("--serpapi-engine", choices=["google", "bing"], default="google", help="Which engine to query via SerpAPI")
    args = parser.parse_args()

    default_dorks = [
        'intitle:index of /etc/ssh inurl:".sa"',
        'intitle:index of /etc/ssh inurl:".eg"',
        'intitle:index of /etc',
        'intitle:index of /etc inurl:".eg"',
        'intitle:"index of" ".sql"',
        'intitle:"index of" "database.sql"',
        'inurl:backup filetype:sql',
        'intext:"index of" ".sql"',
    ]

    if args.dorks_file:
        dorks = load_dorks_from_file(args.dorks_file) or default_dorks
    elif os.path.exists("dorks.txt"):
        dorks = load_dorks_from_file("dorks.txt") or default_dorks
    else:
        dorks = default_dorks

    # Resolve key once here so we can fail early if user asked for serpapi
    resolved_key = _resolve_serpapi_key(args.serpapi_key)
    if args.engine == "serpapi" and not resolved_key:
        print("SerpAPI engine requested but no API key found. Provide --serpapi-key YOUR_KEY once to save it persistently.")
        sys.exit(1)

    main(
        dorks=dorks,
        site=args.site,
        inurl=args.inurl,
        intext=args.intext,
        filetype=args.filetype,
        intitle=args.intitle,
        max_results=args.max_results,
        sleep=args.sleep,
        out_prefix=args.out_prefix,
        engine=args.engine,
        serpapi_key=resolved_key,  # pass resolved
        serpapi_engine_name=args.serpapi_engine
    )
