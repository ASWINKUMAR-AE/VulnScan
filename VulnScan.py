#!/usr/bin/env python3
"""
vulnscan.py

A consolidated vulnerability scanning helper:
- Crawls internal URLs (simple crawler)
- Extracts <script> blocks and deduplicates
- Prefilters JS snippets for suspicious patterns
- Optionally runs Semgrep (SAST) on local source if desired
- Sends shortlisted JS snippets in chunks to OpenRouter Chat Completions
  (uses OPENROUTER_API_KEY environment variable)
- Writes machine-parseable JSON-lines output: chatGPT_<JS_UNIQUE_FILE>.jsonl
- Produces a human-friendly final report 'final_<domain>.txt'

Notes:
- Do NOT commit your API keys.
- Use temperature=0.0 for deterministic output.
"""

import os
import re
import sys
import time
import json
import textwrap
import hashlib
import requests
import subprocess
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Import OpenRouter's OpenAI-compatible client
from openai import OpenAI

# ---------------------------
# Configurable parameters
# ---------------------------
MODEL = "openai/chatgpt-4o-latest"  # OpenRouter model name
CHUNK_SIZE = 3000      # chunk size for sending to model (chars)
MAX_RECURSION = 1      # default recursion if not provided interactively
REQUESTS_TIMEOUT = 15  # seconds
USER_AGENT = "Mozilla/5.0 (VulnScan/1.0)"
SEMgrep_ENABLED = True  # set False to skip semgrep step
SEMgrep_CONFIG = "auto"  # can be 'p/ci' or 'auto' or a rules file
OUTPUT_DIR = "."

# OpenRouter API Key (loaded from environment variable or local API_Key.txt)
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
if not OPENROUTER_API_KEY and os.path.exists("API_Key.txt"):
    try:
        with open("API_Key.txt", "r") as f:
            OPENROUTER_API_KEY = f.read().strip()
    except Exception:
        pass

# Initialize OpenRouter client globally
client = None

def init_openrouter_client():
    global client
    api_key = OPENROUTER_API_KEY
    if not api_key:
        print("[!] ERROR: OPENROUTER_API_KEY is not set.")
        sys.exit(1)
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

# ---------------------------
# Utility helpers
# ---------------------------
def safe_request_get(url, headers=None, timeout=REQUESTS_TIMEOUT):
    headers = headers or {}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r
    except Exception as e:
        print(f"[!] Request error for {url}: {e}")
        return None


def normalize_url(base, link):
    if not link:
        return None
    parsed = urlparse(link)
    if parsed.scheme in ("http", "https"):
        return link.rstrip('/')
    # relative
    try:
        return urljoin(base, link).rstrip('/')
    except Exception:
        return None


def domain_from_url(url):
    parsed = urlparse(url)
    host = parsed.netloc.split(':')[0]
    parts = host.split('.')
    if len(parts) >= 2:
        return parts[-2] + '.' + parts[-1]
    return host

# ---------------------------
# Crawler / URL Finder
# ---------------------------
def crawl_website_seed(url, max_recursion=1):
    """
    Crawl internal links up to max_recursion depth (BFS-style).
    Returns a sorted list of unique URLs (including the seed).
    """
    headers = {"User-Agent": USER_AGENT}
    domain = urlparse(url).netloc
    visited = set()
    to_visit = [(url, 0)]
    results = []

    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        r = safe_request_get(current_url, headers=headers)
        if not r or r.status_code != 200 or not r.text:
            continue

        results.append(r.url.rstrip('/'))  # final resolved url

        # if depth < max_recursion: parse links
        if depth < max_recursion:
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                norm = normalize_url(r.url, a.get('href'))
                if not norm:
                    continue
                parsed = urlparse(norm)
                if parsed.netloc == domain and norm not in visited:
                    to_visit.append((norm, depth + 1))

        # Try sitemap.xml and robots.txt at root (only at first page)
        if depth == 0:
            base = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"
            for extra in ["/sitemap.xml", "/robots.txt"]:
                try:
                    er = safe_request_get(base + extra, headers=headers)
                    if er and er.status_code == 200 and er.text:
                        # crude extraction of links from sitemap or robots
                        for link in re.findall(r'(https?://[^\s"\'<>]+)', er.text):
                            if urlparse(link).netloc == domain:
                                results.append(link.rstrip('/'))
                except Exception:
                    pass

    unique_sorted = sorted(set(results))
    return unique_sorted

# ---------------------------
# JavaScript extraction & dedupe
# ---------------------------
def extract_js_snippets(urls, js_unique_filename):
    """
    For each url: fetch, parse <script> tags, deduplicate by hash.
    Writes: JS_URL_<domain>.json (mapping id->url/xpath/dup info).
    Writes unique snippets into JS_Unique_<domain>.txt delimited by --- blocks.
    Returns list of dictionaries: { "id": "(idX,JS#Y)", "snippet": "...", "url": "...", "xpath": "..."}
    """
    seen_hashes = {}
    outputs = []
    domain = domain_from_url(urls[0]) if urls else "domain"
    js_url_fname = os.path.join(OUTPUT_DIR, f"JS_URL_{domain}.json")
    js_unique_fname = os.path.join(OUTPUT_DIR, js_unique_filename)

    # ensure files reset
    open(js_unique_fname, "w", encoding="utf-8").close()
    open(js_url_fname, "w", encoding="utf-8").close()

    counter = 1
    for u in urls:
        r = safe_request_get(u, headers={"User-Agent": USER_AGENT})
        if not r or r.status_code != 200 or not r.text:
            continue
        soup = BeautifulSoup(r.text, 'html.parser')
        script_tags = soup.find_all('script')

        script_counter = 1
        for script in script_tags:
            text = script.string if script.string is not None else (script.get_text() or "")
            if not text.strip():
                script_counter += 1
                continue

            # compute hash
            h = hashlib.sha256(text.strip().encode('utf-8')).hexdigest()
            id_label = f"id{counter},JS#{script_counter}"
            xpath = build_xpath(script)

            if h in seen_hashes:
                # log duplication
                dup_entry = {"id": id_label, "url": u, "xpath": xpath, "duplication": seen_hashes[h]}
                with open(js_url_fname, "a", encoding="utf-8") as f:
                    f.write(json.dumps(dup_entry) + "\n")
            else:
                seen_hashes[h] = id_label
                # write JS_Unique file with snippet block
                with open(js_unique_fname, "a", encoding="utf-8") as f:
                    f.write("\n---\n")
                    f.write(f"({id_label})\n\n")
                    f.write(text.strip() + "\n")
                    f.write("---\n")
                entry = {"id": f"({id_label})", "snippet": text.strip(), "url": u, "xpath": xpath}
                outputs.append(entry)
                with open(js_url_fname, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"id": f"({id_label})", "url": u, "xpath": xpath}) + "\n")

            script_counter += 1
        counter += 1

    return outputs, js_unique_fname, js_url_fname

def build_xpath(element):
    """
    Build a crude xpath-like path for the script element.
    """
    try:
        parts = []
        el = element
        while el is not None and getattr(el, "name", None):
            parts.append(el.name)
            el = el.parent
        return "/".join(reversed(parts))
    except Exception:
        return ""

# ---------------------------
# Prefilter heuristics
# ---------------------------
PREFILTER_PATTERNS = {
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "newFunction": re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
    "innerHTML": re.compile(r"\.innerHTML\b", re.IGNORECASE),
    "documentWrite": re.compile(r"document\.write\s*\(", re.IGNORECASE),
    "cookies": re.compile(r"document\.cookie\b", re.IGNORECASE),
    "locationSearch": re.compile(r"location\.search\b", re.IGNORECASE),
    "xhr": re.compile(r"\bXMLHttpRequest\b|\bfetch\s*\(", re.IGNORECASE),
    "setTimeoutEval": re.compile(r"setTimeout\s*\(\s*['\"]", re.IGNORECASE),
}

def js_prefilter(snippet_text):
    hits = []
    for name, pat in PREFILTER_PATTERNS.items():
        if pat.search(snippet_text):
            hits.append(name)
    return hits

# ---------------------------
# Semgrep run (optional)
# ---------------------------
def run_semgrep_on_local(path=".", config=SEMgrep_CONFIG, output_json="semgrep_results.json"):
    """
    Run semgrep and gather results (requires semgrep installed).
    Returns parsed JSON or None on error.
    """
    try:
        cmd = ["semgrep", "--config", config, "--json", "-o", output_json, path]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(output_json, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Semgrep run failed or not installed: {e}")
        return None

# ---------------------------
# LLM integration (OpenRouter OpenAI-compatible)
# ---------------------------
def chunk_text_by_snippets(snippets, chunk_size=CHUNK_SIZE):
    """
    Pack multiple snippets into chunks not exceeding chunk_size characters.
    Each snippet block is preserved.
    Returns list of chunk strings.
    """
    chunks = []
    cur = ""
    for s in snippets:
        block = "\n---\n" + s["full_block"] + "\n---\n"
        if len(cur) + len(block) > chunk_size and cur:
            chunks.append(cur)
            cur = block
        else:
            cur += block
    if cur:
        chunks.append(cur)
    return chunks

def make_openai_call(payload):
    """
    Use OpenRouter's OpenAI-compatible client for chat completions.
    """
    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "<YOUR_SITE_URL>",  # Optional, replace with your site URL or remove
                "X-Title": "<YOUR_SITE_NAME>",      # Optional, replace with your site name or remove
            },
            model=payload["model"],
            messages=payload["messages"],
            max_tokens=payload.get("max_tokens", 800),
            temperature=payload.get("temperature", 0.0),
        )
        return {
            "choices": [
                {
                    "message": {
                        "content": completion.choices[0].message.content
                    }
                }
            ]
        }
    except Exception as e:
        raise Exception(f"OpenRouter API error: {e}")

def prepare_system_prompt():
    """
    System prompt that enforces JSON-lines output for vulnerabilities only.
    """
    prompt = textwrap.dedent("""
    You are a professional web security auditor.
    You will receive one or more JavaScript snippets in the input.
    Each snippet is delimited by lines with --- and preceded by an identifier line like (id1,JS#1).
    For EACH snippet that is VULNERABLE, output EXACTLY one JSON object (one per line), nothing else.
    Do NOT output any other commentary or text.

    The JSON object schema (string values) must be:
    {
      "id": "(idX,JS#Y)",
      "result": "Vulnerable",
      "type": "<one of: XSS, RCE, SSRF, CSRF, InsecureStorage, InsecureTransport, Other>",
      "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "explain": "Short explanation (max 30 words)",
      "remediation": "Short remediation (max 25 words)"
    }

    If a snippet is NOT vulnerable, produce NO output line for that snippet.
    Be concise, factual, and deterministic. Use severity heuristics conservatively.
    """).strip()
    return prompt

def analyze_with_llm(snippets_to_send, js_unique_fname, model=MODEL, chunk_size=CHUNK_SIZE):
    """
    Send chunks to the LLM and write JSON-lines to an output file.
    snippets_to_send: list of dicts {id, snippet, url, xpath}
    """
    if client is None:
        raise RuntimeError("OpenRouter client is not initialized.")

    # Prepare snippet blocks
    packaged = []
    for s in snippets_to_send:
        # build the full block expected by system prompt
        full_block = f"{s['id']}\n\n{s['snippet']}"
        packaged.append({"id": s["id"], "full_block": full_block, "url": s.get("url"), "xpath": s.get("xpath")})

    chunks = chunk_text_by_snippets(packaged, chunk_size=chunk_size)
    output_jsonl = os.path.join(OUTPUT_DIR, f"chatGPT_{os.path.basename(js_unique_fname)}.jsonl")
    if os.path.exists(output_jsonl):
        os.remove(output_jsonl)

    system_prompt = prepare_system_prompt()
    for idx, chunk in enumerate(chunks, start=1):
        print(f"[LLM] Sending chunk {idx}/{len(chunks)} ({len(chunk)} chars)")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": chunk}
            ],
            "max_tokens": 400,
            "temperature": 0.0
        }
        # retry logic
        for attempt in range(3):
            try:
                resp = make_openai_call(payload)
                content = resp["choices"][0]["message"]["content"].strip()
                # The model should return zero or more JSON objects, one per line.
                # Append raw lines to jsonl file (we'll validate later).
                with open(output_jsonl, "a", encoding="utf-8") as f:
                    # normalize: sometimes model returns trailing newlines
                    for line in content.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        f.write(line + "\n")
                break
            except Exception as e:
                wait = (attempt + 1) * 2
                print(f"[LLM] attempt {attempt+1} failed: {e}. retrying in {wait}s")
                time.sleep(wait)
                continue

    print(f"[LLM] Completed. Output written to {output_jsonl}")
    return output_jsonl

# ---------------------------
# Parsing LLM output and generating final report
# ---------------------------
def parse_llm_jsonlines(jsonl_path):
    vulns = []
    if not os.path.exists(jsonl_path):
        return vulns
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                if obj.get("result") == "Vulnerable":
                    vulns.append(obj)
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed LLM line (first 200 chars): {raw[:200]}")
    return vulns

def produce_final_report(vulns, js_url_fname, js_unique_fname, final_name=None):
    """
    Compose a simple human-readable final report merging LLM findings with URL references and code snippets.
    """
    if final_name is None:
        domain = os.path.basename(js_url_fname).replace("JS_URL_", "").replace(".json", "")
        final_name = os.path.join(OUTPUT_DIR, f"final_{domain}.txt")

    # load url map
    url_map = {}
    if os.path.exists(js_url_fname):
        with open(js_url_fname, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    url_map[j.get("id")] = j.get("url")
                except Exception:
                    pass

    # load snippets from unique file for quick lookup
    snippets_by_id = {}
    if os.path.exists(js_unique_fname):
        content = open(js_unique_fname, "r", encoding="utf-8").read()
        # parse blocks
        blocks = re.split(r'\n---\n', content)
        for b in blocks:
            b = b.strip()
            if not b:
                continue
            # first line should be (id...), then a blank line, then snippet
            m = re.match(r'\((id\d+,JS#\d+)\)\s*\n\n(.*)', b, flags=re.S)
            if m:
                iid = f"({m.group(1)})"
                snippets_by_id[iid] = m.group(2).strip()

    with open(final_name, "w", encoding="utf-8") as f:
        if not vulns:
            # Print green text with emoji in console:
            print("\n" * 2)
            print("\033[1m\033[32m✅ No vulnerabilities found by LLM analysis! Great job! 😄\033[0m")
            print("\n" * 2)
            f.write("No vulnerabilities found by LLM analysis.\n")
            return final_name

        f.write("Potential vulnerabilities discovered:\n\n")
        for v in vulns:
            f.write(f"ID: {v.get('id')}\n")
            f.write(f"Type: {v.get('type')}\n")
            f.write(f"Severity: {v.get('severity')}\n")
            f.write(f"Explanation: {v.get('explain')}\n")
            f.write(f"Remediation: {v.get('remediation')}\n")
            urlref = url_map.get(v.get("id"), "N/A")
            f.write(f"Source URL: {urlref}\n")
            snippet = snippets_by_id.get(v.get("id"), "[Snippet not found]")
            f.write(f"Code Snippet:\n{snippet}\n")
            f.write("=" * 80 + "\n\n")
    print(f"[+] Final report generated: {final_name}")
    return final_name

# ---------------------------
# Main program
# ---------------------------
def main():
    print(r"""
 _    _       _               _____                                      
| |  | |     | |             / ____|                                     
| |  | |_ __ | | ___  _   _ | (___   ___ _ ____   _____ _ __ ___  ___ ___ 
| |  | | '_ \| |/ _ \| | | | \___ \ / _ \ '__\ \ / / _ \ '__/ __|/ _ / __|
| |__| | |_) | | (_) | |_| | ____) |  __/ |   \ V /  __/ |  \__ |  __\__ \
 \____/| .__/|_|\___/ \__, ||_____/ \___|_|    \_/ \___|_|  |___/\___|___/
       | |             __/ |                                               
       |_|            |___/                                               
    """)
    print("Welcome to VulnScan AI powered by OpenRouter!\n")

    # Step 1: Get URL and recursion level
    url = input("Enter the website URL to scan (http(s)://...): ").strip()
    if not url.startswith("http"):
        print("[!] Please enter a valid http or https URL.")
        sys.exit(1)

    recursion = input(f"Recursion Level (Between 1-3 | Default={MAX_RECURSION}): ").strip()
    if recursion.isdigit():
        recursion = int(recursion)
        if recursion < 1 or recursion > 3:
            recursion = MAX_RECURSION
    else:
        recursion = MAX_RECURSION

    print(f"[+] Starting crawl on {url} with recursion level {recursion} ...")

    # Initialize OpenRouter client
    init_openrouter_client()

    # Step 2: Crawl website internal links
    urls = crawl_website_seed(url, max_recursion=recursion)
    print(f"[+] Found {len(urls)} pages to analyze.")

    # Step 3: Extract JS snippets and deduplicate
    domain = domain_from_url(url)
    js_unique_filename = f"JS_Unique_{domain}.txt"
    snippets, js_unique_fname, js_url_fname = extract_js_snippets(urls, js_unique_filename)
    print(f"[+] Extracted {len(snippets)} unique JavaScript snippets.")

    if not snippets:
        print("[!] No JavaScript snippets found to analyze.")
        sys.exit(0)

    # Step 4: Prefilter snippets for suspicious patterns
    suspicious_snippets = []
    for snip in snippets:
        flags = js_prefilter(snip["snippet"])
        if flags:
            suspicious_snippets.append(snip)
    print(f"[+] {len(suspicious_snippets)} snippets flagged as suspicious by prefilter.")

    if not suspicious_snippets:
        print("[*] No suspicious snippets found. Consider lowering prefilter strictness or analyze all snippets.")
        suspicious_snippets = snippets  # fallback to all snippets

    # Step 5: (Optional) Run semgrep if enabled (for local source code)
    if SEMgrep_ENABLED:
        print("[*] Running Semgrep static analysis (if installed and configured)...")
        semgrep_results = run_semgrep_on_local()
        if semgrep_results:
            print(f"[+] Semgrep found {len(semgrep_results.get('results', []))} findings.")
        else:
            print("[!] Semgrep run failed or no results.")

    # Step 6: Send suspicious snippets to LLM via OpenRouter client
    jsonl_path = analyze_with_llm(suspicious_snippets, js_unique_fname)

    # Step 7: Parse LLM output and produce final human-readable report
    vulnerabilities = parse_llm_jsonlines(jsonl_path)
    produce_final_report(vulnerabilities, js_url_fname, js_unique_fname)

    print("[+] Scan complete.")

if __name__ == "__main__":
    main()
