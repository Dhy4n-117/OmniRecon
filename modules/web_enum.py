import asyncio
import aiohttp
from typing import List, Dict
from core.console import Logger
import ssl
import random
from bs4 import BeautifulSoup
import re

# List of common User-Agents to rotate through
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
]

# Basic regex for finding interesting secrets in HTML/JS
SECRET_REGEXES = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic Bearer Token": r"Bearer\s[a-zA-Z0-9\-\._~+\/]+="
}

async def check_url(session: aiohttp.ClientSession, url: str) -> dict:
    """Checks a single URL for its status code, headers, and deep content."""
    
    # 1. Rate Limiting / Jitter
    # Add a random delay between 0.05s and 0.2s before each request to avoid tripping WAFs immediately
    await asyncio.sleep(random.uniform(0.05, 0.2))
    
    # 2. User-Agent Rotation
    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    try:
        async with session.get(url, allow_redirects=False, ssl=False, headers=headers) as response:
            status = response.status
            
            # Extract interesting headers
            interesting_headers = {}
            for header in ['Server', 'X-Powered-By', 'Via', 'X-AspNet-Version']:
                if header in response.headers:
                    interesting_headers[header] = response.headers[header]
            
            result = {
                "url": url,
                "status": status,
                "headers": interesting_headers,
                "content_len": response.content_length or 0,
                "title": None,
                "js_files": [],
                "secrets": []
            }
            
            # 3. Deep Content Parsing (Only parse if it's a successful response and looks like HTML)
            if status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                try:
                    html_content = await response.text()
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    # Extract Title
                    if soup.title and soup.title.string:
                        result["title"] = soup.title.string.strip()
                        
                    # Extract linked JS files
                    for script in soup.find_all('script', src=True):
                        result["js_files"].append(script['src'])
                        
                    # Search for Secrets
                    for name, regex in SECRET_REGEXES.items():
                        matches = re.finditer(regex, html_content)
                        for match in matches:
                            result["secrets"].append(f"{name} found: {match.group(0)[:10]}...") # truncate for display

                except Exception as e:
                    # Ignore parsing errors for individual pages
                    pass
                    
            return result
            
    except Exception:
        return None

async def fuzzer_worker(queue: asyncio.Queue, session: aiohttp.ClientSession, base_url: str, progress, task_id, results: List[dict]):
    """Worker coroutine to pick words from queue and test the URL."""
    while True:
        word = await queue.get()
        # Clean paths
        word = word.strip('/')
        url = f"{base_url}/{word}"
        
        result = await check_url(session, url)
        
        if result and result["status"] not in [404, 400]:
            # Found something interesting
            title_str = f" | Title: {result['title'][:30]}" if result.get('title') else ""
            secrets_str = f" | [red]SECRETS![/red]" if result.get('secrets') else ""
            
            Logger.success(f"[Web] {url} (Status: {result['status']}){title_str}{secrets_str}")
            results.append(result)
            
            # 4. Recursive Fuzzing Logic
            # If we found a directory (often denoted by a redirect or specific structure), we COULD auto-queue here.
            # To prevent infinite loops in this version, we will only queue if the status is exactly a redirect (301)
            # indicating a valid trailing slash directory, and we'll append standard sub-words.
            if result["status"] in [301, 302] and word != "":
                # Simplified recursion: add common inner files to the queue for this specific path
                recursive_words = ['admin', 'login', 'config', 'index.html', '.git/config']
                for rw in recursive_words:
                    queue.put_nowait(f"{word}/{rw}")
                    progress.update(task_id, total=progress.tasks[task_id].total + 1)
            
        progress.update(task_id, advance=1)
        queue.task_done()


async def run_web_enum(context: dict):
    """
    Takes the open ports from the context, determines if they are HTTP/HTTPS,
    and runs a directory fuzzer against them.
    """
    open_hosts = context.get("open_ports", {})
    if not open_hosts:
        Logger.warning("No open ports found to run Web Enumeration against.")
        return

    wordlist_path = context.get("wordlist")
    if not wordlist_path:
        Logger.warning("Web fuzzing skipped: No wordlist provided (-w). Only basic Header checks will run.")
        words = [""] # Just check the root path for headers
    else:
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            Logger.error(f"Wordlist not found: {wordlist_path}")
            return

    # Create base URLs to test (http://ip:port and https://ip:port)
    base_urls = []
    for host, ports in open_hosts.items():
        for port in set(ports): # Unique ports
            if port in [80, 8080]:
                base_urls.append(f"http://{host}:{port}")
            elif port in [443, 8443]:
                base_urls.append(f"https://{host}:{port}")
            else:
                # For unknown ports, we try both just in case
                base_urls.append(f"http://{host}:{port}")
                base_urls.append(f"https://{host}:{port}")

    Logger.info(f"Starting web enumeration on {len(base_urls)} endpoints with {len(words)} word payload...")

    total_requests = len(base_urls) * len(words)
    concurrency = context.get("concurrency", 100)
    
    web_findings = {}

    # Custom connector to ignore SSL errors and limit connections
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    timeout = aiohttp.ClientTimeout(total=10) # 10 sec total max

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        
        with Logger.get_progress() as progress:
            task_id = progress.add_task("[magenta]Fuzzing directories...", total=total_requests)
            
            for base_url in base_urls:
                web_findings[base_url] = []
                
                # We create a new queue for each base URL to isolate the workers gently
                queue = asyncio.Queue()
                for word in words:
                    queue.put_nowait(word)
                    
                workers = []
                # Spin up workers
                for _ in range(min(concurrency, queue.qsize())):
                    worker = asyncio.create_task(
                        fuzzer_worker(queue, session, base_url, progress, task_id, web_findings[base_url])
                    )
                    workers.append(worker)
                    
                # Wait for queue to finish for this URL
                await queue.join()
                
                # Cancel workers
                for worker in workers:
                    worker.cancel()

    # Clean up empty findings
    context["web_findings"] = {url: findings for url, findings in web_findings.items() if findings}
    
    # Print a summary of interesting technologies
    techs = set()
    for url, findings in context["web_findings"].items():
        for find in findings:
            for header, value in find.get('headers', {}).items():
                techs.add(f"{header}: {value}")
                
    if techs:
        Logger.info("Interesting Technologies Detected:")
        for t in techs:
            Logger.info(f" - {t}")
