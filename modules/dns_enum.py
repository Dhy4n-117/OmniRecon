import asyncio
import aiohttp
import aiodns
from core.console import Logger
import re
from typing import Set

class DNSEnumerator:
    def __init__(self, target: str, concurrency: int = 100):
        self.target = target
        self.concurrency = concurrency
        self.found_subdomains: Set[str] = set()
        
        # Configure resolver
        loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=loop)
        
        # We need a shared session for HTTP requests
        self.session = None

    async def _query_crt_sh(self):
        """Passively finds subdomains using crt.sh (Certificate Transparency Logs)"""
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # crt.sh returns a list of dictionaries. We want the 'name_value'
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Handle wildcard certs and multiple domains separated by newlines
                        for sub in name_value.split('\\n'):
                            sub = sub.strip().lower()
                            if not sub.startswith('*'): # Ignore wildcards like *.example.com
                                self.found_subdomains.add(sub)
        except Exception as e:
            Logger.warning(f"Failed to query crt.sh: {e}")

    async def _resolve_worker(self, queue: asyncio.Queue, progress, task_id):
        """Worker coroutine to consume words from queue and brute-force via DNS"""
        while True:
            sub = await queue.get()
            
            fqdn = f"{sub}.{self.target}"
            try:
                # Query A record
                result = await self.resolver.query(fqdn, 'A')
                if result:
                    self.found_subdomains.add(fqdn)
            except aiodns.error.DNSError:
                # Domain doesn't exist
                pass
            except Exception as e:
                # Other transient errors
                pass
            finally:
                progress.update(task_id, advance=1)
                queue.task_done()

    async def run_passive(self):
        async with aiohttp.ClientSession() as session:
            self.session = session
            Logger.info(f"Querying crt.sh for {self.target}...")
            await self._query_crt_sh()
            Logger.success(f"Discovered {len(self.found_subdomains)} subdomains via crt.sh")

    async def run_active(self, wordlist_path: str):
        """Reads a wordlist and creates tasks to resolve them."""
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            Logger.error(f"Wordlist not found: {wordlist_path}")
            return
            
        queue = asyncio.Queue()
        for word in words:
            queue.put_nowait(word)
            
        total_words = len(words)
        
        Logger.info(f"Starting active DNS brute-force with {total_words} words (Concurrency: {self.concurrency})")
        
        with Logger.get_progress() as progress:
            task_id = progress.add_task("[cyan]Brute-forcing DNS...", total=total_words)
            
            workers = []
            for _ in range(self.concurrency):
                worker = asyncio.create_task(self._resolve_worker(queue, progress, task_id))
                workers.append(worker)
                
            # Wait for queue to empty
            await queue.join()
            
            # Cancel workers
            for worker in workers:
                worker.cancel()

        Logger.success(f"Active DNS brute-force complete. Total unique subdomains found: {len(self.found_subdomains)}")

async def run_dns_enum(context: dict, run_active: bool = False):
    enumerator = DNSEnumerator(
        target=context["domain"], 
        concurrency=context["concurrency"]
    )
    
    # Always run passive mapping
    await enumerator.run_passive()
    
    # Optionally run active brute-forcing if wordlist provided
    if run_active and context.get("wordlist"):
        await enumerator.run_active(context["wordlist"])
        
    if not context.get("wordlist") and run_active:
        Logger.warning("Active DNS brute-forcing skipped: No wordlist provided (-w)")

    # Ensure the root domain is always included in the target list
    enumerator.found_subdomains.add(context["domain"])

    context["subdomains"] = enumerator.found_subdomains
    Logger.info(f"Final subdomain count for next phases: {len(context['subdomains'])}")
