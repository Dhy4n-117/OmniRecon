import asyncio
from typing import List
from core.console import Logger
import socket

async def scan_port(sem: asyncio.Semaphore, target: str, port: int, timeout: int = 1) -> tuple:
    """Attempts to connect to a specific port asynchronously with a semaphore limit."""
    async with sem:
        try:
            # We connect directly using IPv4
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            
            # Simple banner grab
            banner = ""
            try:
                # Try reading 100 bytes of banner
                banner_data = await asyncio.wait_for(reader.read(100), timeout=0.5)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except:
                pass
                
            writer.close()
            await writer.wait_closed()
            return (target, port, True, banner)
        except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
            return (target, port, False, "")

async def run_port_scan(context: dict, port_spec: str):
    """
    Scans a given string of ports (e.g. '80,443' or 'full') against all subdomains
    discovered in the context.
    """
    # Parse ports
    ports_to_scan = []
    if port_spec.lower() == "full":
        ports_to_scan = list(range(1, 65536))
    else:
        try:
            ports_to_scan = [int(p.strip()) for p in port_spec.split(",")]
        except ValueError:
            Logger.error("Invalid port format. Use comma separated numbers (80,443) or 'full'.")
            return

    subdomains = context.get("subdomains", {context["domain"]})
    
    # Optional logic: If we have no subdomains, at least scan the primary
    if not subdomains:
        subdomains = {context["domain"]}

    total_tasks = len(subdomains) * len(ports_to_scan)
    Logger.info(f"Starting async port scan on {len(subdomains)} hosts across {len(ports_to_scan)} ports (Total checks: {total_tasks})")

    # Limit maximum concurrent outgoing connections
    sem = asyncio.Semaphore(context["concurrency"])
    
    tasks = []
    for sub in subdomains:
        for port in ports_to_scan:
            tasks.append(scan_port(sem, sub, port))

    open_ports_dict = {}

    with Logger.get_progress() as progress:
        task_id = progress.add_task("[cyan]Scanning ports...", total=total_tasks)
        
        # Gather results progressively
        for coro in asyncio.as_completed(tasks):
            target, port, is_open, banner = await coro
            
            if is_open:
                if target not in open_ports_dict:
                    open_ports_dict[target] = []
                
                open_ports_dict[target].append(port)
                
                # Live logging
                banner_str = f" | Banner: {banner[:40]}" if banner else ""
                Logger.success(f"{target}:{port} is OPEN{banner_str}")
            
            progress.update(task_id, advance=1)

    context["open_ports"] = open_ports_dict
    Logger.info(f"Port scan complete. Found open ports on {len(open_ports_dict)} hosts.")
