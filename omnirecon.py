#!/usr/bin/env python3
import argparse
import asyncio
import sys
from core.console import Logger
from core.reporter import generate_json_report
from modules.dns_enum import run_dns_enum
from modules.port_scan import run_port_scan
from modules.web_enum import run_web_enum

def parse_args():
    example_usage = """
Examples:
  Basic run (DNS + Ports + Web):
    %(prog)s -d example.com --dns --ports 80,443 --web -o scan_results.json
    
  Full Port Scan (1-65535):
    %(prog)s -d target.com --ports full -o scan.json

  With Subdirectory Fuzzing (requires wordlist):
    %(prog)s -d target.com --ports 80,443 --web -w subdomains.txt -o out.json
"""
    parser = argparse.ArgumentParser(
        description="OmniRecon\nAdvanced Asynchronous Reconnaissance Framework\n\nA cross-platform, highly concurrent recon framework designed for bug bounties.",
        epilog=example_usage,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Target Specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")

    # Scanning Modules
    scan_group = parser.add_argument_group("Scan Modules")
    scan_group.add_argument("--dns", action="store_true", help="Run DNS and Subdomain enumeration (passive + active)")
    scan_group.add_argument("--ports", type=str, default="80,443,8080,8443", help="Comma-separated list of ports to scan (e.g., 22,80,443) or 'full' for 1-65535")
    scan_group.add_argument("--web", action="store_true", help="Run Web Fuzzing and HTTP header inspection on open ports")

    # Options
    opt_group = parser.add_argument_group("Options")
    opt_group.add_argument("-w", "--wordlist", help="Path to dictionary file for DNS/Web fuzzing")
    opt_group.add_argument("-t", "--concurrency", type=int, default=100, help="Max number of concurrent coroutines (default: 100)")
    opt_group.add_argument("-o", "--output", help="Path to save the JSON report (e.g., reports/scan.json)")
    
    return parser.parse_args()

async def main():
    args = parse_args()

    Logger.banner("OmniRecon v1.0", f"Target: {args.domain} | Concurrency: {args.concurrency}")

    # Shared State context
    # This dictionary will hold all findings and be passed to modules
    context = {
        "domain": args.domain,
        "concurrency": args.concurrency,
        "wordlist": args.wordlist,
        "subdomains": set(), 
        "open_ports": {}, # Format: {'subdomain.com': [80, 443]}
        "web_findings": {} 
    }

    if args.dns:
        Logger.info("Starting DNS Enumeration module...")
        await run_dns_enum(context, run_active=(args.wordlist is not None))

    if args.ports:
        Logger.info(f"Starting Asynchronous Port Scanning ({args.ports})...")
        await run_port_scan(context, args.ports)

    if args.web:
        Logger.info("Starting Web Enumeration module...")
        await run_web_enum(context)

    # Reporting Stage
    Logger.info("Scan Complete. Generating report...")
    if args.output:
        await generate_json_report(context, args.output)
        Logger.success(f"Report saved to {args.output}")
    else:
        Logger.info("Skipped report generation (no --output specified)")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n")
        Logger.error("Scan interrupted by user (Ctrl+C). Exiting.")
        sys.exit(1)
