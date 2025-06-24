#!/usr/bin/env python3
"""
SubTitan - Advanced Subdomain Enumeration Tool
Code by Issam Junior
"""

import argparse
import concurrent.futures
import dns.resolver
import json
import re
import requests
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from typing import Set, List, Optional
import warnings
from colorama import Fore , init 
init(autoreset=True)
color_ = Fore
# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class SubTitan:
    def __init__(self, target: str, threads: int = 50, timeout: int = 5):
        self.target = self._normalize_target(target)
        self.threads = threads
        self.timeout = timeout
        self.discovered_subdomains = set()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.timeout = timeout
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Custom embedded wordlist for subdomain brute forcing
        self.wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns5', 'upload', 'client',
            'search', 'dns', 'help', 'live', 'signin', 'tv', 'ssl', 'ts', 'cpanelwebmail',
            'cloud', 'host', 'ftp2', 'staging', 'app', 'radio', 'files', 'connect', 'chat',
            'irc', 'webmin', 'whois', 'remote', 'exchange', 'dns3', 'mx1', 'mx2', 'relay',
            'ww1', 'ww42', 'ns6', 'www3', 'mssql', 'dashboard', 'promo', 'srv', 'server',
            'ns7', 'im', 'cname', 'redirects', 'payment', 'contact', 'dl', 'jabber',
            'hostmaster', 'proxy', 'register', 'about', 'mobile1', 'pda', 'mail1', 'mx3',
            'redirect', 'dns4', 'music', 'www4', 'ping', 'status', 'www5', 'photo',
            'router', 'service', 'www6', 'mx4', 'www7', 'www8', 'mail3', 'www9', 'ns8',
            'backup', 'lab', 'monitoring', 'database', 'int', 'gateway', 'v2', 'ldap',
            'marketing', 'cms', 'stage', 'archive', 'graph', 'analytics', 'metrics',
            'deploy', 'sandbox', 'edge', 'prometheus', 'grafana', 'jenkins', 'git',
            'assets', 'static1', 'static2', 'cdn1', 'cdn2', 'dl1', 'download', 'updates',
            'push', 'notifications', 'streaming', 'live1', 'qa', 'testing', 'preprod',
            'uat', 'production', 'prod', 'www-staging', 'dev1', 'dev2', 'staging2',
            'api1', 'api2', 'rest', 'service1', 'service2', 'backend', 'frontend',
            'app1', 'app2', 'mobile2', 'wap', 'touch', 'responsive', 'lb', 'balancer',
            'cluster', 'node', 'worker', 'master', 'slave', 'primary', 'secondary',
            'cache', 'redis', 'memcache', 'db', 'db1', 'db2', 'database1', 'postgres',
            'mongodb', 'elasticsearch', 'kibana', 'logstash', 'log', 'logs', 'syslog',
            'monitoring1', 'nagios', 'zabbix', 'icinga', 'munin', 'cacti', 'smokeping',
            'ntp', 'time', 'mirror', 'repo', 'repository', 'packages', 'apt', 'yum',
            'registry', 'docker', 'kubernetes', 'k8s', 'rancher', 'consul', 'vault',
            'ci', 'cd', 'build', 'compile', 'artifactory', 'nexus', 'sonar', 'quality'
        ]

    def _normalize_target(self, target: str) -> str:
        """Normalize the target domain by removing protocol and paths"""
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            target = parsed.netloc
        
        # Remove port if present
        target = target.split(':')[0]
        
        # Remove www. prefix if present
        if target.startswith('www.'):
            target = target[4:]
        
        return target.lower()

    def print_banner(self):
        """Print the tool banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███████╗██╗   ██╗██████╗ ████████╗██╗████████╗ █████╗ ███╗   ██╗   ║
║   ██╔════╝██║   ██║██╔══██╗╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║   ║
║   ███████╗██║   ██║██████╔╝   ██║   ██║   ██║   ███████║██╔██╗ ██║   ║
║   ╚════██║██║   ██║██╔══██╗   ██║   ██║   ██║   ██╔══██║██║╚██╗██║   ║
║   ███████║╚██████╔╝██████╔╝   ██║   ██║   ██║   ██║  ██║██║ ╚████║   ║
║   ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ║
║                                                                      ║
║                    Subdomain Intelligence Scanner                    ║
║                         {color_.GREEN}Code by{color_.RED} Issam Junior{color_.RESET}                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def add_subdomain(self, subdomain: str):
        """Thread-safe method to add discovered subdomains"""
        with self.lock:
            if subdomain not in self.discovered_subdomains:
                self.discovered_subdomains.add(subdomain)
                print(f"{color_.CYAN}[+] Found:{color_.WHITE} {subdomain}")

    def dns_brute_force(self):
        """Perform DNS brute force using embedded wordlist"""
        print(f"\n{color_.BLUE}[*] Starting DNS brute force with {len(self.wordlist)} entries...")
        
        def check_subdomain(word):
            subdomain = f"{word}.{self.target}"
            try:
                dns.resolver.resolve(subdomain, 'A')
                self.add_subdomain(subdomain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, self.wordlist)

    def certificate_transparency(self):
        """Search Certificate Transparency logs"""
        print(f"\n{color_.YELLOW}[*] Searching Certificate Transparency logs...")
        
        try:
            # crt.sh API
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = self.session.get(url, verify=False, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        domains = entry['name_value'].split('\n')
                        for domain in domains:
                            domain = domain.strip().lower()
                            if domain.endswith(f'.{self.target}') and domain != self.target:
                                # Remove wildcard prefix if present
                                if domain.startswith('*.'):
                                    domain = domain[2:]
                                self.add_subdomain(domain)
        except Exception as e:
            print(f"{color_.RED}[!] Certificate Transparency search failed: {str(e)}")

        # Try alternative CT sources
        try:
            # Censys API (public endpoint)
            url = f"https://search.censys.io/api/v2/certificates/search"
            params = {"q": f"names: *.{self.target}"}
            response = self.session.get(url, params=params, verify=False, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'result' in data and 'hits' in data['result']:
                    for hit in data['result']['hits']:
                        if 'names' in hit:
                            for name in hit['names']:
                                if name.endswith(f'.{self.target}') and name != self.target:
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    self.add_subdomain(name)
        except Exception:
            pass

    def reverse_dns_lookup(self):
        """Perform reverse DNS lookups on IP ranges"""
        print(f"\n{color_.BLUE}[*] Performing reverse DNS lookups...")
        
        try:
            # Get IP address of main domain
            ip = socket.gethostbyname(self.target)
            ip_parts = ip.split('.')
            base_ip = '.'.join(ip_parts[:3])
            
            def check_reverse_dns(i):
                try:
                    test_ip = f"{base_ip}.{i}"
                    hostname = socket.gethostbyaddr(test_ip)[0]
                    if self.target in hostname and hostname != self.target:
                        self.add_subdomain(hostname)
                except (socket.herror, socket.gaierror):
                    pass
                except Exception:
                    pass

            # Check a range of IPs around the target
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                executor.map(check_reverse_dns, range(1, 255))
                
        except Exception as e:
            print(f"{color_.RED}[!] Reverse DNS lookup failed: {str(e)}")

    def web_scraping(self):
        """Scrape web sources for subdomain mentions"""
        print(f"\n{color_.YELLOW}[*] Web scraping for subdomain references...")
        
        sources = [
            f"https://www.google.com/search?q=site:{self.target}",
            f"https://dnsdumpster.com/",
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=text&fl=original&collapse=urlkey"
        ]
        
        for source in sources:
            try:
                if "archive.org" in source:
                    response = self.session.get(source, verify=False, timeout=self.timeout * 2)
                    if response.status_code == 200:
                        # Parse Wayback Machine results
                        for line in response.text.split('\n'):
                            if line and 'http' in line:
                                try:
                                    url = line.strip()
                                    parsed = urllib.parse.urlparse(url)
                                    hostname = parsed.netloc.lower()
                                    if hostname.endswith(f'.{self.target}') and hostname != self.target:
                                        self.add_subdomain(hostname)
                                except Exception:
                                    continue
                
                else:
                    response = self.session.get(source, verify=False, timeout=self.timeout)
                    if response.status_code == 200:
                        # Extract subdomains using regex
                        pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.target)
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        for match in matches:
                            subdomain = match[0] + self.target if isinstance(match, tuple) else match
                            if subdomain != self.target:
                                self.add_subdomain(subdomain)
                                
            except Exception as e:
                continue

    def passive_dns_lookup(self):
        """Perform passive DNS lookups using public APIs"""
        print(f"\n{color_.YELLOW}[*] Performing passive DNS lookups...")
        
        # Try VirusTotal API (public/free tier)
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': 'public',  # Using public endpoint
                'domain': self.target
            }
            response = self.session.get(url, params=params, verify=False, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        if subdomain != self.target:
                            self.add_subdomain(subdomain)
        except Exception:
            pass

        # Try SecurityTrails (public endpoint)
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains"
            response = self.session.get(url, verify=False, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        full_subdomain = f"{subdomain}.{self.target}"
                        self.add_subdomain(full_subdomain)
        except Exception:
            pass

    def dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        print(f"\n{color_.MAGENTA}[*] Attempting DNS zone transfers...")
        
        try:
            # Get name servers for the domain
            ns_records = dns.resolver.resolve(self.target, 'NS')
            
            for ns in ns_records:
                try:
                    ns_ip = str(ns).rstrip('.')
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.target))
                    
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.target}" if name != '@' else self.target
                        if subdomain != self.target:
                            self.add_subdomain(subdomain)
                            
                except Exception:
                    continue
                    
        except Exception:
            pass

    def check_common_ports(self):
        """Check for services on common ports that might reveal subdomains"""
        print(f"\n{color_.YELLOW}[*] Checking common service ports...")
        
        try:
            target_ip = socket.gethostbyname(self.target)
            common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995]
            
            def check_port_banner(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        if port == 443:  # HTTPS - check SSL certificate
                            try:
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                
                                with socket.create_connection((target_ip, port), timeout=2) as sock:
                                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                                        cert = ssock.getpeercert()
                                        if cert and 'subjectAltName' in cert:
                                            for type_, name in cert['subjectAltName']:
                                                if type_ == 'DNS' and name.endswith(f'.{self.target}'):
                                                    if name.startswith('*.'):
                                                        name = name[2:]
                                                    self.add_subdomain(name)
                            except Exception:
                                pass
                    
                    sock.close()
                except Exception:
                    pass

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(check_port_banner, common_ports)
                
        except Exception:
            pass

    def run_scan(self):
        """Run the complete subdomain enumeration"""
        start_time = time.time()
        
        print(f"\n{color_.RED}[*] Target:{color_.WHITE} {self.target}")
        print(f"{color_.RED}[*] Threads:{color_.WHITE} {self.threads}")
        print(f"{color_.RED}[*] Timeout:{color_.WHITE} {self.timeout}s")
        print(f"{color_.RED}[*] Started at:{color_.WHITE} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        # Add the main domain
        self.add_subdomain(self.target)

        # Run all enumeration techniques
        techniques = [
            self.dns_brute_force,
            self.certificate_transparency,
            self.reverse_dns_lookup,
            self.web_scraping,
            self.passive_dns_lookup,
            self.dns_zone_transfer,
            self.check_common_ports
        ]

        for technique in techniques:
            try:
                technique()
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error in {technique.__name__}: {str(e)}")
                continue

        # Final results
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 70)
        print(f"{color_.GREEN}[*] Scan completed in {duration:.2f} seconds")
        print(f"{color_.YELLOW}[*] Total subdomains found: {len(self.discovered_subdomains)}")
        print(f"\n{color_.YELLOW}[*] Results:")
        print(color_.WHITE+"-" * 40)
        
        sorted_subdomains = sorted(list(self.discovered_subdomains))
        for subdomain in sorted_subdomains:
            print(f"  {color_.BLUE}•{color_.WHITE} {subdomain}")
        
        return sorted_subdomains


def main():
    parser = argparse.ArgumentParser(
        description="SubTitan - Advanced Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subtitan.py -d example.com
  python subtitan.py -d https://www.example.com -t 100 --timeout 3
  python subtitan.py -d example.com -o results.txt
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, 
                       help='Target domain or URL to enumerate subdomains for')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads for concurrent scanning (default: 50)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Timeout for network requests in seconds (default: 5)')
    parser.add_argument('-o', '--output', 
                       help='Output file to save results')
    parser.add_argument('--silent', action='store_true',
                       help='Silent mode - only show results')
    
    args = parser.parse_args()
    
    try:
        subtitan = SubTitan(args.domain, args.threads, args.timeout)
        
        if not args.silent:
            subtitan.print_banner()
        
        # Run the scan
        results = subtitan.run_scan()
        
        # Save results to file if specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    for subdomain in results:
                        f.write(f"{subdomain}\n")
                print(f"\n{color_.GREEN}[*] Results saved to: {args.output}")
            except Exception as e:
                print(f"{color_.RED}[!] Failed to save results: {str(e)}")
        
    except KeyboardInterrupt:
        print("\n{color_.RED}[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{color_.RED}[!] Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
