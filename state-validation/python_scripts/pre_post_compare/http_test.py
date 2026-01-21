#!/usr/bin/env python3

import socket
import ssl
import requests
import time
from datetime import datetime
import signal
import sys
import re
import argparse
from rich.console import Console
console = Console()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='HTTPS Ping Monitor')
    parser.add_argument('--ignore-cert', 
                       action='store_true',
                       help='Ignore SSL certificate verification')
    return parser.parse_args()

def validate_domain(domain):
    """Validate domain name format"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def get_valid_domain():
    """Prompt user for domain name with validation"""
    while True:
        domain = input("\nEnter the domain to monitor (e.g., example.com): ").strip().lower()
        
        if not domain:
            console.print("[red]Error: Domain cannot be empty. Please try again.")
            continue
            
        if validate_domain(domain):
            return domain
        else:
            console.print("[red]Error: Invalid domain format. Please enter a valid domain (e.g., example.com)")

class HTTPSPingMonitor:
    def __init__(self, domain, port=443, interval=5, verify_ssl=True):
        self.domain = domain
        self.port = port
        self.interval = interval
        self.verify_ssl = verify_ssl
        self.running = False
        self.success_count = 0
        self.fail_count = 0
        self.start_time = None
        
        # Setup signal handler for clean exit
        signal.signal(signal.SIGINT, self.handle_exit)
        
    def handle_exit(self, signum, frame):
        """Handle clean exit when Ctrl+C is pressed"""
        print("\n\nStopping HTTPS ping monitor...")
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"\nMonitoring Statistics for {self.domain}:")
            print(f"Duration: {int(duration)} seconds")
            print(f"Successful pings: {self.success_count}")
            print(f"Failed pings: {self.fail_count}")
            if self.success_count + self.fail_count > 0:
                success_rate = (self.success_count / (self.success_count + self.fail_count)) * 100
                print(f"Success rate: {success_rate:.1f}%")
        sys.exit(0)

    def check_single_ping(self):
        """Perform a single HTTPS ping check"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            # Start timing
            start_time = time.time()
            
            # Create socket and attempt connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.interval - 1)  # Timeout just before next interval
            result = sock.connect_ex((self.domain, self.port))
            
            if result == 0:
                # Attempt HTTPS request
                response = requests.head(
                    f"https://{self.domain}",
                    timeout=self.interval - 1,
                    verify=self.verify_ssl  # Use the verify_ssl parameter
                )
                response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                
                console.print(f"[green][{timestamp}] ✓ HTTPS Response: {response.status_code} - Time: {response_time:.1f}ms")
                self.success_count += 1
            else:
                console.print(f"[red][{timestamp}] ✗ Connection Failed - Port {self.port} closed")
                self.fail_count += 1
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red][{timestamp}] ✗ HTTPS Request Failed: {str(e)}")
            self.fail_count += 1
        except socket.gaierror:
            console.print(f"[red][{timestamp}] ✗ DNS Resolution Failed")
            self.fail_count += 1
        except socket.timeout:
            console.print(f"[red][{timestamp}] ✗ Connection Timed Out")
            self.fail_count += 1
        except Exception as e:
            console.print(f"[red][{timestamp}] ✗ Error: {str(e)}")
            self.fail_count += 1
        finally:
            try:
                sock.close()
            except:
                pass

    def start_monitoring(self):
        """Start continuous monitoring"""
        print(f"\nStarting HTTPS ping monitor for {self.domain}:{self.port}")
        print(f"Interval: {self.interval} seconds")
        if not self.verify_ssl:
            print("SSL Certificate verification is disabled")
        print("Press Ctrl+C to stop monitoring\n")
        print("-" * 60)
        
        self.running = True
        self.start_time = time.time()
        
        # Disable SSL verification warnings if verify_ssl is False
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        while self.running:
            self.check_single_ping()
            time.sleep(self.interval)

def main():
    """Main function to run the monitor"""
    print("=== HTTPS Ping Monitor ===")
    
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Get domain from user with validation
        domain = get_valid_domain()
        
        # Create and start monitor with SSL verification setting
        monitor = HTTPSPingMonitor(domain, interval=5, verify_ssl=not args.ignore_cert)
        monitor.start_monitoring()
        
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

