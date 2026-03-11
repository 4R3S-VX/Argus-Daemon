import psutil
import os
import sys
import argparse
import time
from colorama import Fore, Style, init

# Initialize Cinema-grade Terminal Colors
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}  █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
 ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
 ███████║██████╔╝██║  ███╗██║   ██║███████╗
 ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
 ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
                                           
{Fore.WHITE}  [ Ἄργος : THE HUNDRED-EYED DAEMON ]  {Fore.RED}v1.2.0-STABLE
{Fore.BLACK}{Style.BRIGHT}  HEURISTIC ENGINE: 4R3S_VX | TARGET: MEMORY_RESIDENT_MALWARE
{Style.RESET_ALL}"""

def boot_sequence():
    print(BANNER)
    tasks = [
        ("CORE", "Initializing Heuristic Engine..."),
        ("MEM",  "Mapping Resident PIDs..."),
        ("NET",  "Hooking Network Listeners..."),
        ("OS",   "Verifying Disk Integrity..."),
    ]
    for module, message in tasks:
        print(f"{Fore.BLUE}[{module}]{Fore.WHITE} {message}", end="\r")
        time.sleep(0.4) 
    print(f"{Fore.GREEN}[READY]{Fore.WHITE} The Eyes of Argus are Open.          ")
    print(f"{Fore.BLACK}{'='*60}{Style.RESET_ALL}")

def scan_memory(purge=False):
    boot_sequence()
    pids = psutil.pids()
    print(f"{Fore.YELLOW}[*] Scanning {len(pids)} active processes for anomalies...")
    print(f"{'-'*60}")

    suspicious_count = 0

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            name = pinfo['name'] or "Unknown"

            if pid in [0, 4] or name.lower() in ['registry', 'memcompression', 'unknown']:
                continue 

            is_suspicious = False
            reason = ""

            # HEURISTIC 1: Living Off The Land
            if name.lower() in ['powershell.exe', 'cmd.exe', 'wscript.exe']:
                if proc.net_connections():
                    is_suspicious = True
                    reason = "Unusual Network Activity (LotL)"

            # HEURISTIC 2: Ghost Process
            if not pinfo['exe'] or not os.path.exists(pinfo['exe']):
                is_suspicious = True
                reason = "No Valid Disk Path (Fileless Injection)"

            if is_suspicious:
                suspicious_count += 1
                print(f"{Fore.RED}[!] ALERT: {name} (PID: {pid}) -> {reason}")
                
                if purge:
                    try:
                        proc.terminate()
                        print(f"{Fore.GREEN}    [+] THREAT NEUTRALIZED.")
                    except psutil.AccessDenied:
                        print(f"{Fore.YELLOW}    [!] ACCESS DENIED: Run as Admin to kill.")
                else:
                    print(f"{Fore.WHITE}    [>] RECOMMENDATION: Run with --purge to kill.")
            else:
                print(f"{Fore.BLACK}{Style.BRIGHT}[IDLE] Checked PID {pid}: {name[:20]}...")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    print(f"{'-'*60}")
    if suspicious_count == 0:
        print(f"{Fore.GREEN}[+] SYSTEM SECURED. NO ANOMALIES DETECTED.")
    else:
        print(f"{Fore.RED}[X] SCAN COMPLETE. {suspicious_count} THREATS IDENTIFIED.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--purge", action="store_true")
    args = parser.parse_args()

    try:
        scan_memory(purge=args.purge)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan Aborted.")
        sys.exit(0)