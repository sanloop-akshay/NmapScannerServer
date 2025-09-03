import socket
import nmap
import threading

nm = nmap.PortScanner()
scan_results = [] 


def resolve_target(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        print(f"Error resolving host '{host}': {e}")
        return host


def host_discovery(target: str):
    print("1. Host Discovery...")
    nm.scan(hosts=target, arguments='-sn')
    print("scanned 1")
    scan_results.append({'host_discovery': nm.all_hosts()})


def comprehensive_scan(target: str):
    print("2. Comprehensive Scan...")
    nm.scan(hosts=target, arguments='-sS -sV -O -p-')
    print("scanned 2")
    scan_results.append({'comprehensive': nm._scan_result.copy()})


def aggressive_scan(target: str):
    print("3. Aggressive Scan...")
    nm.scan(hosts=target, arguments='-A')
    print("scanned 3")
    scan_results.append({'aggressive': nm._scan_result.copy()})


def web_enumeration(target: str):
    print("4. Web Enumeration...")
    nm.scan(
        hosts=target,
        arguments='--script http-enum,http-title,http-headers,http-methods,http-vuln* -p 80,443,8080'
    )
    print("scanned 4")
    scan_results.append({'web': nm._scan_result.copy()})


def ssl_checks(target: str):
    print("5. SSL/TLS Checks...")
    nm.scan(hosts=target, arguments='--script ssl-cert,ssl-enum-ciphers,ssl-heartbleed -p 443')
    print("scanned 5")
    scan_results.append({'ssl': nm._scan_result.copy()})


def smb_checks(target: str):
    print("6. SMB/Windows Checks...")
    nm.scan(hosts=target, arguments='--script smb-os-discovery,smb-vuln* -p 445')
    print("scanned 6")
    scan_results.append({'smb': nm._scan_result.copy()})


def database_checks(target: str):
    print("7. Database Checks...")
    nm.scan(hosts=target, arguments='--script mysql-vuln* -p 3306')
    scan_results.append({'mysql': nm._scan_result.copy()})
    nm.scan(hosts=target, arguments='--script ms-sql-info,ms-sql-empty-password -p 1433')
    print("scanned 7")
    scan_results.append({'mssql': nm._scan_result.copy()})


def general_vuln_scan(target: str):
    print("8. General Vulnerability Scan...")
    nm.scan(hosts=target, arguments='-sV --script vuln')
    print("scanned 8")
    scan_results.append({'vuln': nm._scan_result.copy()})


def run_all_scans(target: str):

    ip = resolve_target(target)
    print(f"Resolved IP: {ip}")

    scan_functions = [
        host_discovery,
        comprehensive_scan,
        aggressive_scan,
        web_enumeration,
        ssl_checks,
        smb_checks,
        database_checks,
        general_vuln_scan
    ]

    threads = []
    for func in scan_functions:
        t = threading.Thread(target=func, args=(ip,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("All scans completed.")
    return scan_results


if __name__ == "__main__":
    target = "icanio.com"
    results = run_all_scans(target)
    print(results)
