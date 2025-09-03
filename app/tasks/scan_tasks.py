from celery import shared_task
import socket
import nmap

scan_results = []

nm = nmap.PortScanner()

def resolve_target(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        print(f"Error resolving host '{host}': {e}")
        return host


def host_discovery(target: str):
    nm.scan(hosts=target, arguments='-sn')
    scan_results.append({'host_discovery': nm.all_hosts()})


def comprehensive_scan(target: str):
    nm.scan(hosts=target, arguments='-sS -sV -O -p-')
    scan_results.append({'comprehensive': nm._scan_result.copy()})


def aggressive_scan(target: str):
    nm.scan(hosts=target, arguments='-A')
    scan_results.append({'aggressive': nm._scan_result.copy()})


def web_enumeration(target: str):
    nm.scan(hosts=target, arguments='--script http-enum,http-title,http-headers,http-methods,http-vuln* -p 80,443,8080')
    scan_results.append({'web': nm._scan_result.copy()})


def ssl_checks(target: str):
    nm.scan(hosts=target, arguments='--script ssl-cert,ssl-enum-ciphers,ssl-heartbleed -p 443')
    scan_results.append({'ssl': nm._scan_result.copy()})


def smb_checks(target: str):
    nm.scan(hosts=target, arguments='--script smb-os-discovery,smb-vuln* -p 445')
    scan_results.append({'smb': nm._scan_result.copy()})


def database_checks(target: str):
    nm.scan(hosts=target, arguments='--script mysql-vuln* -p 3306')
    scan_results.append({'mysql': nm._scan_result.copy()})
    nm.scan(hosts=target, arguments='--script ms-sql-info,ms-sql-empty-password -p 1433')
    scan_results.append({'mssql': nm._scan_result.copy()})


def general_vuln_scan(target: str):
    nm.scan(hosts=target, arguments='-sV --script vuln')
    scan_results.append({'vuln': nm._scan_result.copy()})


@shared_task(name="app.tasks.scan_tasks.run_all_scans")
def run_all_scans(target: str):

    global scan_results
    scan_results = []

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

    for func in scan_functions:
        func(ip)
    return scan_results
