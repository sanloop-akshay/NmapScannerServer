# app/tasks/scan_tasks.py
from celery import shared_task
import socket
import nmap
import threading
import json
from xhtml2pdf import pisa
import os

nm = nmap.PortScanner()
scan_results = []



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
    nm.scan(
        hosts=target,
        arguments='--script http-enum,http-title,http-headers,http-methods,http-vuln* -p 80,443,8080'
    )
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



def generate_html_report(host, ip, results):
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; font-size: 12px; }}
            h1 {{ color: #2E86C1; text-align: center; }}
            h2 {{ background: #117A65; color: white; padding: 6px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
            th {{ background: #f2f2f2; }}
            .critical {{ color: red; font-weight: bold; }}
            .ok {{ color: green; font-weight: bold; }}
            pre {{ background: #f9f9f9; padding: 8px; border: 1px solid #ccc; }}
        </style>
    </head>
    <body>
        <h1>🔍 Nmap Security Scan Report</h1>
        <p><b>Target:</b> {host} ({ip})</p>
        <hr>
    """

    for section_data in results:
        for section, data in section_data.items():
            html += f"<h2>{section.replace('_', ' ').title()}</h2>"
            if isinstance(data, dict) and "scan" in data:
                for target_ip, target_data in data["scan"].items():
                    if "tcp" in target_data:
                        html += "<table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>State</th></tr>"
                        for port, portdata in target_data["tcp"].items():
                            state = portdata.get("state", "unknown")
                            css_class = "critical" if state == "open" else "ok"
                            html += f"<tr><td>{port}</td><td>{portdata.get('name','')}</td><td>{portdata.get('product','')}</td><td>{portdata.get('version','')}</td><td class='{css_class}'>{state}</td></tr>"
                        html += "</table>"

                        for port, portdata in target_data["tcp"].items():
                            if "script" in portdata:
                                html += f"<h3>Port {port} Scripts & Findings</h3><ul>"
                                for script_name, script_output in portdata["script"].items():
                                    html += f"<li><b>{script_name}</b><br><pre>{script_output}</pre></li>"
                                html += "</ul>"
            else:
                html += f"<pre>{json.dumps(data, indent=2)}</pre>"

    html += "</body></html>"
    return html


def save_pdf(html_content, filename="scan_report.pdf"):
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, filename)

    with open(filepath, "w+b") as f:
        pisa.CreatePDF(html_content, dest=f)

    return filepath



@shared_task(name="app.tasks.scan_tasks.run_all_scans")
def run_all_scans(target: str):
    print(f"Starting scans for target: {target}")
    global scan_results
    scan_results = []

    ip = resolve_target(target)

    scan_functions = [
        host_discovery,
        # comprehensive_scan,
        # aggressive_scan,
        # web_enumeration,
        ssl_checks,
        smb_checks,
        database_checks,
        # general_vuln_scan
    ]

    threads = []
    for func in scan_functions:
        t = threading.Thread(target=func, args=(ip,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    html_report = generate_html_report(target, ip, scan_results)
    pdf_path = save_pdf(html_report, f"{target}_scan_report.pdf")

    
