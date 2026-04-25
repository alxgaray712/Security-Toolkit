#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║   Web Security Scanner v1.0              ║
║   Author: Tu Nombre                      ║
║   GitHub: github.com/tu_usuario          ║
║   Use only on authorized targets         ║
╚══════════════════════════════════════════╝
"""

import requests
import json
import ssl
import socket
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse

# ─── Colores para terminal ───────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def banner():
    print(f"""
{BLUE}{BOLD}
╔═══════════════════════════════════════════╗
║     🔐 Web Security Scanner v1.0          ║
║     github.com/tu_usuario                 ║
╚═══════════════════════════════════════════╝
{RESET}""")

# ─── Análisis de Headers HTTP ────────────────────────
def check_security_headers(url):
    results = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers  = response.headers

        security_headers = {
            "Strict-Transport-Security": {
                "severity": "HIGH",
                "description": "Falta HSTS — El sitio no fuerza HTTPS",
                "fix": "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "Vulnerable a Clickjacking",
                "fix": "Agregar: X-Frame-Options: DENY"
            },
            "X-Content-Type-Options": {
                "severity": "MEDIUM",
                "description": "Vulnerable a MIME-type sniffing",
                "fix": "Agregar: X-Content-Type-Options: nosniff"
            },
            "Content-Security-Policy": {
                "severity": "HIGH",
                "description": "Sin política CSP — riesgo de XSS",
                "fix": "Agregar: Content-Security-Policy: default-src 'self'"
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "Sin política de Referrer",
                "fix": "Agregar: Referrer-Policy: strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "severity": "LOW",
                "description": "Sin política de permisos",
                "fix": "Agregar: Permissions-Policy: geolocation=(), microphone=()"
            },
        }

        print(f"\n{BOLD}[+] Analizando headers de seguridad...{RESET}\n")

        for header, info in security_headers.items():
            if header not in headers:
                severity_color = RED if info["severity"] == "HIGH" else YELLOW if info["severity"] == "MEDIUM" else BLUE
                print(f"  {severity_color}[{info['severity']}]{RESET} ✗ {header}")
                print(f"         → {info['description']}")
                print(f"         💡 Fix: {info['fix']}\n")
                results.append({
                    "header": header,
                    "status": "MISSING",
                    "severity": info["severity"],
                    "description": info["description"],
                    "remediation": info["fix"]
                })
            else:
                print(f"  {GREEN}[OK]{RESET}  ✓ {header}: {headers[header][:60]}")
                results.append({
                    "header": header,
                    "status": "PRESENT",
                    "severity": "NONE",
                    "value": headers[header]
                })

        # Detectar tecnologías expuestas
        exposed = {}
        if "Server" in headers:
            exposed["Server"] = headers["Server"]
            print(f"\n  {YELLOW}[WARN]{RESET} Server expuesto: {headers['Server']}")
        if "X-Powered-By" in headers:
            exposed["X-Powered-By"] = headers["X-Powered-By"]
            print(f"  {YELLOW}[WARN]{RESET} X-Powered-By expuesto: {headers['X-Powered-By']}")

        return results, exposed, response.status_code

    except Exception as e:
        print(f"{RED}[ERROR] No se pudo conectar: {e}{RESET}")
        return [], {}, 0

# ─── Verificación SSL ─────────────────────────────────
def check_ssl(hostname):
    print(f"\n{BOLD}[+] Verificando SSL/TLS...{RESET}\n")
    ssl_info = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
            ssl_info["valid"]   = True
            ssl_info["version"] = s.version()
            ssl_info["expires"] = cert['notAfter']
            ssl_info["issuer"]  = dict(x[0] for x in cert['issuer'])

            print(f"  {GREEN}[OK]{RESET}  ✓ SSL Válido")
            print(f"  {GREEN}[OK]{RESET}  ✓ Versión: {s.version()}")
            print(f"  {GREEN}[OK]{RESET}  ✓ Expira: {cert['notAfter']}")
            print(f"  {GREEN}[OK]{RESET}  ✓ Emisor: {ssl_info['issuer'].get('organizationName', 'N/A')}")

    except ssl.SSLCertVerificationError:
        print(f"  {RED}[CRITICAL]{RESET} ✗ Certificado SSL inválido o autofirmado")
        ssl_info["valid"] = False
        ssl_info["error"] = "Certificado inválido"
    except Exception as e:
        print(f"  {YELLOW}[WARN]{RESET} No se pudo verificar SSL: {e}")
        ssl_info["valid"] = False
        ssl_info["error"] = str(e)

    return ssl_info

# ─── Calcular Score ───────────────────────────────────
def calculate_score(headers_result, ssl_info):
    score = 100
    critical = medium = low = 0

    for item in headers_result:
        if item["status"] == "MISSING":
            if item["severity"] == "HIGH":
                score -= 20
                critical += 1
            elif item["severity"] == "MEDIUM":
                score -= 10
                medium += 1
            elif item["severity"] == "LOW":
                score -= 5
                low += 1

    if not ssl_info.get("valid", True):
        score -= 30
        critical += 1

    score = max(0, score)

    if score >= 80:
        level = f"{GREEN}BAJO{RESET}"
    elif score >= 50:
        level = f"{YELLOW}MEDIO{RESET}"
    else:
        level = f"{RED}ALTO{RESET}"

    return score, level, critical, medium, low

# ─── Generar Reporte JSON ─────────────────────────────
def generate_report(url, headers_result, ssl_info, exposed, score, level, critical, medium, low):
    report = {
        "meta": {
            "tool": "Web Security Scanner v1.0",
            "github": "github.com/tu_usuario/security-toolkit",
            "target": url,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "summary": {
            "score": score,
            "risk_level": level.replace("\033[92m","").replace("\033[93m","").replace("\033[91m","").replace("\033[0m",""),
            "critical_issues": critical,
            "medium_issues": medium,
            "low_issues": low,
        },
        "ssl": ssl_info,
        "exposed_technologies": exposed,
        "headers": headers_result,
    }
    return report

# ─── Main ─────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="Web Security Scanner")
    parser.add_argument("url",    help="URL objetivo (ej: https://ejemplo.com)")
    parser.add_argument("--output", choices=["json", "terminal"], default="terminal")
    args = parser.parse_args()

    url      = args.url
    parsed   = urlparse(url)
    hostname = parsed.hostname

    print(f"{BOLD}[*] Objetivo:{RESET} {url}")
    print(f"{BOLD}[*] Inicio: {RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 55)

    headers_result, exposed, status = check_security_headers(url)
    ssl_info = check_ssl(hostname)
    score, level, critical, medium, low = calculate_score(headers_result, ssl_info)

    print(f"\n{'─'*55}")
    print(f"{BOLD}[📊] RESUMEN FINAL{RESET}")
    print(f"{'─'*55}")
    print(f"  Puntuación de Seguridad : {BOLD}{score}/100{RESET}")
    print(f"  Nivel de Riesgo         : {level}")
    print(f"  Problemas Críticos      : {RED}{critical}{RESET}")
    print(f"  Problemas Medios        : {YELLOW}{medium}{RESET}")
    print(f"  Problemas Bajos         : {BLUE}{low}{RESET}")
    print(f"{'─'*55}")

    if args.output == "json":
        report = generate_report(url, headers_result, ssl_info, exposed, score, level, critical, medium, low)
        filename = f"reporte_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n{GREEN}[✓] Reporte guardado: {filename}{RESET}")

    print(f"\n  📋 Generado por: github.com/tu_usuario/security-toolkit\n")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
