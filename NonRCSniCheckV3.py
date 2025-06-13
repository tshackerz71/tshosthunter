import subprocess
import socket
import ssl
import requests
import time
import sys

def main_menu():
    while True:
        print("\n==============================")
        print("  TSHACKER - REAL BUG HOST SCANNER")
        print("==============================")
        print("[1] Single Domain Test")
        print("[2] Bulk Domain Test (comma-separated)")
        print("[0] Exit")
        choice = input("Select option: ")

        if choice == '1':
            domain_input(single=True)
        elif choice == '2':
            domain_input(single=False)
        elif choice == '0':
            sys.exit("Exiting TSHACKER. Bye!")
        else:
            print("Invalid choice. Try again.")

def domain_input(single):
    if single:
        domain = input("Enter domain: ").strip()
        domains = [domain]
    else:
        domain_line = input("Enter domains (comma-separated): ")
        domains = [d.strip() for d in domain_line.split(",") if d.strip()]

    for d in domains:
        run_full_scan(d)

def run_full_scan(domain):
    print(f"\n🚀 Starting full scan for: {domain}")
    traceroute_ok = tls_ok = ssl_ok = payload_ok = redirect_ok = tunnel_ok = False

    # Traceroute
    print(f"\n🚀 Traceroute to {domain}... please wait...")
    try:
        result = subprocess.run(['traceroute', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
        if any(x in result.stdout for x in [' 1 ', ' 2 ', ' 3 ', domain]):
            traceroute_ok = True
            print("✅ Traceroute PASS")
        else:
            print("❌ Traceroute FAIL (No valid hops)")
    except Exception as e:
        print(f"❌ Traceroute FAIL (Error: {e})")

    # TLS Connect
    print(f"\n🚀 TLS handshake on {domain}:443... please wait...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                print("✅ TLS Connect PASS")
                tls_ok = True
    except Exception as e:
        print(f"❌ TLS Connect FAIL (Reason: {e})")

    # SSL Handshake
    ssl_ok = tls_ok  # SSL handshake covered in TLS connect above

    # Payload test
    print(f"\n🚀 Sending payload to {domain}... please wait...")
    try:
        resp = requests.get(f"https://{domain}", allow_redirects=False)
        if resp.status_code in [200, 404]:
            print(f"✅ Payload response PASS (HTTP {resp.status_code})")
            payload_ok = True
        else:
            print(f"❌ Payload response FAIL (HTTP {resp.status_code})")
    except Exception as e:
        print(f"❌ Payload response FAIL (Reason: {e})")

    # Redirect check
    if payload_ok and resp.is_redirect:
        print("❌ Redirect detected FAIL")
    else:
        print("✅ No redirect PASS")
        redirect_ok = True

    # Tunnel data flow test (simulated as real tunnel test needs active tunnel client)
    print(f"\n🚀 Testing tunnel data flow (simulated)... please wait...")
    if traceroute_ok and tls_ok and payload_ok and redirect_ok:
        print("✅ Tunnel data flow PASS")
        tunnel_ok = True
    else:
        print("❌ Tunnel data flow FAIL")

    # Final Decision
    print("\n==============================")
    if all([traceroute_ok, tls_ok, ssl_ok, payload_ok, redirect_ok, tunnel_ok]):
        print(f"✅ FINAL RESULT: WORKING BUG HOST -> {domain}")
    else:
        print(f"❌ FINAL RESULT: NON WORKING HOST -> {domain}")
    print("==============================")

if __name__ == "__main__":
    main_menu()
