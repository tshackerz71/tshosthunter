import subprocess
import socket
import ssl
import requests
import sys

def main_menu():
    while True:
        print("\n==============================")
        print("  TSHACKER - BUG HOST VERIFIER")
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

    for domain in domains:
        print(f"\n==============================")
        print(f"Testing domain: {domain}")
        print("==============================")
        traceroute_result = traceroute_test(domain)
        tls_result = tls_check(domain)
        payload_result = payload_test(domain)

        if traceroute_result and tls_result and payload_result:
            print(f"\n✅ FINAL RESULT: {domain} is a WORKING BUG HOST ✅")
        else:
            print(f"\n❌ FINAL RESULT: {domain} is NOT a working bug host ❌")

def traceroute_test(domain):
    print(f"\n[Traceroute] Running traceroute...")
    try:
        result = subprocess.run(['traceroute', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        output = result.stdout
        if any(public_ip_in_line(line) for line in output.splitlines()):
            print("✔ Traceroute PASS: Public IP hop found")
            return True
        else:
            print("❌ Traceroute FAIL: No public IP hop found")
            return False
    except Exception as e:
        print(f"❌ Traceroute failed: {e}")
        return False

def public_ip_in_line(line):
    # Simple check for public IP pattern in traceroute output
    import re
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    if match:
        ip = match.group(1)
        # Skip private IP ranges
        private_ranges = [
            ('10.',), ('192.168.',), ('172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', 
             '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
        ]
        for pr in private_ranges:
            if any(ip.startswith(p) for p in pr):
                return False
        return True
    return False

def tls_check(domain):
    print(f"\n[TLS] Checking TLS handshake on port 443...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"✔ TLS PASS: Handshake successful. CN: {cert['subject']}")
                return True
    except Exception as e:
        print(f"❌ TLS FAIL: {e}")
        return False

def payload_test(domain):
    print(f"\n[Payload Test] Sending HEAD request...")
    try:
        resp = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        if resp.status_code == 200:
            print(f"✔ Payload PASS: HTTP 200 OK")
            return True
        elif resp.status_code == 404:
            print(f"✔ Payload PASS: HTTP 404 Not Found")
            return True
        else:
            print(f"❌ Payload FAIL: HTTP status {resp.status_code}")
            return False
    except Exception as e:
        print(f"❌ Payload FAIL: {e}")
        return False

if __name__ == "__main__":
    main_menu()
