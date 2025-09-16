import whois
import argparse
import concurrent.futures
import time
import threading
import idna
import tldextract
import socket

# ---------------- CONFIG ----------------
RATE_LIMIT = 2        # seconds between WHOIS requests
MAX_WORKERS = 5       # max concurrent threads
RETRIES = 3           # retry attempts per domain
TIMEOUT = 10          # socket timeout seconds

# Token bucket for global rate limiting
tokens = threading.Semaphore(0)
stop_event = threading.Event()

def token_refiller():
    """Background thread to refill tokens at RATE_LIMIT interval."""
    while not stop_event.is_set():
        tokens.release()
        time.sleep(RATE_LIMIT)

def normalize_domain(domain):
    """Normalize subdomain -> registrable domain and encode IDNs."""
    extracted = tldextract.extract(domain.strip().lower())
    base_domain = f"{extracted.domain}.{extracted.suffix}"
    return idna.encode(base_domain).decode("ascii"), base_domain

def extract_registrar(w):
    """Extract registrar field with priority order."""
    priority_keys = ["registrar", "sponsoring registrar", "registrar name"]
    registrar = None
    for key in priority_keys:
        for wk in w.keys():
            if wk and wk.lower() == key:
                registrar = w.get(wk)
                break
        if registrar:
            break

    # fallback: any registrar-like key
    if not registrar:
        for wk in w.keys():
            if wk and "registrar" in wk.lower():
                registrar = w.get(wk)
                break

    # handle list values
    if isinstance(registrar, list):
        registrar = ", ".join(filter(None, registrar))
    return registrar

def lookup_domain(original_domain):
    """Perform WHOIS lookup with retries and rate limiting."""
    try:
        norm_domain, registrable = normalize_domain(original_domain)

        for attempt in range(1, RETRIES + 1):
            try:
                tokens.acquire()  # global pacing

                socket.setdefaulttimeout(TIMEOUT)
                w = whois.whois(norm_domain)

                registrar = extract_registrar(w)
                if registrar:
                    print(f"{original_domain} ({registrable}/{norm_domain}): {registrar}")
                else:
                    print(f"{original_domain} ({registrable}/{norm_domain}): Registrar not found")
                return
            except Exception as e:
                if attempt < RETRIES:
                    time.sleep(attempt)  # backoff
                else:
                    print(f"{original_domain}: Error - {e}")

    except Exception as e:
        print(f"{original_domain}: Error - {e}")

def main():
    parser = argparse.ArgumentParser(description="WHOIS Registrar Lookup Tool")
    parser.add_argument("domains", nargs="*", help="List of domains to look up")
    parser.add_argument("--file", "-f", help="Optional input file with domains")
    args = parser.parse_args()

    # Gather domains
    domains = args.domains
    if args.file:
        with open(args.file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.extend(line.split())

    # Deduplicate and sort for stable output
    domains = sorted(set(domains))
    if not domains:
        print("No domains provided. Use CLI or --file input.txt")
        return

    # Start token refiller
    refill_thread = threading.Thread(target=token_refiller, daemon=True)
    refill_thread.start()

    # Run lookups
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(lookup_domain, d) for d in domains]
        concurrent.futures.wait(futures)

    # Stop refiller
    stop_event.set()
    refill_thread.join(timeout=1)

if __name__ == "__main__":
    main()
