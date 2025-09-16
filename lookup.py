import whois
import threading
import time

# Rate limit in seconds between requests
RATE_LIMIT = 2  

def lookup_domain(domain):
    """Perform WHOIS lookup and extract Registrar."""
    try:
        time.sleep(RATE_LIMIT)  # enforce rate limiting
        w = whois.whois(domain)
        registrar = w.get("registrar", "Registrar not found")
        print(f"{domain}: {registrar}")
    except Exception as e:
        print(f"{domain}: Error - {e}")

def main():
    # Read domains from input.txt 
    with open("input.txt", "r") as f:
        content = f.read()
    domains = content.split()  # splits by whitespace
    
    threads = []
    for domain in domains:
        t = threading.Thread(target=lookup_domain, args=(domain,))
        threads.append(t)
        t.start()
    
    # Wait for all threads to finish
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
