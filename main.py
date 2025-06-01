import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import certifi

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BLUE = "\033[94m"


def check_cert_expiration(url):
    """
    Check SSL certificate expiration date for a given URL.

    Args:
        url (str): URL to check

    Returns:
        tuple: (url, expiration_date, days_remaining) or (url, None, None) if error
    """
    try:
        # Clean and parse URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed_url = urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path

        # Remove www. if present
        hostname = hostname.replace("www.", "")

        # Create SSL context with certifi's certificates
        context = ssl.create_default_context(cafile=certifi.where())

        # Create connection
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Get expiration date
                expire_date = datetime.strptime(
                    cert["notAfter"],  # pyright: ignore
                    "%b %d %H:%M:%S %Y %Z",
                )
                days_remaining = (expire_date - datetime.now()).days

                return url, expire_date, days_remaining
    except socket.gaierror:
        print(f"Error for {url}: Could not resolve hostname")
        return url, None, None
    except socket.timeout:
        print(f"Error for {url}: Connection timed out")
        return url, None, None
    except ssl.SSLError as e:
        print(f"Error for {url}: SSL error - {str(e)}")
        return url, None, None
    except Exception as e:
        print(f"Error for {url}: {str(e)}")
        return url, None, None


def main():
    # Example URLs to check
    urls = [
        "dasa.dev",
        "dansahagian.com",
        "fbsurvivor.com",
    ]

    print("Checking SSL certificates expiration dates...")
    print("-" * 50)

    for url in urls:
        print(f"\n{BLUE}Checking certificate for: {url}{RESET}")
        print(f"Attempting connection to: {url}")
        url, expire_date, days_remaining = check_cert_expiration(url)

        if expire_date and days_remaining:
            print(f"{GREEN}✓ Success!{RESET}")
            print(f"{BLUE}Certificate Information:{RESET}")
            print(f"  URL: {url}")
            print(f"  Expires: {expire_date.strftime('%Y-%m-%d')}")
            if days_remaining <= 30:
                print(f"  Days remaining: {RED}{days_remaining}{RESET}")
            else:
                print(f"  Days remaining: {GREEN}{days_remaining}{RESET}")
        else:
            print(f"{RED}✗ Failed to get certificate information{RESET}")
        print("-" * 50)


if __name__ == "__main__":
    main()
