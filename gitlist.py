import requests
import time
import random
import os

def download_file(url, local_filename):
    print(f"Attempting to download '{url}' to '{local_filename}'...")
    try:
        with requests.get(url, stream=True, timeout=5) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Successfully downloaded '{local_filename}'.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        return False
    except IOError as e:
        print(f"Error writing file to disk: {e}")
        return False

def read_domains_from_local_file(local_filename, num_random_domains=10):
    print(f"\nReading domains from local file: {local_filename}")
    try:
        with open(local_filename, 'r', encoding='utf-8') as f:
            all_domains = f.readlines()
        valid_domains = [
            domain.strip() for domain in all_domains
            if domain.strip() and not domain.strip().startswith('#')
        ]
        print(f"Successfully read {len(valid_domains)} domains from local file")
    except FileNotFoundError:
        print(f"Error: file '{local_filename}' not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if len(valid_domains) < num_random_domains:
        print(f"Warning: Only {len(valid_domains)} domains available, selecting all of them")
        selected_domains = valid_domains
    else:
        selected_domains = random.sample(valid_domains, num_random_domains)
        print(f"Selected {len(selected_domains)} random domains for querying")

    print("\nStarting query operations for selected domains...\n")
    for i, domain in enumerate(selected_domains):
        url = f"https://{domain}"
        print(f"[{i+1}/{len(selected_domains)}] Attempting to query: {url}")

        try:
            response = requests.get(url, timeout=1, allow_redirects=True)
            print(f"  Status: {response.status_code} - OK (Redirected to: {response.url if response.history else 'N/A'})")
        except requests.exceptions.ConnectionError:
            print(f"  Error: Connection failed for {url}")
        except requests.exceptions.Timeout:
            print(f"  Error: Timeout reached for {url}")
        except requests.exceptions.HTTPError as e:
            print(f"  Error: HTTP error {e.response.status_code} for {url}")
        except requests.exceptions.RequestException as e:
            print(f"  Error: An unexpected request error occurred for {url}: {e}")
        except Exception as e:
            print(f"  Error: An unhandled error occurred for {url}: {e}")
        time.sleep(0.3)

    print("\nQuery operations completed for selected domains.")

if __name__ == "__main__":
    github-domain-list = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"
    local_domains_filename = "git-blocklist"

    if not os.path.exists(local_domains_filename):
        print("Local domain file not found. Downloading now...")
        if not download_file(github-domain-list, local_domains_filename):
            print("Failed to download the domain list. Exiting.")
            exit()
    else:
        print(f"Local domain file '{local_domains_filename}' already exists. Skipping download.")

    read_domains_from_local_file(local_domains_filename, num_random_domains=10)
