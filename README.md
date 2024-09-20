### Stager Script for Linux Systems ###
```
sudo bash < <(curl -s https://raw.githubusercontent.com/jdibby/traffgen/refs/heads/main/stager.sh)
```

### Clone The Directory and Change To The New Directory ###
```
git clone https://github.com/jdibby/traffgen && cd traffgen
```

### Build Container ###
```
docker build -t jdibby/traffgen .
```

### Run Container Continuously in Background ###
```
docker run --detach --restart unless-stopped jdibby/traffgen:latest
```

### Run Container in Foreground ###
```
docker run -it jdibby/traffgen:latest
```

### Help Page ###
```
docker run jdibby/traffgen:latest --help
```

### Update Repo ###
```
cd traffgen && git pull
```

### Running Help File ###
```
usage: generator.py [-h] [--suite {all,bigfile,crawl,dns,ftp,http,https,icmp,netflix,nmap,ntp,scaled,ssh,url-response,virus-sim-http,virus-sim-https}] [--size {S,M,L,XL}] [--loop] [--max-wait-secs MAX_WAIT_SECS] [--nowait]
                    [--os {debian,alpine}] [--update_packages] [--scaled_endpoints SCALED_ENDPOINTS] [--replace_all_endpoints REPLACE_ALL_ENDPOINTS] [--crawl-start CRAWL_START]

options:
  -h, --help            show this help message and exit
  --suite {all,bigfile,crawl,dns,ftp,http,https,icmp,netflix,nmap,ntp,scaled,ssh,url-response,virus-sim-http,virus-sim-https}
                        Test suite to run
  --size {S,M,L,XL}     Size of tests to run
  --loop                Loop test continuously
  --max-wait-secs MAX_WAIT_SECS
                        Maximum possible time (in seconds) for random intervals between tests or loops
  --nowait              Don't wait random intervals between tests or loops
  --os {debian,alpine}  Host OS running the script
  --update_packages     Install dependent packages
  --scaled_endpoints SCALED_ENDPOINTS
                        URL to query for scaled endpoints file
  --replace_all_endpoints REPLACE_ALL_ENDPOINTS
                        URL to query for replacement endpoints.py file
  --crawl-start CRAWL_START
                        URL to start crawling from
```
