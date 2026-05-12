#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
endpoints.py — Traffic Generator endpoint data
================================================
All network targets (IPs, URLs, user-agents, community strings, etc.) used
by generator.py are defined here as plain Python lists.  Keeping data
separate from logic makes it easy to customise targets without touching
test code.

The replace_all_endpoints() function in generator.py can hot-swap this file
at runtime from a remote URL.

Variable index (matches generator.py usage names 1-to-1):

  DNS
    dns_endpoints       Public DNS resolver IPs (used by dns_queries, dns_exfil)
    dns_urls            Domain names to resolve (dns_queries, http_random, doh_check)
    doh_providers       DNS-over-HTTPS provider URLs (doh_check)
    dot_servers         DNS-over-TLS (ip, servername) tuples (dot_check)
    dns_exfil_domains   Domains used for DNS-tunnelling simulation (dns_exfil)

  Network / layer-3
    icmp_endpoints      IPs for ping / traceroute (icmp_probe, traceroute)
    bgp_neighbors       IPs for GoBGP peering sessions (bgp_peering)

  Application protocols
    ntp_endpoints       NTP server hostnames (ntp_probe)
    ssh_endpoints       IPs / hostnames for SSH probes (ssh_probe)
    nmap_endpoints      IPs for nmap port scans (nmap_scan, nmap_vuln)
    snmp_endpoints      IPs / hostnames for SNMP probes (snmp_v1/v2c/v3)
    snmp_v1_strings     SNMPv1 community strings
    snmp_v2c_strings    SNMPv2c community strings
    snmp_v3_creds       SNMPv3 credential tuples (user, level, auth-proto, auth-pass, priv-proto, priv-pass)

  Web / HTTPS traffic
    http_endpoints      Plain HTTP hostnames (http_random)
    https_endpoints     General HTTPS URLs (https_random, https_crawl, http3, webscan_nikto, speed_test)
    ad_endpoints        Ad-network URLs — fallback when Hagezi blocklist is unreachable
    ai_endpoints        AI-service HTTPS URLs (ai_https)
    webscan_endpoints   Intentionally-vulnerable web apps (webscan_nikto)
    kyber_endpoints     Post-quantum TLS endpoints (kyber_tls)

  Threat simulation
    malware_endpoints   Malware / C2-category domains (malware_domains)
    malware_user_agents Bot / malware user-agent strings (malware_domains, c2_beacon)
    malware_files       URLs to known-bad file archives (malware_download)
    c2_beacon_targets   Public echo services for C2 check-in simulation (c2_beacon)
    virus_endpoints     EICAR / AV-test file URLs (virus_download)
    squatting_endpoints Domains probed for homograph / squatting (domain_check, phishing_domains)
    pornography_endpoints Adult-content URLs (pornography_crawl)
    dlp_https_endpoints DLP test-data file URLs (dlp_download)

  User agents
    user_agents         ~500 realistic browser UAs (most HTTP functions)
    malware_user_agents Malware / scanner UAs (malware_domains, c2_beacon)

  LLM / AI APIs
    llm_api_endpoints   REST API paths for major AI providers (llm_dlp)
    llm_web_endpoints   Browser-facing AI app URLs (llm_dlp, ai_https)

  S3 / cloud object storage
    s3_download_urls    S3 bucket/object URLs for GET simulation (s3_sim)
    s3_upload_targets   S3 bucket/key paths for PUT upload simulation (s3_sim)

  New detection suites
    shadow_it_endpoints      Unsanctioned cloud apps (shadow_it) — CASB app-control
    tor_anonymizer_endpoints Tor/VPN/proxy sites (tor_anonymizer) — URL-filter category
    waf_attack_targets       Pen-test-authorised web apps for WAF probes (waf_attack)
    data_exfil_targets       Paste/upload services for DLP POST simulation (data_exfil_http)
    ips_ua_signatures        ~260 malicious/suspicious UA strings (ips_ua) — IDS/IPS UA rules
    ips_ua_targets           Safe IDS/IPS test hosts for UA-based probes (ips_ua)
    cve_http_probes          CVE exploit probe tuples (cve_probe) — IPS signature detection
    cve_probe_targets        Safe IDS/IPS test hosts for CVE probes (cve_probe)
"""

# ── DNS resolvers ──────────────────────────────────────────────────────────────
dns_endpoints = [
    # US
    "8.8.8.8", "8.8.4.4",            # Google
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "9.9.9.9", "149.112.112.112",    # Quad9
    "64.6.64.6",                      # Verisign
    # Canada
    "149.112.121.10", "149.112.122.10",  # CIRA
    # Europe
    "77.88.8.8", "77.88.8.1",        # Yandex — Russia
    "84.200.69.80", "84.200.70.40",  # DNS.Watch — Germany
    "80.67.169.40",                   # FDN — France
    "194.168.4.100",                  # BT — UK
    "82.132.254.2",                   # Virgin Media — UK
    "212.69.36.35",                   # Sky Broadband — UK
    "81.103.221.35",                  # EE — UK
    "194.109.6.66",                   # SURFnet — Netherlands
    "194.132.32.32",                  # Bahnhof — Sweden
    "91.239.100.100", "89.233.43.71", # UncensoredDNS — Denmark
    "195.159.0.100",                  # UiO — Norway
    "193.166.4.24",                   # FUNET — Finland
    "193.17.47.1", "185.43.135.1",   # CZ.NIC — Czech Republic
    "130.59.31.248",                  # SWITCH — Switzerland
    "195.175.39.39",                  # Türk Telekom — Turkey
    "195.238.2.21",                   # Scarlet — Belgium
    "62.1.0.11",                      # OTE — Greece
    "89.104.118.6",                   # RCS&RDS — Romania
    "213.0.184.251",                  # Orange — Spain
    "193.43.4.12",                    # CNR — Italy
    "212.162.33.6",                   # NASK — Poland
    # Asia-Pacific
    "202.12.27.33",                   # WIDE — Japan
    "168.126.63.1", "168.126.63.2",  # KT — South Korea
    "223.5.5.5", "223.6.6.6",        # Alibaba — China
    "119.29.29.29", "114.114.114.114",  # Tencent/114DNS — China
    "168.95.1.1", "168.95.192.1",    # Chunghwa — Taiwan
    "203.80.96.10",                   # HKBN — Hong Kong
    "202.166.205.61",                 # Singtel — Singapore
    "103.8.45.5", "103.8.46.5",      # BSNL — India
    "122.160.36.29",                  # Airtel — India (New Delhi)
    "59.144.75.1",                    # BSNL — India (Chennai)
    "115.115.115.115",                # BSNL — India (Mumbai)
    "203.113.0.110",                  # TOT — Thailand
    "203.162.4.190",                  # VDC — Vietnam
    "202.155.0.10",                   # Telkom — Indonesia
    "210.213.131.235",                # PLDT — Philippines
    "202.90.136.56",                  # Globe Telecom — Philippines (Manila)
    "112.198.67.235",                 # Globe Telecom — Philippines (Cebu)
    "202.188.0.132",                  # TMnet — Malaysia
    "203.82.80.8",                    # PTCL — Pakistan
    "202.4.96.2",                     # Grameen — Bangladesh
    # Middle East & Africa
    "212.199.244.162",                # Bezeq — Israel
    "213.42.20.20",                   # Emirates — UAE
    "212.104.59.28",                  # Mobily — Saudi Arabia
    "196.37.155.180",                 # IS — South Africa
    "196.207.40.30",                  # MTN — Nigeria
    "196.201.216.30",                 # Jamii — Kenya
    "196.202.250.10",                 # Nour — Egypt
    # South America
    "200.221.11.101",                 # NIC.br — Brazil
    "200.49.159.68",                  # Claro — Argentina
    "200.33.89.90",                   # Telmex — Mexico
    # Oceania
    "139.130.4.5",                    # Internode — Australia
    "202.160.50.9",                   # Orcon — New Zealand
    # Internal/private (LAN reachability)
    "10.254.254.1",
    ]

# ── DNS query targets (domain names) ──────────────────────────────────────────
dns_urls = [
    "accounts.google.com",
    "adn.com",
    "time.google.com",
    "twitter.com",
    "tesla.com",
    "adobe.com",
    "apple.com",
    "docs.google.com",
    "en.wikipedia.org",
    "openai.com",
    "neverssl.com",
    "github.com",
    "linkedin.com",
    "maps.google.com",
    "microsoft.com",
    "mozilla.org",
    "play.google.com",
    "www.thelegacy.de",
    "plus.google.com",
    "sites.google.com",
    "www.att.com",
    "info.cern.ch",
    "support.google.com",
    "vimeo.com",
    "wordpress.org",
    "www.blogger.com",
    "www.google.com",
    "www.unco.edu",
    "www.apple.com",
    "www.netflix.com",
    "youtube.com",
    "abc.com",
    ]

# ── ICMP / traceroute targets ──────────────────────────────────────────────────
icmp_endpoints = [
    # United States — Alabama (AL)
    "131.204.122.1",                  # UAB — Birmingham
    "12.106.32.1",                    # AT&T Southeast — Birmingham
    # United States — Alaska (AK)
    "192.234.141.1",                  # ACS (Alaska Communications) — Anchorage
    "12.12.12.12",                    # GCI / AT&T — Anchorage
    # United States — Arizona (AZ)
    "150.135.0.1",                    # University of Arizona — Tucson
    "150.169.0.1",                    # Arizona State University — Tempe
    # United States — Arkansas (AR)
    "130.184.0.1",                    # University of Arkansas — Fayetteville
    "69.135.176.1",                   # Windstream — Little Rock
    # United States — California (CA)
    "128.97.0.1",                     # UCLA — Los Angeles
    "171.67.0.1",                     # Stanford University — Palo Alto
    # United States — Colorado (CO)
    "128.138.0.1",                    # University of Colorado — Boulder
    "24.116.0.201",                   # Comcast — Denver
    # United States — Connecticut (CT)
    "130.132.0.1",                    # Yale University — New Haven
    "68.87.196.1",                    # Comcast — Hartford
    # United States — Delaware (DE)
    "128.175.0.1",                    # University of Delaware — Newark
    "68.85.78.1",                     # Comcast — Wilmington
    # United States — Florida (FL)
    "128.186.0.1",                    # Florida State University — Tallahassee
    "128.227.0.1",                    # University of Florida — Gainesville
    # United States — Georgia (GA)
    "130.207.0.1",                    # Georgia Tech — Atlanta
    "68.87.85.98",                    # Comcast — Atlanta
    # United States — Hawaii (HI)
    "128.171.0.1",                    # University of Hawaii — Honolulu
    "66.25.0.1",                      # Hawaiian Telcom — Honolulu
    # United States — Idaho (ID)
    "132.178.0.1",                    # University of Idaho — Moscow
    "65.175.64.1",                    # CenturyLink — Boise
    # United States — Illinois (IL)
    "128.174.0.1",                    # University of Illinois — Urbana-Champaign
    "68.85.4.1",                      # Comcast — Chicago
    # United States — Indiana (IN)
    "128.210.0.1",                    # Purdue University — West Lafayette
    "68.87.64.146",                   # Comcast — Indianapolis
    # United States — Iowa (IA)
    "128.255.0.1",                    # University of Iowa — Iowa City
    "66.92.0.1",                      # MidAmerican Energy/ISU — Ames
    # United States — Kansas (KS)
    "129.237.0.1",                    # University of Kansas — Lawrence
    "65.113.0.1",                     # Southwestern Bell — Wichita
    # United States — Kentucky (KY)
    "128.163.0.1",                    # University of Kentucky — Lexington
    "68.87.52.1",                     # Comcast — Louisville
    # United States — Louisiana (LA)
    "130.39.0.1",                     # Louisiana State University — Baton Rouge
    "69.135.64.1",                    # Cox — New Orleans
    # United States — Maine (ME)
    "130.111.0.1",                    # University of Maine — Orono
    "67.211.128.1",                   # Spectrum/Charter — Portland
    # United States — Maryland (MD)
    "128.220.0.1",                    # University of Maryland — College Park
    "68.87.196.2",                    # Comcast — Baltimore
    # United States — Massachusetts (MA)
    "18.7.0.1",                       # MIT — Cambridge
    "68.87.230.1",                    # Comcast — Boston
    # United States — Michigan (MI)
    "141.211.0.1",                    # University of Michigan — Ann Arbor
    "68.87.64.1",                     # Comcast — Detroit
    # United States — Minnesota (MN)
    "134.84.0.1",                     # University of Minnesota — Minneapolis
    "67.211.0.1",                     # Comcast — Minneapolis
    # United States — Mississippi (MS)
    "130.74.0.1",                     # University of Mississippi — Oxford
    "69.135.192.1",                   # C Spire — Jackson
    # United States — Missouri (MO)
    "128.252.0.1",                    # Washington University — St. Louis
    "68.87.22.1",                     # Comcast — Kansas City
    # United States — Montana (MT)
    "153.90.0.1",                     # Montana State University — Bozeman
    "65.175.128.1",                   # CenturyLink — Billings
    # United States — Nebraska (NE)
    "129.93.0.1",                     # University of Nebraska — Lincoln
    "66.27.96.1",                     # Cox — Omaha
    # United States — Nevada (NV)
    "134.197.0.1",                    # University of Nevada — Reno
    "68.105.28.11",                   # Cox — Las Vegas
    # United States — New Hampshire (NH)
    "132.177.0.1",                    # University of New Hampshire — Durham
    "67.211.224.1",                   # Comcast — Manchester
    # United States — New Jersey (NJ)
    "128.6.0.1",                      # Rutgers University — New Brunswick
    "68.87.216.1",                    # Comcast — Newark
    # United States — New Mexico (NM)
    "129.24.0.1",                     # University of New Mexico — Albuquerque
    "65.113.128.1",                   # CenturyLink — Albuquerque
    # United States — New York (NY)
    "128.122.0.1",                    # New York University — New York City
    "68.87.240.1",                    # Comcast — Buffalo
    # United States — North Carolina (NC)
    "152.2.0.1",                      # UNC Chapel Hill
    "68.87.44.1",                     # Comcast — Charlotte
    # United States — North Dakota (ND)
    "134.129.0.1",                    # University of North Dakota — Grand Forks
    "65.113.192.1",                   # CenturyLink — Fargo
    # United States — Ohio (OH)
    "128.146.0.1",                    # Ohio State University — Columbus
    "68.87.72.1",                     # Comcast — Cleveland
    # United States — Oklahoma (OK)
    "129.15.0.1",                     # University of Oklahoma — Norman
    "69.135.128.1",                   # Cox — Tulsa
    # United States — Oregon (OR)
    "128.223.0.1",                    # University of Oregon — Eugene
    "68.87.176.1",                    # Comcast — Portland
    # United States — Pennsylvania (PA)
    "128.91.0.1",                     # University of Pennsylvania — Philadelphia
    "68.87.202.1",                    # Comcast — Pittsburgh
    # United States — Rhode Island (RI)
    "138.99.0.1",                     # Brown University — Providence
    "68.87.212.1",                    # Comcast — Providence
    # United States — South Carolina (SC)
    "129.252.0.1",                    # University of South Carolina — Columbia
    "69.135.160.1",                   # AT&T — Greenville
    # United States — South Dakota (SD)
    "139.32.0.1",                     # South Dakota State University — Brookings
    "65.113.224.1",                   # CenturyLink — Sioux Falls
    # United States — Tennessee (TN)
    "160.36.0.1",                     # Vanderbilt University — Nashville
    "68.87.60.1",                     # Comcast — Memphis
    # United States — Texas (TX)
    "128.83.0.1",                     # University of Texas — Austin
    "68.87.28.1",                     # Comcast — Houston
    # United States — Utah (UT)
    "155.97.0.1",                     # University of Utah — Salt Lake City
    "65.175.192.1",                   # CenturyLink — Salt Lake City
    # United States — Vermont (VT)
    "132.198.0.1",                    # University of Vermont — Burlington
    "67.211.160.1",                   # Comcast — Burlington
    # United States — Virginia (VA)
    "128.143.0.1",                    # University of Virginia — Charlottesville
    "68.87.108.1",                    # Comcast — Richmond
    # United States — Washington (WA)
    "140.142.0.1",                    # University of Washington — Seattle
    "68.87.184.1",                    # Comcast — Seattle
    # United States — West Virginia (WV)
    "157.182.0.1",                    # West Virginia University — Morgantown
    "67.211.192.1",                   # Comcast — Charleston
    # United States — Wisconsin (WI)
    "128.105.0.1",                    # University of Wisconsin — Madison
    "68.87.12.1",                     # Comcast — Milwaukee
    # United States — Wyoming (WY)
    "129.72.0.1",                     # University of Wyoming — Laramie
    "65.175.224.1",                   # CenturyLink — Cheyenne
    # United States — General (CDN / anycast)
    "8.8.8.8", "8.8.4.4",            # Google DNS
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "9.9.9.9",                        # Quad9
    "4.2.2.2", "4.2.2.4",            # Level3
    # Canada
    "149.112.121.10",                 # CIRA
    # Brazil
    "200.221.11.101",                 # NIC.br
    # Argentina
    "200.49.159.68",                  # Claro
    # Mexico
    "200.33.89.90",                   # Telmex
    # Chile
    "200.1.123.46",                   # ENTEL
    # Russia
    "77.88.8.8", "77.88.8.1",        # Yandex
    # Germany
    "84.200.69.80", "84.200.70.40",  # DNS.Watch
    # France
    "80.10.246.2", "80.10.246.129",  # Orange
    # UK
    "194.168.4.100",                  # BT
    "82.132.254.2",                   # Virgin Media
    "212.69.36.35",                   # Sky Broadband
    "81.103.221.35",                  # EE
    # Netherlands
    "194.109.6.66",                   # SURFnet
    # Sweden
    "194.132.32.32",                  # Bahnhof
    # Denmark
    "91.239.100.100",                 # UncensoredDNS
    # Norway
    "195.159.0.100",                  # UiO
    # Finland
    "193.166.4.24",                   # FUNET
    # Czech Republic
    "193.17.47.1",                    # CZ.NIC
    # Turkey
    "195.175.39.39",                  # Türk Telekom
    # Belgium
    "195.238.2.21",                   # Scarlet
    # Greece
    "62.1.0.11",                      # OTE
    # Romania
    "89.104.118.6",                   # RCS&RDS
    # Switzerland
    "130.59.31.248",                  # SWITCH
    # Italy
    "193.43.4.12",                    # CNR
    # Japan
    "202.12.27.33",                   # WIDE Project
    # South Korea
    "168.126.63.1", "168.126.63.2",  # KT
    # China
    "223.5.5.5", "119.29.29.29", "114.114.114.114",
    # Taiwan
    "168.95.1.1",                     # Chunghwa
    # Hong Kong
    "203.80.96.10",                   # HKBN
    # Singapore
    "202.166.205.61",                 # Singtel
    # Thailand
    "203.113.0.110",                  # TOT
    # Vietnam
    "203.162.4.190",                  # VDC
    # Indonesia
    "202.155.0.10",                   # Telkom
    # Philippines
    "210.213.131.235",                # PLDT
    "202.90.136.56",                  # Globe Telecom — Manila
    "112.198.67.235",                 # Globe Telecom — Cebu
    # Malaysia
    "202.188.0.132",                  # TMnet
    # India
    "103.8.45.5", "103.8.46.5",      # BSNL
    "122.160.36.29",                  # Airtel — New Delhi
    "59.144.75.1",                    # BSNL — Chennai
    "115.115.115.115",                # BSNL — Mumbai
    # Pakistan
    "203.82.80.8",                    # PTCL
    # Bangladesh
    "202.4.96.2",                     # Grameen
    # Australia
    "139.130.4.5",                    # Internode
    # New Zealand
    "202.160.50.9",                   # Orcon
    # Israel
    "212.199.244.162",                # Bezeq
    # UAE
    "213.42.20.20",                   # Emirates
    # Saudi Arabia
    "212.104.59.28",                  # Mobily
    # South Africa
    "196.37.155.180",                 # Internet Solutions
    # Nigeria
    "196.207.40.30",                  # MTN
    # Kenya
    "196.201.216.30",                 # Jamii Telecom
    # Egypt
    "196.202.250.10",                 # Nour
    # Private LAN (test local reachability)
    "172.30.0.1", "172.16.0.1", "172.22.11.1", "192.168.1.1",
    ]

# ── NTP servers ───────────────────────────────────────────────────────────────
ntp_endpoints = [
    '1.ro.pool.ntp.org',
    '0.us.pool.ntp.org',
    '1.us.pool.ntp.org',
    '2.us.pool.ntp.org',
    '3.us.pool.ntp.org',
    'time.google.com',
    'time-a-g.nist.gov',
    'time-b-g.nist.gov',
    'time-c-g.nist.gov',
    'time-d-g.nist.gov',
    'time-e-g.nist.gov',
    'time-a-wwv.nist.gov',
    'time-b-wwv.nist.gov',
    'time-c-wwv.nist.gov',
    'time-d-wwv.nist.gov',
    'time-e-wwv.nist.gov',
    'time-a-b.nist.gov',
    'time-b-b.nist.gov',
    'time-c-b.nist.gov',
    'time-d-b.nist.gov',
    'time-e-b.nist.gov',
    'time.nist.gov',
    'utcnist.colorado.edu',
    'utcnist2.colorado.edu',
    'ag.pool.ntp.org',
    'ai.pool.ntp.org',
    'bb.pool.ntp.org',
    'bl.pool.ntp.org',
    'bm.pool.ntp.org',
    'bq.pool.ntp.org',
    'bz.pool.ntp.org',
    'ca.pool.ntp.org',
    'cr.pool.ntp.org',
    'dm.pool.ntp.org',
    'gd.pool.ntp.org',
    'gl.pool.ntp.org',
    'hn.pool.ntp.org',
    'ht.pool.ntp.org',
    'ky.pool.ntp.org',
    'mf.pool.ntp.org',
    'mx.pool.ntp.org',
    'ni.pool.ntp.org',
    'pa.pool.ntp.org',
    'sv.pool.ntp.org',
    'sx.pool.ntp.org',
    'vc.pool.ntp.org',
    'vg.pool.ntp.org',
    'vi.pool.ntp.org',
]

# ── SSH probe targets ─────────────────────────────────────────────────────────
ssh_endpoints = [
    "12.12.12.12",
    "192.168.1.1",
    "172.16.1.1",
    "10.10.10.1",
    "10.177.177.1",
    "10.188.188.1",
    "10.199.199.1",
    "10.211.211.1",
    "192.168.2.1",
    "172.30.0.1",
    "192.168.2.2",
    "www.testmyids.com",
    "scanme.nmap.org",
    ]

# ── Nmap scan targets ─────────────────────────────────────────────────────────
# Only publicly routable hosts that explicitly authorise scanning.
# scanme.nmap.org / 45.33.32.156 — Nmap's official scan-me service (nmap.org/book/legal-issues.html)
# testmyids.com              — Emerging Threats IDS test service
# juice-shop.herokuapp.com   — OWASP Juice Shop intentionally-vulnerable demo app
nmap_endpoints = [
    '45.33.32.156',            # scanme.nmap.org (IPv4)
    'scanme.nmap.org',
    'www.testmyids.com',
    'juice-shop.herokuapp.com',
]

# ── Plain HTTP endpoints ───────────────────────────────────────────────────────
http_endpoints = [
    "www.facebook.com",
    "www.foxnews.com",
    "www.google.com",
    "neverssl.com",
    "www.linkedin.com",
    "baidu.com",
    "www.spotify.com",
    "info.cern.ch",
    "gnu.org",
    "www.twitter.com",
    "www.testmyids.com",
    "scanme.nmap.org",
    "httpforever.com",
    ]

# ── Webscan / intentionally-vulnerable targets (nikto) ───────────────────────
webscan_endpoints = [
    'www.testmyids.com',
    'scanme.nmap.org',
    'httpforever.com',
    'testmyids.com',
    'hackazon.webscantest.com',
    'zero.webappsecurity.com',
    'testhtml5.vulnweb.com',
    'juice-shop.herokuapp.com',
]

# ── Ad-network / tracker URLs ─────────────────────────────────────────────────
ad_endpoints = [
    "adtago.s3.amazonaws.com",
    "advice-ads.s3.amazonaws.com",
    "pagead2.googlesyndication.com",
    "stats.g.doubleclick.net",
    "ad.doubleclick.net",
    "static.doubleclick.net",
    "m.doubleclick.net",
    "mediavisor.doubleclick.net",
    "ads30.adcolony.com",
    "adc3-launch.adcolony.com",
    "events3alt.adcolony.com",
    "wd.adcolony.com",
    "static.media.net",
    "media.net",
    "adservetx.media.net",
    "static.ads-twitter.com",
    "ads.linkedin.com",
    "ads.pinterest.com",
    "ads.youtube.com",
    "ads.tiktok.com",
    "ads.yahoo.com",
    "api.ad.xiaomi.com",
    "sdkconfig.ad.xiaomi.com",
    "sdkconfig.ad.intl.xiaomi.com",
    "samsungads.com",
    "pagead2.googleadservices.com",
    "events.hotjar.io",
    "ssl.google-analytics.com",
    "https://google-analytics.com",
    "adservice.google.com",
    "analytics.google.com",
    "log.pinterest.com",
    "analytics.pinterest.com",
    "click.googleanalytics.com",
    "cdn.mouseflow.com",
    "realtime.luckyorange.com",
    "notify.bugsnag.com",
    "an.facebook.com",
    "pixel.facebook.com",
    "nmetrics.samsung.com",
    "appmetrica.yandex.ru",
    "afs.googlesyndication.com",
    "metrika.yandex.ru",
    "tracking.rus.miui.com",
    "extmaps-api.yandex.net",
    "logservice1.hicloud.com",
    "offerwall.yandex.net",
    "data.mistat.xiaomi.com",
    "data.ads.oppomobile.com",
    "ck.ads.oppomobile.com",
    "metrics.data.hicloud.com",
    "click.oneplus.cn",
    "adx.ads.oppomobile.com",
    "bdapi-ads.realmemobile.com",
    "adfstat.yandex.ru",
    "cdn-test.mouseflow.com",
    "events.reddit.com",
    "metrics.icloud.com",
    "api.luckyorange.com",
    "cs.luckyorange.net",
    "adtech.yahooinc.com",
    "upload.luckyorange.net",
    "gemini.yahoo.com",
    "sessions.bugsnag.com",
    "freshmarketer.com",
    "udc.yahoo.com",
    "metrics.mzstatic.com",
    "udcm.yahoo.com",
    "data.mistat.rus.xiaomi.com",
    "log.fc.yahoo.com",
    "data.mistat.india.xiaomi.com",
    "analytics.tiktok.com",
    "ads-api.twitter.com",
    "api-adservices.apple.com",
    "books-analytics-events.apple.com",
    "geo.yahoo.com",
    "settings.luckyorange.net",
    "weather-analytics-events.apple.com",
    "notes-analytics-events.apple.com",
    "analytics.query.yahoo.com",
    "smetrics.samsung.com",
    "open.oneplus.net",
    "events.redditmedia.com",
    "samsung-com.112.2o7.net",
    "trk.pinterest.com",
    "browser.sentry-cdn.com",
    "analyticsengine.s3.amazonaws.com",
    "analytics.s3.amazonaws.com",
    "script.hotjar.com",
    "o2.mouseflow.com",
    "auction.unityads.unity3d.com",
    "adserver.unityads.unity3d.com",
    "config.unityads.unity3d.com",
    "api.bugsnag.com",
    "gtm.mouseflow.com",
    "insights.hotjar.com",
    "mouseflow.com",
    "app.getsentry.com",
    "fwtracks.freshmarketer.com",
    "log.byteoversea.com",
    "cdn.luckyorange.com",
    "adm.hotjar.com",
    "w1.luckyorange.com",
    "app.bugsnag.com",
    "luckyorange.com",
    "webview.unityads.unity3d.com",
    "partnerads.ysm.yahoo.com",
    "tools.mouseflow.com",
    "api.mouseflow.com",
    "identify.hotjar.com",
    "iot-eu-logser.realme.com",
    "stats.wp.com",
    "claritybt.freshmarketer.com",
    "iadsdk.apple.com",
    "analytics-api.samsunghealthcn.com",
    "metrics2.data.hicloud.com",
    "grs.hicloud.com",
    "adsfs.oppomobile.com",
    "adfox.yandex.ru",
    "surveys.hotjar.com",
    "bdapi-in-ads.realmemobile.com",
    "logservice.hicloud.com",
    "analytics.yahoo.com",
    "iot-logser.realme.com",
    "business-api.tiktok.com",
    "ads-sg.tiktok.com",
    "ads-api.tiktok.com",
    "logbak.hicloud.com",
    "analytics-sg.tiktok.com",
    "analytics.pointdrive.linkedin.com",
    "careers.hotjar.com",
]

# ── General HTTPS endpoints ───────────────────────────────────────────────────
https_endpoints = [
    'https://urlhaus.abuse.ch',
    'https://urlhaus.abuse.ch/browse',
    'https://commoncrawl.org',
    'https://dmoztools.net',
    'http://crawler-test.com',
    'https://abcnews.go.com',
    'https://aboutads.info',
    'https://amazon.com',
    'https://aol.com',
    'https://apache.org',
    'https://bbc.co.uk',
    'https://bbc.com',
    'https://bloomberg.com',
    'https://bp.blogspot.com',
    'https://buydomains.com',
    'https://cloudflare.com',
    'https://cnn.com',
    'https://openai.com',
    'https://peacocktv.com',
    'https://www.max.com',
    'https://developers.google.com',
    'https://draft.blogger.com',
    'https://engadget.com',
    'https://es.wikipedia.org',
    'https://europa.eu',
    'https://feedburner.com',
    'https://forbes.com',
    'https://fr.wikipedia.org',
    'https://google.com',
    'https://google.co.jp',
    'https://google.co.uk',
    'https://google.ca',
    'https://google.com.au',
    'https://google.de',
    'https://google.fr',
    'https://google.it',
    'https://google.es',
    'https://google.nl',
    'https://google.com.br',
    'https://google.ru',
    'https://google.co.in',
    'https://google.cn',
    'https://google.co.kr',
    'https://google.com.mx',
    'https://google.co.nz',
    'https://google.co.za',
    'https://google.com.ar',
    'https://google.be',
    'https://google.ch',
    'https://google.se',
    'https://google.no',
    'https://google.dk',
    'https://google.pl',
    'https://google.com.tr',
    'https://google.pt',
    'https://google.cz',
    'https://google.fi',
    'https://google.hu',
    'https://google.gr',
    'https://google.ie',
    'https://google.co.il',
    'https://google.co.id',
    'https://google.com.my',
    'https://google.com.ph',
    'https://google.com.sg',
    'https://google.co.th',
    'https://google.com.vn',
    'https://google.com.ua',
    'https://google.ro',
    'https://google.cl',
    'https://google.com.co',
    'https://google.co.ve',
    'https://google.com.eg',
    'https://google.ae',
    'https://google.com.sa',
    'https://google.com.pk',
    'https://google.com.bd',
    'https://google.lk',
    'https://google.co.ke',
    'https://google.com.ng',
    'https://google.com.gh',
    'https://google.co.tz',
    'https://google.co.ug',
    'https://google.kz',
    'https://google.by',
    'https://google.sk',
    'https://google.bg',
    'https://google.hr',
    'https://google.si',
    'https://google.ee',
    'https://google.lv',
    'https://google.lt',
    'https://google.is',
    'https://google.lu',
    'https://google.li',
    'https://google.com.mt',
    'https://google.com.cy',
    'https://google.com.pe',
    'https://google.com.ec',
    'https://google.com.uy',
    'https://google.com.py',
    'https://google.com.bo',
    'https://google.com.pa',
    'https://google.com.do',
    'https://google.co.cr',
    'https://google.com.gt',
    'https://google.com.sv',
    'https://google.hn',
    'https://google.com.ni',
    'https://google.com.jm',
    'https://google.tt',
    'https://google.com.pr',
    'https://hugedomains.com',
    'https://line.me',
    'https://live.com',
    'https://medium.com',
    'https://msn.com',
    'https://networkadvertising.org',
    'https://news.google.com',
    'https://nih.gov',
    'https://nytimes.com',
    'https://opera.com',
    'https://oracle.com',
    'https://paypal.com',
    'https://policies.google.com',
    'https://pt.wikipedia.org',
    'https://reuters.com',
    'https://theguardian.com',
    'https://tinyurl.com',
    'https://tools.google.com',
    'https://un.org',
    'https://uol.com.br',
    'https://w3.org',
    'https://washingtonpost.com',
    'https://whatsapp.com',
    'https://wikimedia.org',
    'https://wired.com',
    'https://www.foxnews.com',
    'https://www.google.com',
    'https://www.gov.uk',
    'https://www.linkedin.com',
    'https://www.imdb.com',
    'https://www.office.com',
    'https://www.huffingtonpost.com',
    'https://www.yahoo.com',
    'https://www.microsoft.com',
    'https://www.salesforce.com',
    'https://www.adobe.com',
    'https://www.oracle.com',
    'https://www.sap.com',
    'https://www.servicenow.com',
    'https://www.workday.com',
    'https://www.intuit.com',
    'https://www.shopify.com',
    'https://www.zendesk.com',
    'https://www.docusign.com',
    'https://zoom.us',
    'https://slack.com',
    'https://asana.com',
    'https://monday.com',
    'https://clickup.com',
    'https://www.notion.so',
    'https://www.smartsheet.com',
    'https://calendly.com',
    'https://miro.com',
    'https://www.figma.com',
    'https://www.canva.com',
    'https://www.grammarly.com',
    'https://zapier.com',
    'https://www.twilio.com',
    'https://stripe.com',
    'https://www.adyen.com',
    'https://pos.toasttab.com',
    'https://www.hubspot.com',
    'https://www.xero.com',
    'https://gusto.com',
    'https://www.crowdstrike.com',
    'https://www.okta.com',
    'https://www.zscaler.com',
    'https://www.cloudflare.com',
    'https://1password.com',
    'https://www.databricks.com',
    'https://www.snowflake.com',
    'https://www.palantir.com',
    'https://www.datadoghq.com',
    'https://www.splunk.com',
    'https://mailchimp.com',
    'https://github.com',
    'https://about.gitlab.com',
    'https://circleci.com',
    'https://www.postman.com',
    'https://sentry.io',
    'https://amplitude.com',
    'https://mixpanel.com',
    'https://segment.com',
    'https://auth0.com',
    'https://www.workiva.com',
    'https://www.applovin.com',
    'https://www.cyberark.com',
    'https://www.nutanix.com',
    'https://www.qlik.com',
    'https://www.alteryx.com',
    'https://www.uipath.com',
    'https://www.freshworks.com',
    'https://www.intercom.com',
    'https://www.drift.com',
    'https://www.pendo.io',
    'https://www.walkme.com',
    'https://heap.io',
    'https://www.fullstory.com',
    'https://www.hotjar.com',
    'https://www.qualtrics.com',
    'https://www.typeform.com',
    'https://www.wix.com',
    'https://www.squarespace.com',
    'https://webflow.com',
    'https://www.algolia.com',
    'https://www.mulesoft.com',
    'https://www.confluent.io',
    'https://www.hashicorp.com',
    'https://www.digitalocean.com',
    'https://vercel.com',
    'https://www.netlify.com',
    'https://www.heroku.com',
    'https://www.airtable.com',
    'https://www.gainsight.com',
]

# ── Malware / C2-category domains ─────────────────────────────────────────────
# These URLs are specifically designed to trigger URL-category blocks in
# SASE/NGFW/AV platforms.  testmyids.com and scanme.nmap.org are intentionally
# excluded: they are categorised as "security testing tools", not malware.
# httpbin.org / postman-echo paths are also excluded: the domain is trusted
# and SASE URL-category lookups are domain-based, so the path is irrelevant
# — those belong in c2_beacon_targets for POST-based behavioural testing.
malware_endpoints = [
    # WICAR — safe malware-behaviour test pages designed to trigger AV/NGFW/SASE
    "https://www.wicar.org/test-malware.html",
    "https://www.wicar.org/",
    "https://malware.wicar.org/data/ms14_064_ole_not_xp.html",
    "https://malware.wicar.org/data/java_jre17_exec.html",
    "https://malware.wicar.org/data/eicar.com",

    # AMTSO — Anti-Malware Testing Standards Organisation (cross-vendor standard)
    "https://www.amtso.org/check-desktop-security-tools/",
    "https://www.amtso.org/potentially-unwanted-application-detection/",
    "https://www.amtso.org/phishing-test-page/",

    # Google Safe Browsing test URLs — categorised as malware/phishing/unwanted
    # by every SASE vendor that integrates the GSB API
    "http://malware.testing.google.test/testing/malware/",
    "http://phishing.testing.google.test/testing/phishing/",
    "http://unwanted.testing.google.test/testing/unwanted/",

    # HTTP-evader — tests whether the NGFW/IPS decodes evasion tricks
    # (chunked TE, compressed body, broken headers, multipart, etc.)
    "https://http-evader.semantic-gap.de/chunked",
    "https://http-evader.semantic-gap.de/compressed",
    "https://http-evader.semantic-gap.de/clen",
    "https://http-evader.semantic-gap.de/broken",
    "https://http-evader.semantic-gap.de/mime",
    "https://http-evader.semantic-gap.de/messagerfc822",
    "https://http-evader.semantic-gap.de/range",
    "https://http-evader.semantic-gap.de/-ECABSGAABwMOAAAAAAAAAKpBdDwPL2ZvYi9ub3ZpcnXZDnUwFA==",
    "https://http-evader.semantic-gap.de/-ECABSGAABwMOAAAAAAAAAKpBdDwPanQsb2xsL3NldF_ZVWIrBXN0LWRz",
    "https://http-evader.semantic-gap.de/-ECABSGAABwMOAAAAAAAAAKpBdDwPaWpkIWFsbC9vay7aTmY=",
    "https://http-evader.semantic-gap.de/-ECABSGAABwMOAAAAAAAAAKpBdDwPaHNuYi9hbGwvcGHYRW88P3Nid1FzdWNjZXNzhEh1JQw=",
    "https://noxxi.de/research/http-evader-testsite.html",
    "http://http-evader.semantic-gap.de",
    "https://http-evader.semantic-gap.de",
]

# ── C2 framework / malware family user-agents ─────────────────────────────────
# Default UAs shipped with C2 frameworks and known malware families.
# SASE/SSE, NGFW, and EDR vendors maintain threat-intel signatures for these
# specific strings — they are far more effective at triggering C2 detection
# rules than generic bad-bot / scraper UAs.
#
# Used by: malware_random (HEAD) and c2_beacon (POST)
c2_user_agents = [
    # ── Cobalt Strike beacon defaults ────────────────────────────────────────
    # Stock jQuery malleable-C2 profile (3.x / 4.x) — in every major vendor feed
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    # CS IE11 malleable profile
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    # CS stock pre-profile MSIE Trident UA
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727)",

    # ── Metasploit Meterpreter HTTP/HTTPS reverse handler ────────────────────
    "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",

    # ── PowerShell Empire HTTP stager ────────────────────────────────────────
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",

    # ── Sliver C2 default HTTPS implant ──────────────────────────────────────
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",

    # ── DarkComet RAT — extremely distinctive, present in every vendor feed ──
    "DarkComets/0.1",

    # ── QuasarRAT default HTTP listener ──────────────────────────────────────
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.2 Safari/537.36",

    # ── Emotet / TrickBot family — old IE UA pattern common to both families ─
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2)",

    # ── AgentTesla / OriginLogger exfil HTTP POST ────────────────────────────
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",

    # ── njRAT / Bladabindi minimal UA ────────────────────────────────────────
    "Mozilla/5.0 (compatible)",

    # ── Generic script / implant frameworks ─────────────────────────────────
    # Python requests — extremely common in commodity malware and downloaders
    "python-requests/2.28.2",
    # Go HTTP client — Sliver, Havoc, Mythic, and custom Go implants
    "Go-http-client/1.1",
    # Java — jRAT, Adwind, STRRAT, and many commodity Java RATs
    "Java/11.0.16",
    # curl — dropper and staging scripts
    "curl/7.74.0",
    # PowerShell Invoke-WebRequest default
    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682",
]

# ── CVE HTTP probe signatures ─────────────────────────────────────────────────
# Each entry: (cve_id, display_name, method, path, headers_dict, body_bytes_or_None)
# Probes are fired at safe IDS test hosts only (scanme.nmap.org, testmyids.com).
# No actual exploitation occurs — only the network-layer pattern that triggers
# IPS/IDS signatures is sent. Connection is refused/reset by the target server.
cve_http_probes = [
    # ── Remote Code Execution via HTTP headers ────────────────────────────────
    ("CVE-2021-44228", "Log4Shell (JNDI header)",
     "GET", "/",
     {"X-Api-Version": "${jndi:ldap://127.0.0.1:1389/traffgen}",
      "X-Forwarded-For": "${jndi:ldap://127.0.0.1:1389/traffgen}",
      "User-Agent": "${jndi:ldap://127.0.0.1:1389/traffgen}"},
     None),

    ("CVE-2021-45046", "Log4Shell variant (JNDI thread ctx)",
     "GET", "/",
     {"X-Api-Version": "${${lower:j}ndi:${lower:l}dap://127.0.0.1:1389/traffgen}"},
     None),

    ("CVE-2014-6271", "Shellshock (bash function in headers)",
     "GET", "/cgi-bin/test.cgi",
     {"User-Agent": "() { :;}; echo Content-Type: text/plain; echo; id",
      "Cookie": "() { :;}; /bin/bash -c 'id'",
      "Referer": "() { :;}; echo; /bin/bash -c id"},
     None),

    ("CVE-2017-5638", "Struts2 RCE (Content-Type OGNL injection)",
     "POST", "/index.action",
     {"Content-Type":
      "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
      "(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))."
      "(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
      "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
      "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.start())}"},
     None),

    ("CVE-2022-22965", "Spring4Shell (class.module.classLoader)",
     "POST", "/",
     {"Content-Type": "application/x-www-form-urlencoded",
      "suffix": "%>//", "c1": "Runtime", "c2": "<%", "DNT": "1"},
     b"class.module.classLoader.resources.context.parent.pipeline.first.pattern="
     b"%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))"
     b"%7B+java.io.InputStream+in+%3D+%25%7Bc1%7Di.getRuntime().exec"
     b"(request.getParameter(%22cmd%22)).getInputStream()%3B%7D"),

    ("CVE-2022-26134", "Confluence OGNL RCE (URL-encoded OGNL in path)",
     "GET",
     "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28"
     "%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29"
     ".getInputStream%28%29%2C%22utf-8%22%29%29."
     "%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29"
     ".setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
     {}, None),

    ("CVE-2023-46604", "Apache ActiveMQ RCE (ClassInfo header probe)",
     "GET", "/api/jolokia/exec/org.apache.activemq:type=Broker/addConnector/tcp://127.0.0.1:61616",
     {"User-Agent": "traffgen-cve-probe/CVE-2023-46604"}, None),

    # ── Path traversal / LFI CVEs ─────────────────────────────────────────────
    ("CVE-2021-41773", "Apache 2.4.49 Path Traversal",
     "GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", {}, None),

    ("CVE-2021-42013", "Apache 2.4.50 Path Traversal (bypass)",
     "GET", "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd", {}, None),

    ("CVE-2019-11510", "Pulse Secure VPN LFI",
     "GET",
     "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd"
     "?/dana/html5acc/guacamole/",
     {}, None),

    ("CVE-2020-5902", "F5 BIG-IP TMUI LFI",
     "GET",
     "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
     {}, None),

    ("CVE-2018-13379", "Fortinet FortiOS SSL-VPN LFI",
     "GET",
     "/remote/fgt_lang?lang=/////../../../..//////////dev/cmdb/sslvpn_websession",
     {}, None),

    ("CVE-2019-0604", "SharePoint RCE (SOAP action probe)",
     "POST", "/_vti_bin/client.svc/ProcessQuery",
     {"Content-Type": "text/xml",
      "SOAPAction": "\"http://schemas.microsoft.com/sharepoint/soap/ExecuteQuery\""},
     b'<Request xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">'
     b'<Actions><ObjectPath Id="1" ObjectPathId="0"/></Actions><ObjectPaths>'
     b'<StaticProperty Id="0" TypeId="{3747adcd-a3c3-41b9-bfab-4a64dd2f1e0a}" Name="Current"/>'
     b'</ObjectPaths></Request>'),

    ("CVE-2022-1388", "F5 BIG-IP iControl REST auth bypass",
     "POST", "/mgmt/tm/util/bash",
     {"Content-Type": "application/json",
      # IPS probe pattern — not a real credential; value is "traffgen-test" base64-encoded
      "Authorization": "Basic dHJhZmZnZW4tdGVzdA==",
      "X-F5-Auth-Token": "",
      "Connection": "keep-alive, X-F5-Auth-Token"},
     b'{"command":"run","utilCmdArgs":"-c id"}'),

    ("CVE-2023-20198", "Cisco IOS XE Web UI privilege escalation",
     "POST", "/webui/logoutconfirm.html?logon_hash=1",
     {"Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": "traffgen-cve-probe/CVE-2023-20198"}, None),

    # ── XML / injection attacks ───────────────────────────────────────────────
    ("CVE-generic-XXE", "XXE injection (external entity)",
     "POST", "/api/xml",
     {"Content-Type": "application/xml"},
     b'<?xml version="1.0"?><!DOCTYPE root ['
     b'<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     b'<root><data>&xxe;</data></root>'),

    ("CVE-generic-SSTI", "Server-Side Template Injection (Jinja2/Twig/Freemarker)",
     "GET", "/?name={{7*7}}&q=${7*7}&p=<#assign%20ex%3D\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
     {}, None),

    # ── File-based exploit byte-pattern probes ────────────────────────────────
    ("CVE-2017-11882", "Office Equation Editor RCE (RTF/OLE pattern)",
     "POST", "/upload",
     {"Content-Type": "application/rtf"},
     # RTF magic + EQNEDT32.EXE reference — pattern matched by IPS signatures
     b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Times New Roman;}}"
     b"{\\*\\generator traffgen-cve-test;}"
     b"\\pard EQNEDT32.EXE\\par}"),

    ("CVE-2017-0199", "Office HTA remote template (RTF objautlink)",
     "POST", "/upload",
     {"Content-Type": "application/rtf"},
     b"{\\rtf1\\ansi{\\object\\objautlink\\objupdate{\\*\\objclass Word.Document.8}"
     b"{\\objdata 0105000002000000}}}"),

    ("CVE-2012-0158", "MSCOMCTL.OCX RCE (RTF OLE control)",
     "POST", "/upload",
     {"Content-Type": "application/rtf"},
     b"{\\rtf1\\ansi{\\object\\objocx{\\*\\objclass MSComctlLib.ListViewCtrl.2}"
     b"{\\objdata 010500000200000001050000}}}"),

    # ── Scanner / recon UA probes ─────────────────────────────────────────────
    ("CVE-scan-nikto", "Nikto web scanner UA",
     "GET", "/", {"User-Agent": "Nikto/2.1.6"}, None),

    ("CVE-scan-sqlmap", "sqlmap injection scanner UA",
     "GET", "/?id=1'%20OR%201=1--",
     {"User-Agent": "sqlmap/1.7.8#stable (https://sqlmap.org)"}, None),

    ("CVE-scan-nessus", "Nessus vulnerability scanner UA",
     "GET", "/", {"User-Agent": "Mozilla/5.0 (Nessus/10.0)"}, None),

    ("CVE-scan-openvas", "OpenVAS scanner UA",
     "GET", "/", {"User-Agent": "Mozilla/5.0 (compatible; OpenVAS)"}, None),

    ("CVE-scan-nuclei", "Nuclei vulnerability scanner UA",
     "GET", "/", {"User-Agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"}, None),

    ("CVE-scan-zgrab", "ZGrab mass scanner",
     "GET", "/", {"User-Agent": "zgrab/0.x"}, None),

    # ── Webshell access patterns ──────────────────────────────────────────────
    ("CVE-generic-shell", "PHP webshell cmd execution pattern",
     "GET", "/shell.php?cmd=id&passwd=traffgen", {}, None),

    ("CVE-generic-shell", "China Chopper webshell POST pattern",
     "POST", "/index.php",
     {"Content-Type": "application/x-www-form-urlencoded"},
     b"z0=traffgen-test&z1=QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIp"),

    # ── Protocol-specific exploit byte patterns ───────────────────────────────
    ("CVE-2017-0144", "EternalBlue/WannaCry SMB pattern (HTTP delivery probe)",
     "POST", "/",
     {"Content-Type": "application/octet-stream",
      "User-Agent": "traffgen-cve-probe/CVE-2017-0144"},
     b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"),

    ("CVE-2021-26855", "ProxyLogon SSRF (Exchange OWA cookie)",
     "GET", "/owa/auth/x.js",
     {"Cookie": "X-AnonResource=true; path=/logon/LogonPoint; "
                "X-AnonResource-Backend=localhost/ecp/default.flt?~3; "
                "X-BEResource=localhost/owa/auth/logon.aspx~3"},
     None),

    ("CVE-2020-1472", "Zerologon NetLogon probe (HTTP pattern)",
     "GET", "/?CVE-2020-1472-zerologon-probe=1",
     {"User-Agent": "traffgen-cve-probe/CVE-2020-1472-Zerologon"}, None),
]

# Safe IDS/IPS test targets for CVE probes — purpose-built for security testing.
# Connections are refused/reset; payloads never land on disk at these hosts.
cve_probe_targets = [
    "scanme.nmap.org",
    "testmyids.com",
]

# ── IPS user-agent signatures ─────────────────────────────────────────────────
# Malicious / suspicious UA strings drawn from Emerging Threats open rules,
# mitchellkrogza/nginx-ultimate-bad-bot-blocker, mthcht/awesome-lists, and
# public malware-analysis reports.  Used by the ips-ua suite to verify that
# IDS/IPS / SASE platforms detect malicious HTTP user-agent indicators.
# All probes are sent only to ips_ua_targets (purpose-built IDS/IPS test hosts).
ips_ua_targets = [
    "testmyids.com",
    "scanme.nmap.org",
]

ips_ua_signatures = [
    # ── C2 frameworks: Cobalt Strike default / observed malleable profiles ─────
    "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)",
    "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2) Java/1.5.0_08",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/5.0)",

    # ── C2 frameworks: Metasploit / Meterpreter ───────────────────────────────
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",

    # ── C2 frameworks: Empire / PowerShell Empire ─────────────────────────────
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",

    # ── C2 frameworks: Sliver, Havoc, misc open-source C2 ────────────────────
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36",
    "Tsunami C2",
    "specula C2",

    # ── RATs & Trojans (Emerging Threats confirmed signatures) ─────────────────
    "WHCC/",
    "BlackSun",
    "VERTEXNET",
    "VMozilla",
    "Mozzila",
    "Moxilla",
    "Mozil1a",
    "M0zilla/",
    "Mozilla/3.0",
    "Mozilla/1.0 (compatible; MSIE 8.0",
    "Mozilla/4.7 [en] (WinNT",
    "Mozilla 6.0",
    "SimpleClient 1.0",
    "BGroom",
    "tiny",
    "zeroup",
    "iamx/",
    "DownloadMR",
    "Forthgoner",
    "Loands",
    "AutoDL/1.0",
    "Snatch-System",
    "RLMultySocket",
    "onedru/",
    "ekeoil/",
    "google/dance",
    "Gemini/2.0",
    "Hakai/2.0",
    "curl53",
    "libsfml-network/",
    "MyIE",
    "Cyberdog",
    "Revolution Win32",
    "LockXLS",
    "REKOM",
    "HTTPGET",
    "HTTPTEST",
    "Matcash",
    "netcfg",
    "lsosss",
    "adlib/",
    "sgrunt",
    "Godzilla",
    "2search",
    "Poller",
    "Viper 4.0",
    "DriveCleaner Updater",
    "WinFix Master",
    "SAIv",
    "Gator",
    "IST",
    "changhuatong",
    "CholTBAgent",
    "AskPartner",
    "Tear Application",
    "MFC_Tear_Sample",
    "Ufasoft",
    "MtGoxBackOffice",
    "AutoHotkey",
    "ChilkatUpload",
    "FOCA",
    "aguarovex-loader",
    "Kvadrlson",
    "xpymep1.exe",
    "check1.exe",
    "winlogon",
    "svchost",
    "AVP200",
    "IEMGR",
    "ISMYIE",
    "IEhook",
    "ms_ie",
    "ieagent",
    "ieguideupdate",
    "msIE",
    "msdown",
    "msndown",
    "up2dash",
    "PcPcUpdater",
    "PrivacyInfoUpdate",
    "Windows Updates Manager",
    "antispyprogram",
    "MacShield",
    "SUiCiDE",
    "FULLSTUFF",
    "HardCore Software For",
    "SideStep",
    "CFS Agent",
    "CFS_DOWNLOAD",
    "AdiseExplorer",
    "HttpDownload",
    "HTTP Downloader",
    "Download App",
    "GetUrlSize",
    "ReadFileURL",
    "WINS_HTTP_SEND",
    "Inet_read",
    "MYURL",
    "Binget/",
    "pxyscand/",
    "InfoBot",
    "RBR",
    "KKTone",
    "doshowmeanad",
    "Si25",
    "MadeBy",
    "ErrCode",
    "Yandesk",
    "Kwyjibo",
    "InHold",
    "Downing",
    "Poker",
    "sections",
    "adsntD",
    "VCTestClient",
    "SomeTimes",
    "zwt",
    "NSIS_Inetc",
    "NSISDL",
    "Clever Internet Suite",
    "Quick Macros",
    "pivotnacci/",

    # ── Modern malware families (2020–2025 infostealers / loaders) ─────────────
    "BunnyTasks",
    "BunnyLoader",
    "Lokibot",
    "DarkCloud",
    "Arkei Stealer",
    "arkei/",
    "Matanbuchus 3.0",
    "rc2.0/client",
    "SSLoad/",
    "raccoon stealer",
    "CanisRufus",
    "Chnome",
    "DuckTales",
    "GameInfo",
    "GeekingToTheMoon",
    "GunnaWunna",
    "Lemon-Duck-",
    "Lilith-Bot",
    "MoonLight",
    "DecoyLoader",
    "Project1sqlite",
    "*(Charon; Inferno)",

    # ── Vulnerability scanners & pentest tools ────────────────────────────────
    "sqlmap/1.0-dev",
    "sqlmap/1.3.11#stable (http://sqlmap.org)",
    "sqlmap/1.7",
    "Sqlmap",
    "Sqlworm",
    "Sqworm",
    "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)",
    "Mozilla/5.00 (Nikto/@VERSION) (Evasions:@EVASIONS) (Test:@TESTID)",
    "Nikto",
    "Nessus",
    "OpenVAS",
    "Openvas",
    "Nuclei",
    "WPScan",
    "Wprecon",
    "Jorgee",
    "Jbrofuzz",
    "w3af.org",
    "w3af.sf.net",
    "arachni/",
    "Arachni/",
    "Acunetix",
    "Dirbuster",
    "dirbuster",
    "Fimap",
    "fimap",
    "Havij",
    "Webshag",
    "webshag",
    "Whatweb",
    "whatweb",
    "Masscan",
    "masscan",
    "Nmap",
    "nmap nse",
    "nmap scripting engine",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Hydra",
    "hydra",
    "Brutus",
    "brutus",
    "Commix",
    "commix",
    "DotDotPwn",
    "dotdotpwn",
    "Paros",
    "paros",
    "Vega",
    "vega",
    "WebInspect",
    "webinspect",
    "Shodan",
    "CensysInspect",
    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
    "zgrab",
    "ZmEu",
    "Morfeus Fucking Scanner",
    "Libwhisker",
    "libwhisker",
    "ScrapeBox",
    "Xenu",
    "muhstik-scan",
    "sysscan",
    "l9scan",
    "leakix",
    "scan.lol",

    # ── Credential attack & spraying tools ────────────────────────────────────
    "Rubeus/1.0",
    "KrbRelayUp/1.0",
    "ShadowSpray.Kerb/1.0",
    "Cr3dOv3r-Framework",
    "BAV2ROPC",
    "TruffleHog",
    "stratus-red-team",
    "AADInternals",
    "ROADtools",
    "Evilginx",
    "TokenFlare/",
    "RaccoonO365",
    "DeviceCodePhishing",
    "SharePointDumper",
    "Certipy",

    # ── Known bad bots & aggressive scrapers ──────────────────────────────────
    "BackDoorBot",
    "Black Hole",
    "BlackWidow",
    "DataCha0s",
    "Demon",
    "Devil",
    "EasyDL",
    "EmailSiphon",
    "EMail Siphon",
    "EMail Wolf",
    "Evil",
    "FlashGet",
    "GetRight",
    "GetWeb",
    "GrabNet",
    "Grabber",
    "Grafula",
    "HTTrack",
    "Harvest",
    "Heritrix",
    "Humanlinks",
    "InterGET",
    "Larbin",
    "LeechFTP",
    "LeechGet",
    "LexiBot",
    "Mass Downloader",
    "Mata Hari",
    "MIDown tool",
    "Net Vampire",
    "NetAnts",
    "Octopus",
    "Offline Explorer",
    "Offline Navigator",
    "PageGrabber",
    "Pavuk",
    "RealDownload",
    "Reaper",
    "ReGet",
    "Ripper",
    "SiteSnagger",
    "SiteSucker",
    "SmartDownload",
    "Snake",
    "Stripper",
    "Sucker",
    "SuperBot",
    "SuperHTTP",
    "Teleport",
    "TeleportPro",
    "TheNomad",
    "Titan",
    "Toata",
    "VoidEYE",
    "WebBandit",
    "WebCollage",
    "WebCopier",
    "WebFuck",
    "WebReaper",
    "WebSauger",
    "WebStripper",
    "WebSucker",
    "WebWhacker",
    "WebZIP",
    "Whack",
    "WinHTTrack",
    "Widow",
    "WWW::Mechanize",
    "WWW-Mechanize",
    "WWWOFFLE",
    "Xaldon WebSpider",
    "Zeus",

    # ── Automated HTTP libraries commonly flagged by IDS ──────────────────────
    "PyCurl",
    "Python-urllib/",
    "Python/",
    "Go-http-client/1.1",
    "Go-http-client/2.0",
    "lwp-request",
    "lwp-trivial",
    "LWP::Simple",
    "libwww-perl/",
    "HTTP::Lite",
    "PECL::HTTP",
    "POE-Component-Client-HTTP",
    "PHPCrawl",
    "Scrapy",
    "Typhoeus",
    "aiohttp/",
    "axios/",
    "reqwest/",
    "undici",
    "Lomond/",
    "scalaj-http",
    "Mojolicious",

    # ── Lateral movement & RMM abuse ─────────────────────────────────────────
    "Microsoft WinRM Client",
    "NetSupport Manager/",
    "NetSupport Gateway/",
    "AnyDesk/",
    "MeshCentral",
    "LogMeIn/",
    "splashtop",

    # ── PowerShell / Windows scripting (suspicious in HTTP context) ───────────
    "WindowsPowerShell/",
    "Microsoft-CryptoAPI/",
    "Microsoft-WebDAV-MiniRedir/",
    "Microsoft BITS/",
    "Dsreg/10.0",

    # ── Cryptominer / botnet UAs ──────────────────────────────────────────────
    "Lemon-Duck-A-T",
    "Lemon-Duck-B-T",
    "xmrig/",
    "Xmrig",
    "stratum+tcp",

    # ── Exploit kits & drive-by download indicators ───────────────────────────
    "AIBOT",
    "Anarchy",
    "Anarchy99",
    "BetaBot",
    "Downloader",
    "ECCP/1.0",
    "ips-agent",
    "x09Mozilla",
    "x22Mozilla",

    # ── Phishing / AiTM frameworks ────────────────────────────────────────────
    "Evilginx2",
    "Modlishka",
    "ngrok",

    # ── Headless browsers (credential stuffing / scraping) ────────────────────
    "HeadlessChrome",
    "HeadlessEdge",
    "PhantomJS",
    "SlimerJS",

    # ── Miscellaneous trivially-detectable suspicious UAs (ET rules) ──────────
    "WORKED",
    "Our_Agent",
    "TestAgent",
    "YourUserAgent",
    "Hello, World",
    "Hello-World",
    "Ave, Caesar!",
    "attacker",
    "hacker",
    "NULL",
    "agent",
    "asd",
    "mdms",
    "xr",
    "z",
    "-",
    "My_App",
    "My Agent",
    "MyAgent",
    "SERVER",
    "WinProxy",
    "WinXP Pro Service Pack",
    "WebForm",
    "sickness",
    "GOOGLE",
    "Internet HTTP",
    "MS Internet Explorer",
    "Microsoft Internet Explorer",
    "INSTALLER",
    "Mozilla-web",
    "B1D3N_RIM_MY_ASS",
    "AYAYAYAY1337",
    "YAYAYAY",
    "Windows NT 123.9",
    "Intrenet Explorer",
    "Windows Explorer",
    "Opera/8.11",
]

# ── Bad-bot / scraper user-agents ─────────────────────────────────────────────
# Large list of web scrapers, SEO crawlers, and aggressive bots.
# Useful for testing WAF bot-detection rules and rate-limiting policies.
# For C2 / SASE threat-detection testing use c2_user_agents above instead.

# ── AI service HTTPS endpoints ────────────────────────────────────────────────
ai_endpoints = [
    'https://chat.openai.com',
    'https://www.whyzehealth.com',
    'https://www.yedahealth.com',
    'https://www.brightlight.health',
    'https://www.aihack.us',
    'https://www.kodu.ai',
    'https://bard.google.com',
    'https://claude.ai',
    'https://perplexity.ai',
    'https://character.ai',
    'https://ai.google/health',
    'https://tripplanner.ai',
    'https://cursor.com',
    'https://heidihealth.com',
    'https://zzzcode.ai',
    'https://myninja.ai',
    'https://copilot.microsoft.com',
    'https://github.com/github-copilot',
    'https://mindtrip.ai',
    'https://www.notion.so/ai',
    'https://github.com/features/copilot',
    'https://www.copy.ai',
    'https://www.jasper.ai',
    'https://www.runwayml.com',
    'https://www.midjourney.com',
    'https://www.canva.com/ai-image-generator',
    'https://leonardo.ai',
    'https://ideogram.ai',
    'https://www.descript.com',
    'https://pika.art',
    'https://www.d-id.com',
    'https://www.synthesia.io',
    'https://krisp.ai',
    'https://www.tome.app',
    'https://www.nvidia.com/en-us/research/ai',
    'https://deepmind.google',
    'https://huggingface.co',
    'https://replicate.com',
    'https://www.stability.ai',
    'https://openai.com',
    'https://www.anthropic.com',
    'https://www.mistral.ai',
    'https://www.meta.ai',
    'https://www.adobe.com/sensei.html',
    'https://fireflies.ai',
    'https://otter.ai',
    'https://spiny.ai',
    'https://voicemod.net',
    'https://speechify.com',
    'https://www.respeecher.com',
    'https://www.resemble.ai',
    'https://www.elevenlabs.io',
    'https://play.ht',
    'https://www.suno.ai',
    'https://www.boost.ai',
    'https://www.you.com',
    'https://www.writesonic.com',
    'https://www.inkforall.com',
    'https://simplified.com',
    'https://www.peppertype.ai',
    'https://rytr.me',
    'https://www.copylime.com',
    'https://www.hyperwriteai.com',
    'https://wordtune.com',
    'https://quillbot.com',
    'https://deepl.com/translator',
    'https://www.grammarly.com',
    'https://notion.so',
    'https://aixploria.com',
    'https://topai.tools',
    'https://futurepedia.io',
    'https://thereisaan.ai',
    'https://www.futuretools.io',
    'https://toolsaday.com',
    'https://toolify.ai',
    'https://tooldirectory.ai',
    'https://www.insidr.ai',
    'https://www.flowgpt.com',
    'https://www.phind.com',
    'https://www.vizcom.ai',
    'https://scribblediffusion.com',
    'https://autodraw.com',
    'https://hotpot.ai',
    'https://clipdrop.co',
    'https://magicstudio.com',
    'https://www.imgcreator.ai',
    'https://www.artbreeder.com',
    'https://paint.ai',
    'https://getimg.ai',
    'https://www.thispersondoesnotexist.com',
    'https://www.surfboard.ai',
    'https://podcastle.ai',
    'https://www.riverside.fm',
    'https://cleanvoice.ai',
    'https://audiolabz.com',
    'https://www.lalal.ai',
    'https://www.beautiful.ai',
    'https://gamma.app',
    'https://www.decktopus.com',
    'https://slidesgo.com/ai',
    'https://chatpdf.com',
    'https://humata.ai',
    'https://askyourpdf.com',
    'https://www.docsbot.ai',
    'https://www.tldv.io',
    'https://synthesys.io',
    'https://www.murf.ai',
    'https://replika.ai',
    'https://pi.ai',
    'https://www.warmspace.io',
    'https://www.mindstudio.com',
    'https://www.kaiber.ai',
    'https://runwayml.com',
    'https://www.storywizard.ai',
    'https://voicemaker.in',
    'https://motionit.ai',
    'https://deepai.org',
    'https://machinelearningmastery.com',
    'https://mubert.com',
    'https://soundful.com',
    'https://aiva.ai',
    'https://moises.ai',
    'https://audo.ai',
    'https://uberduck.ai',
    'https://revoicer.com',
    'https://www.jammable.com',
    'https://fliki.ai',
    'https://labs.openai.com',
    'https://bing.com/create',
    'https://canva.com',
    'https://midjourney.com',
    'https://designs.ai',
    'https://logomaker.com',
    'https://looka.com',
    'https://framer.com',
    'https://visily.ai',
    'https://studio.design',
    'https://uizard.io',
    'https://fathom.video',
    'https://cogram.com',
    'https://reclaim.ai',
    'https://govdash.com',
    'https://smartwriter.ai',
    'https://descript.com',
    'https://visla.us',
    'https://deepmotion.com',
    'https://cascadeur.com',
    'https://heygen.com',
    'https://pictory.ai',
    'https://fitbod.me',
    'https://woebot.io',
    'https://copy.ai',
    'https://jasper.ai',
    'https://adcopy.ai',
    'https://adcreative.ai',
    'https://codesquire.ai',
    'https://tabnine.com',
    'https://koalawriter.com',
    'https://tidio.com',
    'https://digitalgenius.com',
    'https://paperswithcode.com',
]

# ── Legitimate browser user-agent strings (~500 entries, 2024-2025 devices) ───
user_agents = [
    # Windows Chrome 120-136
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.106 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.142 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.92 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.84 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.141 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.178 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.96 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.48 Safari/537.36',
    # Windows Firefox 120-137
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
    # Windows Edge Chromium 120-136
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
    # macOS Chrome (Sonoma 14.x, Sequoia 15.x)
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Safari/537.36',
    # macOS Safari 17.x and 18.x
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/604.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/604.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/604.1',
    # macOS Firefox
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.0; rv:130.0) Gecko/20100101 Firefox/130.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.1; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.2; rv:134.0) Gecko/20100101 Firefox/134.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.3; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.4; rv:137.0) Gecko/20100101 Firefox/137.0',
    # iPhone Safari iOS 17.x
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6.1 Mobile/15E148 Safari/604.1',
    # iPhone Safari iOS 18.x
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
    # iPhone Chrome (CriOS)
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/122.0.6261.89 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.88 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.6613.92 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/132.0.6834.79 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/134.0.6998.119 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/136.0.7103.56 Mobile/15E148 Safari/604.1',
    # iPhone Firefox (FxiOS)
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/124.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/128.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/130.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/134.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/137.0 Mobile/15E148 Safari/605.1.15',
    # iPad Safari (iPadOS 17/18)
    'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
    # Android Samsung Galaxy Chrome (S23/S24/S25, Android 13/14/15)
    'Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S916B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S931B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S936B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.146 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A356B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-A566B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-F956B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-F966B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.111 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-N986B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Mobile Safari/537.36',
    # Samsung Internet 24.x-26.x
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/125.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S936B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/125.0.0.0 Mobile Safari/537.36',
    # Android Pixel Chrome (Pixel 8/9, Android 14/15)
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro Fold) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.56 Mobile Safari/537.36',
    # Android other brands (OnePlus, Xiaomi, OPPO, vivo, Motorola)
    'Mozilla/5.0 (Linux; Android 14; CPH2447) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; CPH2451) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23049PCD8G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 2312DRAABL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; PHX110) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; V2309A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; motorola edge 50 pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; motorola edge 40 pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; 24117RK66G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; RMX3890) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; 22111317I) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 24031PN0DC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    # Android Firefox
    'Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:136.0) Gecko/136.0 Firefox/136.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:137.0) Gecko/137.0 Firefox/137.0',
    # Linux Chrome
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    # Linux Firefox
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0',
    # ChromeOS
    'Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.212 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15786.41.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.215 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15917.71.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 16002.67.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 16167.29.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.53 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS aarch64 16167.29.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.53 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 16299.60.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.108 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 16413.30.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.117 Safari/537.36',
    # Smart TVs
    'Mozilla/5.0 (SMART-TV; Linux; Tizen 8.0) AppleWebKit/538.1 (KHTML, like Gecko) Version/8.0 TV Safari/538.1',
    'Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/538.1 (KHTML, like Gecko) Version/7.0 TV Safari/538.1',
    'Mozilla/5.0 (SMART-TV; Linux; Tizen 6.5) AppleWebKit/538.1 (KHTML, like Gecko) Version/6.5 TV Safari/538.1',
    'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36 DMOST/2.0.0 (; LGE; webOSTV; WEBOS24H; W24H;)',
    'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Safari/537.36 DMOST/2.0.0 (; LGE; webOSTV; WEBOS23H; W23H;)',
    'Mozilla/5.0 (Linux; Android 11; BRAVIA XR-65A80J Build/RQ3A.210805.001.A1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; BRAVIA 4K GB Build/SKQ1.211019.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.125 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; OLED65C2PSA Build/RQ3A.210805.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36',
    # Gaming consoles
    'Mozilla/5.0 (PlayStation; PlayStation 5/9.60) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15',
    'Mozilla/5.0 (PlayStation; PlayStation 5/8.52) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edge/44.18363.8131.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series S) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edge/44.18363.8131.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
    # Meta Quest / Apple TV
    'Mozilla/5.0 (Linux; Android 10; Quest 2) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/29.0.0.3 SamsungBrowser/4.3 Chrome/120.0.6099.43 VR Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Quest 3) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/31.0.0.3 SamsungBrowser/4.3 Chrome/126.0.6478.72 VR Safari/537.36',
    'Mozilla/5.0 (AppleTV; CPU AppleTV14,1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (AppleTV; CPU AppleTV14,1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    # Additional Windows Chrome with patch versions
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.57 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.55 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.72 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.84 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.58 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.116 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.160 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.53 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.45 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.42 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Safari/537.36',
    # Additional macOS Chrome
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.57 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.72 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.53 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.42 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Safari/537.36',
    # macOS Edge
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0',
    # Additional iPad Chrome
    'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/124.0.6367.88 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/134.0.6998.119 Mobile/15E148 Safari/604.1',
    # Android tablets
    'Mozilla/5.0 (Linux; Android 13; SM-X900) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X910) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X916B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-T733) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-T870) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Lenovo TB350FU) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; 22081283G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 2023106) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; T21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Safari/537.36',
    # Additional Android phone brands
    'Mozilla/5.0 (Linux; Android 14; CPH2557) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 2407FPN8EG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; 25040ADAEG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.111 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; V2351A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; motorola edge 50 ultra) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; motorola razr 50 ultra) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; ASUS_AI2401_D) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23127PN0CC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    # Additional iPhone models with specific hardware IDs
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/21A329 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Mobile/21C66 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/21E236 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5.1 Mobile/21F90 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/22A3354 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/22B91 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/22C150 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.2 Mobile/22D82 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/22E240 Safari/604.1',
    # Additional iPad models with build IDs
    'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/21A329 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/21E236 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/22A3354 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/22C150 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/22E240 Safari/604.1',
    # Additional Samsung Internet
    'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S931B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/125.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-F956B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X916B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Safari/537.36',
    # Additional Android Samsung Galaxy variants
    'Mozilla/5.0 (Linux; Android 13; SM-A736B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A256B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A336B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S906B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    # Additional Android Pixel
    'Mozilla/5.0 (Linux; Android 14; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 6a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    # More Linux Chrome variants
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    # More Linux Firefox
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
    # More macOS Safari patch versions
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2.1 Safari/605.1.15',
    # More Windows Edge with specific builds
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36 Edg/120.0.2210.91',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36 Edg/122.0.2365.66',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36 Edg/124.0.2478.67',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36 Edg/126.0.2592.87',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Safari/537.36 Edg/128.0.2739.79',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.92 Safari/537.36 Edg/130.0.2849.68',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.84 Safari/537.36 Edg/132.0.2957.140',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.178 Safari/537.36 Edg/134.0.3124.85',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.48 Safari/537.36 Edg/136.0.3240.50',
    # Android Chrome on additional devices
    'Mozilla/5.0 (Linux; Android 14; SM-S918U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S911U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S931U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 22041219NY) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 24069PC20G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; RMX3760) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23106RN0DA) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; CPH2387) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; CPH2615) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    # WebView user agents (apps with embedded browsers)
    'Mozilla/5.0 (Linux; Android 14; SM-S928B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Build/AP3A.241205.013; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22C150',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21F90',
    # Windows Firefox ESR and additional patch builds
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.0; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    # Brave browser (Chromium-based)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.58 Safari/537.36',
    # Opera GX and Opera
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/113.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/114.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36 OPR/79.0.0.0',
    # Vivaldi
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.191 Safari/537.36 Vivaldi/7.0.3495.27',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.191 Safari/537.36 Vivaldi/7.0.3495.27',
    # Additional smart TV
    'Mozilla/5.0 (SMART-TV; Linux; Tizen 5.5) AppleWebKit/538.1 (KHTML, like Gecko) Version/5.5 TV Safari/538.1',
    'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.128 Safari/537.36 DMOST/1.0.0 (; LGE; webOSTV; WEBOS22; W22;)',
    'Mozilla/5.0 (Linux; Android 10; AFT_MNDVD Build/PS7408) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Safari/537.36',
    # Additional iOS Chrome variants
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.89 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.103 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.84 Mobile/15E148 Safari/604.1',
    # More Windows Chrome (complete version spread)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.57 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.201 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.76 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.182 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.89 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.58 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.204 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.111 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.98 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.114 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.116 Safari/537.36',
    # macOS Chrome additional patch builds
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.76 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.89 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.204 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.98 Safari/537.36',
    # More Windows Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
    # More Android Firefox
    'Mozilla/5.0 (Android 13; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0',
    # iPhone Safari additional minor versions
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0.2 Mobile/21A350 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.1 Mobile/21B91 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/21D50 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/21E219 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Mobile/22A3370 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/22B83 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2.1 Mobile/22C161 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/22D60 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Mobile/22D72 Safari/604.1',
    # iPad additional minor versions
    'Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.1 Mobile/21B91 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/21D50 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6.1 Mobile/21G93 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/22B91 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/22D60 Safari/604.1',
    # Samsung Galaxy A-series additional models
    'Mozilla/5.0 (Linux; Android 14; SM-A145R) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A226B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A426B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-A566B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-M546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    # More OnePlus/Xiaomi/OPPO/vivo
    'Mozilla/5.0 (Linux; Android 14; LE2125) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; CPH2609) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.56 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 2306EPN60G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; V2354A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Xiaomi 13 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Xiaomi 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Xiaomi 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; OPPO Find X7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; OPPO Find X8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; vivo X100 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    # Android Go / budget devices
    'Mozilla/5.0 (Linux; Android 12; SM-A035G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Redmi Note 13 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Redmi Note 14 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; POCO X6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; POCO F6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    # UCBrowser and other alt browsers
    'Mozilla/5.0 (Linux; U; Android 14; en-US; SM-S928B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 UCBrowser/15.0.0.1621 Mobile Safari/537.36',
    # Windows ARM
    'Mozilla/5.0 (Windows NT 10.0; ARM; Win64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; ARM; Win64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    # Meta Quest Pro / Mixed Reality headsets
    'Mozilla/5.0 (Linux; Android 12; Quest Pro) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/30.0.0.3 SamsungBrowser/4.3 Chrome/123.0.6312.80 VR Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Quest 3S) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/32.0.0.3 SamsungBrowser/4.3 Chrome/129.0.6668.58 VR Safari/537.36',
    # Additional iOS Firefox
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/136.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/128.0 Mobile/15E148 Safari/605.1.15',
    # macOS Firefox additional versions
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.1; rv:131.0) Gecko/20100101 Firefox/131.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.3; rv:135.0) Gecko/20100101 Firefox/135.0',
    # Additional ChromeOS
    'Mozilla/5.0 (X11; CrOS armv7l 15917.71.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15433.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.117 Safari/537.36',
    # More Android Samsung Galaxy S-series
    'Mozilla/5.0 (Linux; Android 14; SM-S921U1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S938U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.111 Mobile Safari/537.36',
    # More Pixel variants
    'Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro Fold) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.56 Mobile Safari/537.36',
    # More Linux Firefox
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0',
    # More Android tablets
    'Mozilla/5.0 (Linux; Android 14; SM-X210) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X610) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; 21081111RG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Redmi Pad Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; OPPO Pad 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Safari/537.36',
    # Huawei (no GMS) browser
    'Mozilla/5.0 (Linux; Android 10; ELS-NX9 Build/HUAWEIELS-NX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 HuaweiBrowser/12.0.4.301 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; TAS-AN00 Build/HUAWEITAS-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/13.0.5.305 Mobile Safari/537.36',
    # Windows Chrome on older Win10 (still NT 10.0)
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.126 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.52 Safari/537.36',
    # ── 2021-2023 era (Chrome 96-119) ─────────────────────────────────────────
    # Windows Chrome 96-119
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.127 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.119 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.111 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.187 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.149 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36',
    # Windows 11 Chrome (same NT 10.0 but distinct build numbers)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Windows Firefox 100-119
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:113.0) Gecko/20100101 Firefox/113.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
    # Windows Firefox 138-140
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0',
    # Windows Edge 96-119
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36 Edg/97.0.1072.62',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36 Edg/98.0.1108.56',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36 Edg/99.0.1150.55',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/100.0.1185.44',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36 Edg/102.0.1245.39',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36 Edg/103.0.1264.37',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.54',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.54 Safari/537.36 Edg/105.0.1343.33',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.61 Safari/537.36 Edg/106.0.1370.37',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.62 Safari/537.36 Edg/107.0.1418.35',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.71 Safari/537.36 Edg/108.0.1462.46',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36 Edg/109.0.1518.52',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36 Edg/110.0.1587.50',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36 Edg/111.0.1661.44',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36 Edg/112.0.1722.39',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.63 Safari/537.36 Edg/113.0.1774.35',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36 Edg/114.0.1823.43',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.102 Safari/537.36 Edg/115.0.1901.188',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 Edg/116.0.1938.54',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36 Edg/117.0.2045.43',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.58 Safari/537.36 Edg/118.0.2088.46',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.105 Safari/537.36 Edg/119.0.2151.58',
    # macOS Chrome 96-119
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.187 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36',
    # macOS Safari 15/16 (Monterey/Ventura era)
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15',
    # macOS Firefox 100-119
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.6; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.0; rv:110.0) Gecko/20100101 Firefox/110.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.3; rv:113.0) Gecko/20100101 Firefox/113.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:116.0) Gecko/20100101 Firefox/116.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:119.0) Gecko/20100101 Firefox/119.0',
    # iPhone Safari iOS 15.x
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7.1 Mobile/15E148 Safari/604.1',
    # iPhone Safari iOS 16.x
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1',
    # iPhone Chrome (CriOS) older
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/105.0.5195.100 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/107.0.5304.83 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/110.0.5481.83 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.99 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/116.0.5845.177 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.169 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/135.0.7049.83 Mobile/15E148 Safari/604.1',
    # iPad Safari older
    'Mozilla/5.0 (iPad; CPU OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1',
    # Android Chrome older (2021-2023 era)
    'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-S906B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.136 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.128 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-A536E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.154 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.131 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.58 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.105 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; 2201116SG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; 2207122MC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; 23013PC75G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.166 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; CPH2325) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.129 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; CPH2357) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.86 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; V2149) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.136 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; motorola edge 30 pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.105 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; motorola edge 40) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.166 Mobile Safari/537.36',
    # Samsung Internet older versions (21-23)
    'Mozilla/5.0 (Linux; Android 12; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/21.0 Chrome/109.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/21.0 Chrome/109.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S916B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 Chrome/111.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A556E) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36',
    # Android Firefox older
    'Mozilla/5.0 (Android 12; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0',
    'Mozilla/5.0 (Android 12; Mobile; rv:112.0) Gecko/112.0 Firefox/112.0',
    'Mozilla/5.0 (Android 13; Mobile; rv:116.0) Gecko/116.0 Firefox/116.0',
    'Mozilla/5.0 (Android 13; Mobile; rv:118.0) Gecko/118.0 Firefox/118.0',
    # DuckDuckGo browser (iOS and Android)
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 DuckDuckGo/7 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 DuckDuckGo/7 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 DuckDuckGo/7 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 DuckDuckGo/7 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36 DuckDuckGo/5',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.50 Mobile Safari/537.36 DuckDuckGo/5',
    # Brave browser (Chromium-based, shows as Chrome)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.159 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.146 Mobile Safari/537.36',
    # Opera newer (116+)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/119.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36 OPR/82.0.0.0',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36 OPR/83.0.0.0',
    # Opera older (2021-2023 era)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36 OPR/82.0.4227.23',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.52 Safari/537.36 OPR/91.0.4516.20',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.74 Safari/537.36 OPR/95.0.4635.25',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.106 Safari/537.36 OPR/100.0.4815.21',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36 OPR/104.0.4944.23',
    # Vivaldi newer versions
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.210 Safari/537.36 Vivaldi/7.1.3570.39',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.178 Safari/537.36 Vivaldi/7.2.3628.27',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.210 Safari/537.36 Vivaldi/7.1.3570.39',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.191 Safari/537.36 Vivaldi/7.0.3495.27',
    # Vivaldi older
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36 Vivaldi/6.1.3035.302',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36 Vivaldi/6.5.3206.57',
    # Linux Chrome older
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.127 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.111 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.149 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    # Linux Firefox older
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:112.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0',
    # ChromeOS older
    'Mozilla/5.0 (X11; CrOS x86_64 14816.131.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15117.111.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.110 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15359.58.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.104 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15474.82.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.241 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15571.63.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.157 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 15633.27.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.212 Safari/537.36',
    # Additional smart TVs
    'Mozilla/5.0 (SMART-TV; Linux; Tizen 9.0) AppleWebKit/538.1 (KHTML, like Gecko) Version/9.0 TV Safari/538.1',
    'Mozilla/5.0 (SMART-TV; Linux; Tizen 4.0) AppleWebKit/538.1 (KHTML, like Gecko) Version/4.0 TV Safari/538.1',
    'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 DMOST/2.0.0 (; LGE; webOSTV; WEBOS25H; W25H;)',
    'Mozilla/5.0 (Linux; Android 12; BRAVIA XR-55A80K Build/SKQ1.220302.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; OLED55C3PSA Build/SKQ1.220302.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 9; SHIELD Android TV Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; AFT_MNDVD Build/PS7408.3524N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
    # Gaming consoles additional
    'Mozilla/5.0 (PlayStation; PlayStation 5/10.20) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
    'Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edge/44.18363.8131.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series S) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edge/44.18363.8131.0',
    # Meta Quest additional
    'Mozilla/5.0 (Linux; Android 12; Quest 3) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/33.0.0.3 SamsungBrowser/4.3 Chrome/130.0.6723.43 VR Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; Quest 2) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/26.0.0.3 SamsungBrowser/4.3 Chrome/104.0.5112.97 VR Safari/537.36',
    # Apple TV additional
    'Mozilla/5.0 (AppleTV; CPU AppleTV15,1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'Mozilla/5.0 (AppleTV; CPU AppleTV11,1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
    # Huawei Browser additional
    'Mozilla/5.0 (Linux; Android 12; NOH-NX9 Build/HUAWEINOH-NX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/13.0.5.310 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; ELS-N39 Build/HUAWEIELS-N39) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.46 HuaweiBrowser/14.0.1.300 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; GLA-LX1 Build/HUAWEIGLA-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 HuaweiBrowser/12.1.5.301 Mobile Safari/537.36',
    # Chrome 137 (2025/2026 era)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    # macOS Safari 18.4/18.5 / iOS 18.4/18.5
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4.1 Mobile/15E148 Safari/604.1',
    # Firefox 138-140 macOS/Linux
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.4; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.5; rv:139.0) Gecko/20100101 Firefox/139.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:138.0) Gecko/138.0 Firefox/138.0',
    'Mozilla/5.0 (Android 15; Mobile; rv:139.0) Gecko/139.0 Firefox/139.0',
    # ── More Android 13-15 diversity ──────────────────────────────────────────
    # Xiaomi / Redmi / POCO (2022-2025)
    'Mozilla/5.0 (Linux; Android 13; 2304FPN6DC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.172 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; 2303CRA44A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.140 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23113RKC6C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 2312DRAABL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; 24117RA68G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.48 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23116PN5BC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 2407FPN8EG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; 25011MND9G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.56 Mobile Safari/537.36',
    # OPPO / OnePlus (2022-2025)
    'Mozilla/5.0 (Linux; Android 12; CPH2269) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; CPH2409) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.154 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; CPH2491) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.166 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; CPH2529) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; CPH2609) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.146 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; CPH2661) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; LE2125) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; CPH2657) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    # vivo (2022-2025)
    'Mozilla/5.0 (Linux; Android 12; V2109) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; V2302A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; V2402A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; V2416A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.138 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; V2501A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.50 Mobile Safari/537.36',
    # Motorola (2022-2025)
    'Mozilla/5.0 (Linux; Android 12; moto g pure) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; moto g stylus 5G (2023)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.48 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; moto g power 5G (2024)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; moto g85 5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; motorola edge+) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36',
    # Samsung Galaxy A-series additional
    'Mozilla/5.0 (Linux; Android 13; SM-A135F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-A235F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.166 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A156B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A346B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A426B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-A166B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-A256E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A725F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36',
    # Additional Pixel models
    'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro Fold) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    # ASUS, Nokia, Nothing phones
    'Mozilla/5.0 (Linux; Android 13; ASUS_AI2302) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.172 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; ASUS_AI2401_A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Nokia XR21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; A065) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23111PN0DC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.134 Mobile Safari/537.36',
    # Android tablets additional
    'Mozilla/5.0 (Linux; Android 12; SM-X200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.119 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-X306B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-T976B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X616B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X818U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Lenovo TB360ZU) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Safari/537.36',
    # WebView additional
    'Mozilla/5.0 (Linux; Android 13; SM-A536B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-A546E Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/AP1A.240405.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S931B Build/AP3A.241205.013; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21G80',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22D63',
    # macOS Chrome additional patch versions
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.116 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.160 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.141 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.96 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Safari/537.36',
    # Windows Chrome additional patch builds
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.88 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.118 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.105 Safari/537.36',
    # Windows Edge additional
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 Edg/116.0.1938.81',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36 Edg/118.0.2088.76',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36 Edg/121.0.2277.128',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.142 Safari/537.36 Edg/125.0.2535.92',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Safari/537.36 Edg/129.0.2792.79',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.141 Safari/537.36 Edg/133.0.3065.92',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.3296.52',
    # iPhone FxiOS additional
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/110.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/118.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/136.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/138.0 Mobile/15E148 Safari/605.1.15',
    # Android Samsung S-series US models
    'Mozilla/5.0 (Linux; Android 13; SM-S911U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S926U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S938U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-G781B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.172 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; SM-S921U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
    # LG phones (older, still in use)
    'Mozilla/5.0 (Linux; Android 10; LM-G900) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; LM-V600) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.58 Mobile Safari/537.36',
    # Tecno, Infinix (emerging market phones)
    'Mozilla/5.0 (Linux; Android 12; TECNO KG8p) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Infinix X6819) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; TECNO LH8n) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    # ── Windows Chrome 2021 era (additional round builds) ─────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    # macOS Chrome 2021 era
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36',
    # macOS Firefox 2021 era
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11.6; rv:96.0) Gecko/20100101 Firefox/96.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.2; rv:100.0) Gecko/20100101 Firefox/100.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.5; rv:104.0) Gecko/20100101 Firefox/104.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.0; rv:107.0) Gecko/20100101 Firefox/107.0',
    # Linux 2021 era
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0',
    # More iPhone CriOS spread
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/102.0.5005.87 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/108.0.5359.83 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.99 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/136.0.7103.56 Mobile/15E148 Safari/604.1',
    # More FxiOS older
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/104.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/106.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/116.0 Mobile/15E148 Safari/605.1.15',
    # Samsung Internet additional old devices
    'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/18.0 Chrome/107.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/19.0 Chrome/107.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/107.0.0.0 Mobile Safari/537.36',
    # Windows Firefox ESR cross-platform
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
    # iOS 15/16 Chrome older
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/94.0.4606.52 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/100.0.4896.85 Mobile/15E148 Safari/604.1',
    # Android Chrome 2021 (11/12 devices)
    'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 4a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.87 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Pixel 5a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-G990B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; 21061110AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; M2012K11AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; POCO X3 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    # Huawei MatePad / MatePad Pro (tablets)
    'Mozilla/5.0 (Linux; Android 11; HarmonyOS; AGM-AL09 Build/HUAWEIAGM-AL09) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/13.0.4.306 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; PAD-LX9 Build/HUAWEIPAD-LX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/13.0.5.305 Safari/537.36',
    # Edge Android / iOS
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36 EdgA/130.0.2849.68',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.50 Mobile Safari/537.36 EdgA/133.0.3065.58',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/132.2957.125 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/133.3065.92 Mobile/15E148 Safari/604.1',
    # Macintosh M-chip explicit
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.201 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.160 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    # ── Additional spread to reach 1000+ total ─────────────────────────────────
    # Windows Edge 2021 era (round builds)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.0.0 Safari/537.36 Edg/96.0.1054.43',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36 Edg/100.0.1185.39',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36 Edg/104.0.1293.70',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.64',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.81',
    # macOS Edge older
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.64',
    # Android Firefox tablet
    'Mozilla/5.0 (Android 12; Tablet; rv:109.0) Gecko/109.0 Firefox/109.0',
    'Mozilla/5.0 (Android 14; Tablet; rv:128.0) Gecko/128.0 Firefox/128.0',
    # More iPhone FxiOS spread
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/122.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15',
    # Windows 11 (some websites detect NT 10.0 as Win11)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0',
    # Vivaldi Android/Linux
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.146 Mobile Safari/537.36 Vivaldi/6.9.3476.46',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.178 Safari/537.36 Vivaldi/7.2.3628.27',
    # iPad Chrome older
    'Mozilla/5.0 (iPad; CPU OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/104.0.5112.99 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/111.0.5563.101 Mobile/15E148 Safari/604.1',
    # Huawei tablet
    'Mozilla/5.0 (Linux; Android 12; DBY-W09 Build/HUAWEIDBY-W09) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/13.0.6.303 Safari/537.36',
    # Samsung Internet on tablets
    'Mozilla/5.0 (Linux; Android 13; SM-X906C) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X910) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Safari/537.36',
    # Kindle Fire
    'Mozilla/5.0 (Linux; Android 9; KFONWI Build/PS7579.3844N) AppleWebKit/537.36 (KHTML, like Gecko) Silk/97.3.1 like Chrome/97.0.4692.98 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; KFTRWI Build/PS7640.3851N) AppleWebKit/537.36 (KHTML, like Gecko) Silk/109.4.0 like Chrome/109.0.0.0 Safari/537.36',
    # Windows Firefox with detailed build versions
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0',
    # macOS Safari older (Big Sur era)
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_8) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15',
    # iPhone Safari Big Sur era (iOS 14/15 early)
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1',
    # Misc additional Android
    'Mozilla/5.0 (Linux; Android 13; SM-F711B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-F731B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; 22127RN68G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.131 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 24078PCD8I) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; CPH2505) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.131 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; LE2125) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36',
    # DuckDuckGo macOS app
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 DuckDuckGo/1.6.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15 DuckDuckGo/1.8.0',
    # Additional macOS Firefox
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.0; rv:131.0) Gecko/20100101 Firefox/131.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.1; rv:133.0) Gecko/20100101 Firefox/133.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15.3; rv:135.0) Gecko/20100101 Firefox/135.0',
    # Windows Firefox older
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0',
    # ChromeOS newer
    'Mozilla/5.0 (X11; CrOS x86_64 16413.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.115 Safari/537.36',
    'Mozilla/5.0 (X11; CrOS x86_64 16520.42.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    # Linux Vivaldi
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36 Vivaldi/6.5.3206.57',
    # Misc Windows builds
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
    # ── Final batch to cross 1000 ──────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Mozilla/5.0 (Android 11; Mobile; rv:96.0) Gecko/96.0 Firefox/96.0',
    'Mozilla/5.0 (Android 12; Mobile; rv:100.0) Gecko/100.0 Firefox/100.0',
    'Mozilla/5.0 (Android 12; Mobile; rv:104.0) Gecko/104.0 Firefox/104.0',
    'Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-A325F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-A736B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.77 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 3a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/96.0.4664.53 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; 23127PN0DC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36',
]

# ── Malware / bot / scanner user-agent strings ────────────────────────────────
malware_user_agents = [
    '01h4x.com',
    '360Spider',
    '404checker',
    '404enemy',
    '80legs',
    'ADmantX',
    'AIBOT',
    'ASPSeek',
    'Abonti',
    'Aboundex',
    'Aboundexbot',
    'Acunetix',
    'AdsTxtCrawlerTP',
    'AfD-Verbotsverfahren',
    'AhrefsBot',
    'AiHitBot',
    'Aipbot',
    'Alexibot',
    'AllSubmitter',
    'Alligator',
    'AlphaBot',
    'Anarchie',
    'Anarchy',
    'Anarchy99',
    'Ankit',
    'Anthill',
    'Apexoo',
    'Aspiegel',
    'Asterias',
    'Atomseobot',
    'Attach',
    'AwarioBot',
    'AwarioRssBot',
    'AwarioSmartBot',
    'BBBike',
    'BDCbot',
    'BDFetch',
    'BLEXBot',
    'BackDoorBot',
    'BackStreet',
    'BackWeb',
    'Backlink-Ceck',
    'BacklinkCrawler',
    'BacklinksExtendedBot',
    'Badass',
    'Bandit',
    'Barkrowler',
    'BatchFTP',
    'BetaBot',
    'Bigfoot',
    'Bitacle',
    'BlackWidow',
    'Blackboard',
    'Blow',
    'BlowFish',
    'Boardreader',
    'Bolt',
    'BotALot',
    'Brandprotect',
    'Brandwatch',
    'Buck',
    'Buddy',
    'BuiltBotTough',
    'BuiltWith',
    'Bullseye',
    'BunnySlippers',
    'BuzzSumo',
    'Bytespider',
    'CATExplorador',
    'CCBot',
    'CODE87',
    'CSHttp',
    'Calculon',
    'CazoodleBot',
    'Cegbfeieh',
    'CensysInspect',
    'ChatGPT-User',
    'CheTeam',
    'CheeseBot',
    'CherryPicker',
    'ChinaClaw',
    'Chlooe',
    'Citoid',
    'Claritybot',
    'ClaudeBot',
    'Cliqzbot',
    'Cocolyzebot',
    'Cogentbot',
    'Collector',
    'Copier',
    'CopyRightCheck',
    'Copyscape',
    'Cosmos',
    'Craftbot',
    'CrazyWebCrawler',
    'Crescent',
    'CrunchBot',
    'Curious',
    'Custo',
    'CyotekWebCopy',
    'DBLBot',
    'DIIbot',
    'DSearch',
    'DataCha0s',
    'DatabaseDriverMysqli',
    'Demon',
    'Deusu',
    'Devil',
    'Digincore',
    'DigitalPebble',
    'Dirbuster',
    'Disco',
    'Discobot',
    'Discoverybot',
    'Dispatch',
    'DittoSpyder',
    'DnBCrawler-Analytics',
    'DnyzBot',
    'DomCopBot',
    'DomainAppender',
    'DomainCrawler',
    'DomainSigmaCrawler',
    'DomainStatsBot',
    'Dotbot',
    'Dragonfly',
    'Drip',
    'ECCP/1.0',
    'EasyDL',
    'Ebingbong',
    'Ecxi',
    'EirGrabber',
    'EroCrawler',
    'Evil',
    'Exabot',
    'ExtLinksBot',
    'Extractor',
    'ExtractorPro',
    'EyeNetIE',
    'Ezooms',
    'FDM',
    'FHscan',
    'FacebookBot',
    'FemtosearchBot',
    'Fimap',
    'Firefox/7.0',
    'FlashGet',
    'Flunky',
    'Foobot',
    'Freeuploader',
    'FrontPage',
    'Fuzz',
    'FyberSpider',
    'Fyrebot',
    'G-i-g-a-b-o-t',
    'GPTBot',
    'GT::WWW',
    'GalaxyBot',
    'GeedoProductSearch',
    'Genieo',
    'GermCrawler',
    'GetRight',
    'GetWeb',
    'Getintent',
    'Gigabot',
    'Go!Zilla',
    'Go-Ahead-Got-It',
    'GoZilla',
    'Gotit',
    'GrabNet',
    'Grabber',
    'Grafula',
    'GrapeFX',
    'GrapeshotCrawler',
    'GridBot',
    'HEADMasterSEO',
    'HMView',
    'HTMLparser',
    'HTTP::Lite',
    'HTTrack',
    'Haansoft',
    'HaosouSpider',
    'Harvest',
    'Havij',
    'Heritrix',
    'Hloader',
    'HonoluluBot',
    'Humanlinks',
    'HybridBot',
    'IDBTE4M',
    'IDBot',
    'IRLbot',
    'Iblog',
    'Id-search',
    'IlseBot',
    'ImagesiftBot',
    'IndeedBot',
    'InfoNaviRobot',
    'InfoTekies',
    'Intelliseek',
    'InterGET',
    'InternetMeasurement',
    'InternetSeer',
    'Iria',
    'Iskanie',
    'IstellaBot',
    'JamesBOT',
    'Jbrofuzz',
    'JennyBot',
    'JetCar',
    'Jetty',
    'JikeSpider',
    'Joomla',
    'Jorgee',
    'JustView',
    'Jyxobot',
    'Kinza',
    'Kozmosbot',
    'LNSpiderguy',
    'LWP::Simple',
    'Lanshanbot',
    'Larbin',
    'Leap',
    'LeechFTP',
    'LeechGet',
    'LexiBot',
    'Lftp',
    'LibWeb',
    'Libwhisker',
    'LieBaoFast',
    'Lightspeedsystems',
    'Likse',
    'LinkScan',
    'LinkWalker',
    'Linkbot',
    'LinkextractorPro',
    'LinkpadBot',
    'LinksManager',
    'LinqiaMetadataDownloaderBot',
    'LinqiaRSSBot',
    'LinqiaScrapeBot',
    'Lipperhey',
    'Litemage_walker',
    'Lmspider',
    'Ltx71',
    'MFC_Tear_Sample',
    'MIIxpc',
    'MJ12bot',
    'MQQBrowser',
    'MSFrontPage',
    'MSIECrawler',
    'MTRobot',
    'Mag-Net',
    'Magnet',
    'Mail.RU_Bot',
    'Majestic-SEO',
    'Majestic12',
    'MarkMonitor',
    'MarkWatch',
    'Masscan',
    'MauiBot',
    'Mb2345Browser',
    'Meanpathbot',
    'Mediatoolkitbot',
    'MegaIndex.ru',
    'Metauri',
    'MicroMessenger',
    'Minefield',
    'Mojeek',
    'Mojolicious',
    'MolokaiBot',
    'Mozlila',
    'Mr.4x3',
    'Msrabot',
    'Musobot',
    'NICErsPRO',
    'NPbot',
    'Nameprotect',
    'Navroad',
    'NearSite',
    'Needle',
    'Nessus',
    'NetAnts',
    'NetLyzer',
    'NetMechanic',
    'NetSpider',
    'NetZIP',
    'Netcraft',
    'Nettrack',
    'Netvibes',
    'NextGenSearchBot',
    'Nibbler',
    'Niki-bot',
    'Nikto',
    'NimbleCrawler',
    'Nimbostratus',
    'Ninja',
    'Nmap',
    'Nuclei',
    'Nutch',
    'Octopus',
    'OnCrawl',
    'OpenLinkProfiler',
    'OpenVAS',
    'Openfind',
    'Openvas',
    'OrangeBot',
    'OrangeSpider',
    'OutclicksBot',
    'OutfoxBot',
    'PECL::HTTP',
    'PHPCrawl',
    'POE-Component-Client-HTTP',
    'PageAnalyzer',
    'PageGrabber',
    'PageScorer',
    'PageThing.com',
    'Pandalytics',
    'Panscient',
    'Pavuk',
    'PeoplePal',
    'Petalbot',
    'Pi-Monster',
    'Picscout',
    'Picsearch',
    'PictureFinder',
    'Piepmatz',
    'Pimonster',
    'Pixray',
    'PleaseCrawl',
    'Pockey',
    'ProPowerBot',
    'ProWebWalker',
    'Probethenet',
    'Proximic',
    'Psbot',
    'Pu_iN',
    'Pump',
    'PxBroker',
    'PyCurl',
    'Quick-Crawler',
    'RSSingBot',
    'Rainbot',
    'RankActive',
    'RankActiveLinkBot',
    'RankFlex',
    'RankingBot',
    'RankingBot2',
    'Rankivabot',
    'RankurBot',
    'Re-re',
    'ReGet',
    'RealDownload',
    'Reaper',
    'RebelMouse',
    'Recorder',
    'RedesScrapy',
    'RepoMonkey',
    'Ripper',
    'RocketCrawler',
    'Rogerbot',
    'SBIder',
    'SEOkicks',
    'SEOkicks-Robot',
    'SEOlyt',
    'SEOlyticsCrawler',
    'SEOprofiler',
    'SEOstats',
    'SISTRIX',
    'SMTBot',
    'SalesIntelligent',
    'ScanAlert',
    'Scanbot',
    'ScoutJet',
    'Scrapy',
    'Screaming',
    'ScreenerBot',
    'ScrepyBot',
    'Searchestate',
    'SearchmetricsBot',
    'Seekport',
    'SeekportBot',
    'SemanticJuice',
    'Semrush',
    'SemrushBot',
    'SemrushBot-BA',
    'SemrushBot-FT',
    'SemrushBot-OCOB',
    'SemrushBot-SI',
    'SemrushBot-SWA',
    'SentiBot',
    'SenutoBot',
    'SeoCherryBot',
    'SeoSiteCheckup',
    'SeobilityBot',
    'Seomoz',
    'Shodan',
    'Siphon',
    'SiteAuditBot',
    'SiteCheckerBotCrawler',
    'SiteExplorer',
    'SiteLockSpider',
    'SiteSnagger',
    'SiteSucker',
    'Sitebeam',
    'Siteimprove',
    'Sitevigil',
    'SlySearch',
    'SmartDownload',
    'Snake',
    'Snapbot',
    'Snoopy',
    'SocialRankIOBot',
    'Sociscraper',
    'Sosospider',
    'Sottopop',
    'SpaceBison',
    'Spammen',
    'SpankBot',
    'Spanner',
    'Spbot',
    'Spider_Bot',
    'Spider_Bot/3.0',
    'Spinn3r',
    'SplitSignalBot',
    'SputnikBot',
    'Sqlmap',
    'Sqlworm',
    'Sqworm',
    'Steeler',
    'Stripper',
    'Sucker',
    'Sucuri',
    'SuperBot',
    'SuperHTTP',
    'Surfbot',
    'SurveyBot',
    'Suzuran',
    'Swiftbot',
    'Szukacz',
    'T0PHackTeam',
    'T8Abot',
    'Teleport',
    'TeleportPro',
    'Telesoft',
    'Telesphoreo',
    'Telesphorep',
    'TheNomad',
    'Thumbor',
    'TightTwatBot',
    'TinyTestBot',
    'Titan',
    'Toata',
    'Toweyabot',
    'Tracemyfile',
    'Trendiction',
    'Trendictionbot',
    'True_Robot',
    'Turingos',
    'Turnitin',
    'TurnitinBot',
    'TwengaBot',
    'Twice',
    'Typhoeus',
    'URLy.Warning',
    'UnisterBot',
    'Upflow',
    'V-BOT',
    'VCI',
    'Vacuum',
    'Vagabondo',
    'VelenPublicWebCrawler',
    'VeriCiteCrawler',
    'VidibleScraper',
    'Virusdie',
    'VoidEYE',
    'Voil',
    'Voltron',
    'WASALive-Bot',
    'WBSearchBot',
    'WEBDAV',
    'WISENutbot',
    'WPScan',
    'WWW-Collector-E',
    'WWW-Mechanize',
    'WWW::Mechanize',
    'WWWOFFLE',
    'Wallpapers',
    'Wallpapers/3.0',
    'WallpapersHD',
    'WeSEE',
    'WebAuto',
    'WebBandit',
    'WebCollage',
    'WebCopier',
    'WebEnhancer',
    'WebFetch',
    'WebFuck',
    'WebImageCollector',
    'WebLeacher',
    'WebPix',
    'WebReaper',
    'WebSauger',
    'WebStripper',
    'WebSucker',
    'WebWhacker',
    'WebZIP',
    'Webalta',
    'WebmasterWorldForumBot',
    'Webshag',
    'WebsiteExtractor',
    'WebsiteQuester',
    'Webster',
    'Whack',
    'Whacker',
    'Whatweb',
    'Widow',
    'WinHTTrack',
    'Wonderbot',
    'Woobot',
    'Wotbox',
    'Wprecon',
    'Xaldon_WebSpider',
    'Xenu',
    'YaK',
    'YoudaoBot',
    'Zade',
    'Zauba',
    'Zermelo',
    'Zeus',
    'Zitebot',
    'ZmEu',
    'ZoomBot',
    'ZoominfoBot',
    'ZumBot',
    'ZyBorg',
    'adscanner',
    'anthropic-ai',
    'archive.org_bot',
    'arquivo-web-crawler',
    'arquivo.pt',
    'autoemailspider',
    'awario.com',
    'backlink-check',
    'cah.io.community',
    'check1.exe',
    'clark-crawler',
    'coccocbot',
    'cognitiveseo',
    'cohere-ai',
    'com.plumanalytics',
    'crawl.sogou.com',
    'crawler.feedback',
    'crawler4j',
    'dataforseo.com',
    'dataforseobot',
    'demandbase-bot',
    'domainsproject.org',
    'eCatch',
    'evc-batch',
    'everyfeed-spider',
    'facebookscraper',
    'gopher',
    'heritrix',
    'imagesift.com',
    'instabid',
    'ips-agent',
    'isitwp.com',
    'iubenda-radar',
    'linkdexbot',
    'linkfluence',
    'lwp-request',
    'lwp-trivial',
    'magpie-crawler',
    'meanpathbot',
    'mediawords',
    'muhstik-scan',
    'oBot',
    'omgili',
    'openai',
    'openai.com',
    'pcBrowser',
    'plumanalytics',
    'probe-image-size',
    'ripz',
    's1z.ru',
    'satoristudio.net',
    'scalaj-http',
    'scan.lol',
    'seobility',
    'seocompany.store',
    'seoscanners',
    'seostar',
    'serpstatbot',
    'sexsearcher',
    'sitechecker.pro',
    'siteripz',
    'sogouspider',
    'sp_auditbot',
    'spyfu',
    'sysscan',
    'tAkeOut',
    'trendiction.com',
    'trendiction.de',
    'ubermetrics-technologies.com',
    'voyagerx.com',
    'webgains-bot',
    'webmeup-crawler',
    'webpros.com',
    'webprosbot',
    'x09Mozilla',
    'x22Mozilla',
    'xpymep1.exe',
    'zauba.io',
    'zgrab',
]

# ── AV / EICAR test file endpoints ────────────────────────────────────────────
virus_endpoints = [
    "http://2016.eicar.org/download/eicar.com",
    "http://2016.eicar.org/download/eicar.com.txt",
    "http://2016.eicar.org/download/eicar_com.zip",
    "http://2016.eicar.org/download/eicarcom2.zip",
    "https://secure.eicar.org/eicar.com",
    "https://secure.eicar.org/eicar.com.txt",
    "https://secure.eicar.org/eicar_com.zip",
    "https://secure.eicar.org/eicarcom2.zip",
    "https://www.ikarussecurity.com/wp-content/downloads/eicar_com.zip",
    "https://wildfire.paloaltonetworks.com/publicapi/test/apk",
    "https://wildfire.paloaltonetworks.com/publicapi/test/macos",
    "http://wildfire.paloaltonetworks.com/publicapi/test/apk",
    "http://wildfire.paloaltonetworks.com/publicapi/test/macos",
]

# ── Domain squatting / homograph probe targets ────────────────────────────────
squatting_endpoints = [
    "accounts.google.com",
    "adn.com",
    "time.google.com",
    "twitter.com",
    "tesla.com",
    "adobe.com",
    "apple.com",
    "docs.google.com",
    "en.wikipedia.org",
    "openai.com",
    "neverssl.com",
    "github.com",
    "linkedin.com",
    "maps.google.com",
    "microsoft.com",
    "mozilla.org",
    "play.google.com",
    "sites.google.com",
    "www.att.com",
    "info.cern.ch",
    "support.google.com",
    "vimeo.com",
    "wordpress.org",
    "www.blogger.com",
    "www.google.com",
    "www.unco.edu",
    "www.apple.com",
    "www.netflix.com",
    "youtube.com",
    "abc.com",
    "google.com",
    "cnn.com",
    "github.com",
    "testmyids.com",
    "microsoft.com",
    "catonetworks.com",
    "wikipedia.com",
    "slashdot.org",
]

# ── Adult / pornography content URLs ──────────────────────────────────────────
pornography_endpoints = [
    "https://livejasmin.com",
    "https://pornhub.com",
    "https://xvideos.com",
    "https://bongacams.com",
    "https://xhamster.com",
    "https://xnxx.com",
    "https://youporn.com",
    "https://chaturbate.com",
    "https://spankbang.com",
    "https://sex.com",
    "https://redtube.com",
    "https://dmm.com",
    "https://beeg.com",
    "https://yespornplease.com",
    "https://4chan.org",
    "https://urbandictionary.com",
    "https://xhamster.desi",
    "https://manyvids.com",
    "https://gotporn.com",
    "https://e-hentai.org",
    "https://cda.pl",
    "https://youjizz.com",
    "https://okcupid.com",
    "https://txxx.com",
    "https://tube8.com",
    "https://myfreecams.com",
    "https://pornhubpremium.com",
    "https://perfectgirls.net",
    "https://nhentai.net",
    "https://sxyprn.com",
    "https://pornpics.com",
    "https://clips4sale.com",
    "https://pornhdvideos.net",
    "https://porntrex.com",
    "https://eporner.com",
    "https://pornhublive.com",
    "https://xhamsterlive.com",
    "https://porn.com",
    "https://xtube.com",
    "https://drtuber.com",
    "https://motherless.com",
    "https://ashemaletube.com",
    "https://hitomi.la",
    "https://fuq.com",
    "https://daftsex.com",
    "https://match.com",
    "https://doublepimp.com",
    "https://cam4.com",
    "https://sexseq.com",
    "https://nutaku.net",
    "https://reallifecam.com",
    "https://thefappeningblog.com",
    "https://theporndude.com",
    "https://gayboystube.com",
    "https://heavy-r.com",
    "https://jizzbunker.com",
    "https://brazzers.com",
    "https://efukt.com",
    "https://biqle.ru",
    "https://hclips.com",
    "https://spankwire.com",
    "https://adultfriendfinder.com",
    "https://bangbros.com",
    "https://sexu.com",
    "https://hqporner.com",
    "https://anyporn.com",
    "https://stripchat.com",
    "https://fishki.net",
    "https://ixxx.com",
    "https://thisvid.com",
    "https://bellesa.co",
    "https://hdzog.com",
    "https://vporn.com",
    "https://hellporno.net",
    "https://thumbzilla.com",
    "https://dlsite.com",
    "https://4tube.com",
    "https://bravotube.net",
    "https://pornq.com",
    "https://vkmag.com",
    "https://muchohentai.com",
    "https://porzo.com",
    "https://tnaflix.com",
    "https://xhamsterpremium.com",
    "https://pornmd.com",
    "https://cosmopolitan.com",
    "https://brazzersnetwork.com",
    "https://celebjihad.com",
    "https://nuvid.com",
    "https://cameraprive.com",
    "https://pornolab.net",
    "https://duga.jp",
    "https://paheal.net",
    "https://joyclub.de",
    "https://escort-advisor.com",
    "https://tukif.com",
    "https://imagefap.com",
    "https://pornhd.com",
    "https://videa.hu",
    "https://r18.com",
    "https://xhamster9.com",
    "https://girlsgogames.com",
    "https://softcore69.com",
    "https://8muses.com",
    "https://cityheaven.net",
    "https://sleazyneasy.com",
    "https://keezmovies.com",
    "https://jasmin.com",
    "https://upornia.com",
    "https://desixnxx2.net",
    "https://cumshots.com",
    "https://anysex.com",
    "https://topescortbabes.com",
    "https://literotica.com",
    "https://adultdvdempire.com",
    "https://videosdemadurasx.com",
    "https://analdin.com",
    "https://crazyshit.com",
    "https://porn.biz",
    "https://ancensored.com",
    "https://planetsuzy.org",
    "https://boyfriendtv.com",
    "https://f95zone.to",
    "https://hentaiheroes.com",
    "https://sankakucomplex.com",
    "https://pornhub.org",
    "https://katestube.com",
    "https://prpops.com",
    "https://thefappening.pro",
    "https://ice-gay.com",
    "https://lsl.com",
    "https://xvidzz.com",
    "https://redtubelive.com",
    "https://kompoz.me",
    "https://evilangel.com",
    "https://dirtypornvids.com",
    "https://blacked.com",
    "https://nudevista.com",
    "https://51.la",
    "https://porndoe.com",
    "https://thisav.com",
    "https://vjav.com",
    "https://videospornogratisx.net",
    "https://pornsos.com",
    "https://hotmovs.com",
    "https://hdsex.org",
    "https://erome.com",
    "https://iwank.tv",
    "https://oral-amateure.com",
    "https://super.cz",
    "https://3movs.com",
    "https://tubedupe.com",
    "https://kink.com",
    "https://naughtyamerica.com",
    "https://pichunter.com",
    "https://vercomicsporno.com",
    "https://shameless.com",
    "https://freevideo.cz",
    "https://mofos.com",
    "https://theync.com",
]

# ── SNMP community strings and probe targets ───────────────────────────────────
snmp_v1_strings = [
    "public", "private", "community", "default", "manager",
    "admin", "cisco", "monitor", "trap", "access", "secret",
    "write", "read", "snmp", "ILMI", "guest", "password", "0",
]

snmp_v2c_strings = [
    "public", "private", "community", "default", "admin",
    "cisco", "router", "switch", "network", "manager",
    "monitor", "core", "access", "test", "security",
    "system", "read", "write", "readonly", "readwrite",
    "all", "temp", "snmpd", "agent", "trap", "secret",
]

# (username, security-level, auth-proto, auth-pass, priv-proto, priv-pass)
# Covers noAuthNoPriv, authNoPriv, and authPriv — common defaults found in the wild
snmp_v3_creds = [
    ("initial",    "noAuthNoPriv", "",     "",              "",     ""),
    ("public",     "noAuthNoPriv", "",     "",              "",     ""),
    ("admin",      "noAuthNoPriv", "",     "",              "",     ""),
    ("readonly",   "noAuthNoPriv", "",     "",              "",     ""),
    ("monitor",    "noAuthNoPriv", "",     "",              "",     ""),
    ("default",    "noAuthNoPriv", "",     "",              "",     ""),
    ("guest",      "noAuthNoPriv", "",     "",              "",     ""),
    ("cisco",      "authNoPriv",   "MD5",  "cisco123",      "",     ""),
    ("admin",      "authNoPriv",   "MD5",  "admin123",      "",     ""),
    ("admin",      "authNoPriv",   "SHA",  "admin123",      "",     ""),
    ("netadmin",   "authNoPriv",   "SHA",  "netadmin",      "",     ""),
    ("snmpv3",     "authNoPriv",   "MD5",  "snmpv3pass",    "",     ""),
    ("v3user",     "authNoPriv",   "SHA",  "password",      "",     ""),
    ("operator",   "authNoPriv",   "MD5",  "operator",      "",     ""),
    ("snmpuser",   "authNoPriv",   "SHA",  "authpass12",    "",     ""),
    ("cisco",      "authPriv",     "MD5",  "cisco123",      "DES",  "cisco123"),
    ("admin",      "authPriv",     "SHA",  "admin123",      "AES",  "admin123"),
    ("snmpuser",   "authPriv",     "SHA",  "authpass12",    "AES",  "privpass12"),
    ("operator",   "authPriv",     "MD5",  "operator",      "DES",  "operator"),
    ("netadmin",   "authPriv",     "SHA",  "netadmin",      "AES",  "netadmin"),
]

snmp_endpoints = [
    "192.168.1.1",
    "172.16.0.1",
    "10.0.0.1",
    "10.0.0.254",
    "192.168.0.1",
    "192.168.1.254",
    "test.net-snmp.org",
    "demo.snmplabs.com",
    "snmp.inetdaemon.com",
    "snmp.pocsag.ro",
    "snmp.openfiler.com",
    "routertest.net",
]

# ── DLP test-data file URLs ────────────────────────────────────────────────────
dlp_https_endpoints = [
    "https://dlptest.com/sample-data.pdf",
    "https://dlptest.com/1-MB-Test.docx",
    "https://dlptest.com/1-MB-Test.xlsx",
    "https://dlptest.com/111-MB-Test.csv",
    "https://dlptest.com/334-MB-Test-CSV.csv",
    "https://dlptest.com/DLP-Test-State-Data.zip",
    "https://dlptest.com/10-MB-Test.xlsx",
    "https://dlptest.com/30-MB-Test.xlsx",
    "https://dlptest.com/DLP-Test-State-Data.zip",
    "https://dlptest.com/103-MB-Test.xlsx",
]

# ── Malware file download URLs (RAT / implant archives for IDS testing) ───────
malware_files = [
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/AbkoRat/AbkoRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/AcidBattery/AcidBattery1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/AcidHead/acidhead.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Adzok/Adzok_Free_v1.0.0.3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Aladino/Aladino.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/AndroRat/AndroRat.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/BBRat/BBRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/BabyRemote/宝贝远控4.3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/BawlessRat/Bawless.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/BillGates/阿布正版25000.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Bugs/Bugs.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CelestialRat/Celestial.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Charon/Charon.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Coma/Coma.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CoolRemCon/CoolRemCon.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DaCryptic/DaCryptic.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DarkCrystalRat/DarkCrystalRat.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DuplexSpyCS/DuplexSpyCS.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/FatalRat/DarkShare.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/FeiMooMa/FeiMooMa.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HellEmpire/Hellempire.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HellRaiser/HellRaiser4.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HiddenzHVNC/HiddenzHVNC.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HiveRat/HiveRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Hobo/20061017llz10.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Hue/Hue_v1b.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/IMRemoteManagement/IM远程管理.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Icarus/Icarus.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/JasonRat/JASONRAT_2.1.1.0_BugFix.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/JokerRat/Joker-RAT_v3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/LimitlessNetRAT/LimitlessNetRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MQ5Rat/mq5(plus).7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicRemote/rc2009.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MasudRana/MasudRana_1.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MiniMo/MiniCommand.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/NetSpear/NetSpear2006.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/NetWindow/NetWindow.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netministrator/Netministrator1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/NonEuclid/NonEuclid.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Octopus/Octopus.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/OmniRAT/OmniRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/OrcaBot/Orca.Bot.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PhoenixKeylogger/PhoenixKeylogger.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Pulsar/Pulsar.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Qianlimu/千里目远程监控系统2.5.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/RMSRat/RMSCreator_3.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Ratroid/Ratroid.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ShaShenRat/ShaShenRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ShadowRoot/ShadowRoot.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SierraLoader/SierraLoader.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Smile/Smile_v1.0SE.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SorillusRat/Sorillus.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.001",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.002",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.003",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.004",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.005",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.006",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SpyNoteX/SpyNoteX.7z.007",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/StillBornRat/StillBornRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/StreamRat/StreamRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/THTRat/THTRat.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ToRAT/ToRATv0.2.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Trochilus/Trochilus.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/WiRat/wiRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/WoodenOx/muniu2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/XNeT/X-NeT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/YuriRat/Yuri_RAT_V1.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Bifrost/BiFroSt-MaTreX/BiFroSt-MaTreX.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Bifrost/Bifrost1.1.03/Bifrost1.1.03.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ByShell/ByShell1.09新版本/ByShell1.09新版本.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ConsoleDevil/ConsoleDevil1.0/consoledevil1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ConsoleDevil/ConsoleDevil1.2/consoledevil1.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CrashCool/CrashCool-Trojan/CrashCool-Trojan.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CrashCool/CrashCool-Trojan2/Crashcool-Trojan2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DarkShell/DarkShell本地版/DarkShell本地版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DarkShell/DarkShell远控DDOS/DarkShell远控DDOS.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DarkShell/카스툴패킷강화/카스툴패킷강화.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/DcRat/PortHack/PortHack.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Dofloo/TF内部版3.8/TF内部版3.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Dofloo/麻衣路由端/麻衣路由端.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/FreeRat/FreeRat1.0/FreeRat1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/FreeRat/FreeRat2.0/FreeRat2.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.001",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.002",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.003",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.004",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.005",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.006",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.007",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.008",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.009",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.010",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.011",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.012",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.013",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.014",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.015",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.016",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.017",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/G700Rat/G-700RATV5/G-700RAT.7z.018",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stCringe/MushroomHead/Bin.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/Gh0st2011/Gh0st2011.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/Hackfans/Hackfans.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/KrisRat/KrisRat.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/Mmly/Mmly.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/MoZhe/MoZhe.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/日月神教VIP专版/日月神教VIP专版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Gh0stRat/牧民战天远控[至尊无壳版]/牧民战天远控[至尊无壳版].7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/JKS_菟菟/JKS_菟菟.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/小花匠技术论坛/小花匠技术论坛.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/灰鸽子VIP2009/灰鸽子VIP2009.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/灰鸽子密文加密解密器/灰鸽子密文加密解密器.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/灰鸽子远程控制【杨凡专版】/灰鸽子远程控制【杨凡专版】.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/灰鸽子黑客手册版/灰鸽子黑客手册版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/灰鸽子黑防专版/灰鸽子黑防专版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Graybird/灰鸽子黑防脱壳版/灰鸽子黑防脱壳版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HorusEyesRat/HorusEyesRat.V0.1.8/HorusEyesRat.V0.1.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HorusEyesRat/HorusEyesRat.V0.1.9/HorusEyesRat.V0.1.9.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/HorusEyesRat/HorusEyesRat.V0.2.1.0/HorusEyesRat.V0.2.1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_1.0/LANfiltrator_1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_1.0_FIX/LANfiltrator_1.0_FIX.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_1.1/LANfiltrator_1.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_1.1_FIX/LANfiltrator_1.1_FIX.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_1.5_Beta_III/LANfiltrator_1.5_Beta_III.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta10/LANfiltrator_Beta10.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta11/LANfiltrator_Beta11.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta3/LANfiltrator_Beta3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta4/LANfiltrator_Beta4.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta5/LANfiltrator_Beta5.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta6/LANfiltrator_Beta6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta7/LANfiltrator_Beta7.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta8/LANfiltrator_beta8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lanfiltrator/LANfiltrator_Beta9/LANfiltrator_Beta9.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/LarryLurexRat/LarryLurexRATv0.2/LarryLurexRATv0.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/LarryLurexRat/LarryLurexRATv0.3/LarryLurexRATv0.3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/LarryLurexRat/LarryLurexRATv0.4/LarryLurexRATv0.4.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lithium/Lithium1.00/Lithium1.00.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lithium/Lithium1.01/Lithium1.01.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lithium/Lithium1.02/Lithium1.02.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lithium/Lithium1.03/Lithium1.03.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Lithium/Lithium1.0b5/Lithium1.0b5.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy1.0/MagicLink_netPcSpy1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy1.2/MagicLink_netPcSpy1.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy1.3/MagicLink_netPcSpy1.3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy1.4/MagicLink_netPcSpy1.4.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy1.5/MagicLink_netPcSpy1.5.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy1.6/MagicLink_netPcSpy1.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy2.0/MagicLink_netPcSpy2.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy2004_4.1/MagicLink_netPcSpy2004_4.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/MagicLink/MagicLink_netPcSpy2004_4.2/MagicLink_netPcSpy2004_4.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nbclass/Nbclass/Nbclass.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys1.0/netsys1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys1.5/netsys1.5.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys10.7/netsys10.7.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys2.0/netsys2.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys2.6/netsys2.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys2006/netsys2006.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys3.0/netsys3.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys3.6/netsys3.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys3.9/netsys3.9.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys4.0/netsys4.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys4.2/netsys4.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys4.6/netsys4.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys4.8/netsys4.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys5.0/netsys5.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys5.8/netsys5.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys6.0/netsys6.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys6.8/netsys6.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys7.0/netsys7.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys7.2/netsys7.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys7.6/netsys7.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys7.8/netsys7.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys8.0/netsys8.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys8.2/netsys8.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys8.3/netsys8.3.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys8.6/netsys8.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys8.7/netsys8.7.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys8.9/netsys8.9.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys9.0/netsys9.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys9.2/netsys9.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys9.6/netsys9.6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Netsys/netsys9.8/netsys9.8.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/2020重制养鸡/2020重制养鸡.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/CkDdos/CkDdos.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/jdahjksha34/jdahjksha34.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/lafgr/lafgr.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/万世轮回DDOS-Win集群端6/万世轮回DDOS-Win集群端6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/傀儡机驱动级复活DDoS攻击穿透破防版/傀儡机驱动级复活DDoS攻击穿透破防版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/大客户CC3.0/大客户CC3.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/天罚V7集群压力测试系统/天罚V7集群压力测试系统.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/天罚V8.1集群压力测试系统,密码ddos.tf/天罚V8.1集群压力测试系统,密码ddos.tf.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/守侯/守侯.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/新建文件夹/新建文件夹.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/无情修改版/无情修改版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/相约巴黎DDOS/相约巴黎DDOS.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Nitol/블랙디도스한글판/블랙디도스한글판.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/NjRat/RootRAT/яσσтRAT.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PcShare/PcShare/PcShare.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PlugX/FastCC/FastCC.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PlugX/FastGf/FastGf.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PlugX/FastGui(360)/FastGui(360).7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PlugX/PlugX/PlugX.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PoisonX/PX6.21/PX6.21.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/PoisonX/PX8.1/PX8.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Quasar/Quasar.v1.0.0.0/Quasar.v1.0.0.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Quasar/Quasar.v1.1.0.0/Quasar.v1.1.0.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Quasar/Quasar.v1.2.0.0/Quasar.v1.2.0.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Quasar/Quasar.v1.3.0.0/Quasar.v1.3.0.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Quasar/Quasar.v1.4.0/Quasar.v1.4.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Quasar/Quasar.v1.4.1/Quasar.v1.4.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Rejoice/【HACK学习内部】无后门不免杀远控/【HACK学习内部】无后门不免杀远控.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Rejoice/上兴远程控制20090405破解版/上兴远程控制20090405破解版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Rejoice/上兴远程控制5.1/上兴远程控制5.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/RemoteShut/Remoteshut1.1/Remoteshut1.1.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/RemoteShut/Remoteshut1.2/Remoteshut1.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/RemoteShut/Remoteshut1.4/Remoteshut1.4.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Revenger/Revenger0.2/Revenger0.2.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Revenger/Revenger1.0/Revenger1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Revenger/Revenger1.5/Revenger1.5.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Sainbox/4.0snips/4.0snips.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/Sainbox/远程管理系统4.0/远程管理系统4.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.0/SilentSpy2.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.05/SilentSpy2.05.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.06/SilentSpy2.06.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.07/SilentSpy2.07.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.08/SilentSpy2.08.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.09/SilentSpy2.09.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/SilentSpy2.10/SilentSpy2.10.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/Silentspy1.0/Silentspy1.0.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/Silentspy2.01/Silentspy2.01.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilentSpy/Silentspy2.02/Silentspy2.02.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilverFox/Quick定制版/Quick定制版.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilverFox/WinOS/winos.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilverFox/熊猫小恶魔远程管理/熊猫小恶魔.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SilverFox/版本4.0/Quick.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/SlhRat/Slh/Slh.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/TorCt/TorCT_6_22_1_6/TorCT_6_22_1_6.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ZDemon/Z-dem0n10/Z-dem0n10.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ZDemon/Z-dem0n11/Z-dem0n11.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ZDemon/Z-dem0n111/Z-dem0n111.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ZDemon/Z-dem0n12/Z-dem0n12.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ZDemon/Z-dem0n125/Z-dem0n125.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/ZDemon/Z-dem0n126/Z-dem0n126.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.001",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.002",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.003",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.004",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.005",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.006",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.007",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/Cobra/Cobra.7z.008",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.001",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.002",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.003",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.004",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.005",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.006",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.007",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/DesertRat/DesertRat.7z.008",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/UnlockRat/Unlock-Rat-V6.7z.001",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/UnlockRat/Unlock-Rat-V6.7z.002",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/UnlockRat/Unlock-Rat-V6.7z.003",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/UnlockRat/Unlock-Rat-V6.7z.004",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/UnlockRat/Unlock-Rat-V6.7z.005",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/CraxsRat/Mods/UnlockRat/Unlock-Rat-V6.7z.006",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/NjRat/Ziku/CRONOS_Rat/CRONOS_Rat.7z",
    "https://raw.githubusercontent.com/Cryakl/Ultimate-RAT-Collection/main/NjRat/Ziku/NJRat_0.7d_Ziku/NJRat_0.7d_Ziku.7z",
]

# ── STUN servers — UDP/3478 targets for VoIP/video app-ID simulation ──────────
# (host, port) tuples.  STUN magic cookie 0x2112A442 in the Binding Request
# payload is the primary fingerprint used by NGFW app-ID engines.
stun_servers = [
    ("stun.l.google.com",           19302),
    ("stun1.l.google.com",          19302),
    ("stun2.l.google.com",          19302),
    ("stun3.l.google.com",          19302),
    ("stun4.l.google.com",          19302),
    ("stun.cloudflare.com",          3478),
    ("stun.zoom.us",                 3478),
    ("stun.services.mozilla.com",    3478),
    ("stunserver.stunprotocol.org",  3478),
    ("stun.nextcloud.com",           3478),
    ("stun.sipnet.net",              3478),
    ("stun.ekiga.net",               3478),
    ("stun.ideasip.com",             3478),
    ("stun.antisip.com",             3478),
    ("stun.voip.blackberry.com",     3478),
]

# ── Public SIP servers — used for SIP OPTIONS probes (UDP/5060) ──────────────
# These are publicly-reachable SIP servers used for VoIP app-ID / UCaaS
# classification testing.  A SIP OPTIONS request is the standard "ping" used by
# SIP UAs to check if a server is alive and triggers SIP/VoIP signatures on
# NGFW and IDS platforms.
sip_servers = [
    ("sip.linphone.org",          5060),
    ("sip2.linphone.org",         5060),
    ("sip.sipgate.co.uk",         5060),
    ("sip.antisip.com",           5060),
    ("sip.zadarma.com",           5060),
    ("sip.freephoneline.ca",      5060),
    ("sip.voip.ms",               5060),
    ("sip.callcentric.com",       5060),
    ("sip.1und1.de",              5060),
    ("sip.blueface.com",          5060),
    ("pbx.myvoipapp.com",         5060),
    ("registrar.sip2sip.info",    5060),
]

# ── UCaaS signaling endpoints — VoIP/video URL-category identification ─────────
# HTTP requests to these URLs trigger "voice" / "video-conferencing" app-ID
# on platforms like Cato Networks, Prisma Access, and Palo Alto NGFW.
ucaas_endpoints = [
    # Zoom
    "https://zoom.us/",
    "https://zoom.us/j/",
    "https://api.zoom.us/v2/users/me",
    "https://zoom.us/wc/join/",
    # Microsoft Teams / Skype for Business
    "https://teams.microsoft.com/",
    "https://teams.microsoft.com/v2/",
    "https://config.teams.microsoft.com/config/v1/MicrosoftTeams",
    "https://presence.teams.microsoft.com/v1/me/forceavailability/",
    # Cisco WebEx
    "https://webex.com/",
    "https://webexapis.com/v1/rooms",
    "https://api.ciscospark.com/v1/rooms",
    "https://webex.com/meet/",
    # Google Meet / Duo
    "https://meet.google.com/",
    "https://meet.google.com/api/",
    "https://duo.google.com/",
    # Slack huddles / calls
    "https://slack.com/",
    "https://slack.com/api/calls.add",
    "https://api.slack.com/methods/calls.add",
    # RingCentral
    "https://app.ringcentral.com/",
    "https://platform.ringcentral.com/restapi/v1.0/account",
    # 8x8
    "https://app.8x8.com/",
    "https://api.8x8.com/",
    # GoTo Meeting
    "https://global.gotomeeting.com/",
    "https://api.getgo.com/G2M/rest/meetings",
    # Discord (voice channels)
    "https://discord.com/",
    "https://discord.com/api/v10/voice/regions",
    # WhatsApp / Meta Calls
    "https://web.whatsapp.com/",
    "https://www.whatsapp.com/download",
    # Apple FaceTime
    "https://facetime.apple.com/",
    "https://vc.icloud.com/",
    # Vonage / Twilio
    "https://api.vonage.com/",
    "https://api.twilio.com/2010-04-01/Accounts",
    # Jitsi
    "https://meet.jit.si/",
    "https://8x8.vc/",
]

# ── BGP peering neighbors ─────────────────────────────────────────────────────
bgp_neighbors = [
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "12.12.12.12",
    "192.168.168.1",
]

# ── Post-quantum TLS (Kyber/ML-KEM) endpoints ────────────────────────────────
# Point at an internal server running OQS-OpenSSL or similar PQC stack.
# The generator opens multiple TLS sessions per run; add more IPs/ports as needed.
kyber_endpoints = [
    "https://172.22.10.112:4433",
]

# ---------------------------------------------------------------------------
# DNS over HTTPS (DoH) providers — RFC 8484 JSON API endpoints
# ---------------------------------------------------------------------------
doh_providers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.cleanbrowsing.org/doh/family-filter/",
    "https://dns.nextdns.io",
    "https://doh.dns.sb/dns-query",
    "https://rdns.ipv64.net/dns-query",
    "https://dns.adguard-dns.com/dns-query",
    "https://unfiltered.adguard-dns.com/dns-query",
]

# ---------------------------------------------------------------------------
# DNS over TLS (DoT) servers — list of (ip, tls_servername) tuples
# Used by openssl s_client to open TCP/853 and complete the TLS handshake
# ---------------------------------------------------------------------------
dot_servers = [
    ("1.1.1.1",         "cloudflare-dns.com"),
    ("1.0.0.1",         "cloudflare-dns.com"),
    ("8.8.8.8",         "dns.google"),
    ("8.8.4.4",         "dns.google"),
    ("9.9.9.9",         "dns.quad9.net"),
    ("149.112.112.112", "dns.quad9.net"),
    ("208.67.222.222",  "dns.opendns.com"),
    ("208.67.220.220",  "dns.opendns.com"),
    ("94.140.14.14",    "dns.adguard-dns.com"),
    ("94.140.15.15",    "dns.adguard-dns.com"),
]

# ---------------------------------------------------------------------------
# C2 beacon targets — public test/echo services used to simulate C2 check-ins.
# All targets accept arbitrary POSTs and return the payload (200/OK), making
# them ideal for C2 detection rule validation without live infrastructure.
# ---------------------------------------------------------------------------
c2_beacon_targets = [
    # Classic IDS trigger
    "http://www.testmyids.com",
    "https://www.testmyids.com",

    # httpbin — full request echo (POST body, headers, JSON visible to DLP/IDS)
    "https://httpbin.org/post",
    "https://httpbin.org/anything",
    "https://httpbin.org/anything/gate.php",        # matches ET TROJAN path patterns
    "https://httpbin.org/anything/update.php",
    "https://httpbin.org/anything/checkin",
    "https://httpbin.org/base64/dGVzdA==",          # base64 path — common in implants
    "https://httpbin.org/delay/1",                  # slow response mimics staging server
    "https://httpbin.org/uuid",                     # UUID response used as session token

    # Postman echo — mirrors full request back
    "https://postman-echo.com/post",
    "https://postman-echo.com/post?r=config.php",

    # requestbin / pipedream — public webhook collectors
    "https://public.requestbin.com/r/dummy",
    "https://en2s9vxjkrn2.x.pipedream.net",

    # Transfer.sh — free file-upload service abused by malware for staging
    "https://transfer.sh/",
]

# ---------------------------------------------------------------------------
# DNS exfil simulation domains — queries are sent with long base32-encoded
# subdomains (e.g. ABCDEF123.example.com) to mimic DNS tunnelling traffic
# ---------------------------------------------------------------------------
dns_exfil_domains = [
    "testmyids.com",
    "scanme.nmap.org",
    "neverssl.com",
    "info.cern.ch",
    "example.com",
    "example.org",
    "example.net",
    "test.example.com",
    "dns-test.net",
    "dnsleaktest.com",
]

# ---------------------------------------------------------------------------
# LLM API endpoints — REST API paths for major AI providers.
# Grouped by provider; requests return 401/403 (no real auth) but the
# URL + payload are fully visible to DLP and AI-category URL filters.
#
# Provider-specific formats handled in generator.py:
#   - OpenAI-compatible  : {"model":..., "messages":[...], "max_tokens":...}
#   - Anthropic          : same body + anthropic-version / x-api-key headers
#   - Google Gemini      : {"contents":[{"parts":[{"text":...}]}], ...}
#   - Cohere             : {"model":..., "message":..., "max_tokens":...}
# ---------------------------------------------------------------------------
llm_api_endpoints = [
    # ── OpenAI / ChatGPT ────────────────────────────────────────────────────
    "https://api.openai.com/v1/chat/completions",
    "https://api.openai.com/v1/completions",
    "https://api.openai.com/v1/embeddings",
    "https://api.openai.com/v1/images/generations",

    # ── Anthropic / Claude ──────────────────────────────────────────────────
    "https://api.anthropic.com/v1/messages",
    "https://api.anthropic.com/v1/complete",

    # ── Google Gemini / PaLM ────────────────────────────────────────────────
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",

    # ── Microsoft Azure OpenAI ──────────────────────────────────────────────
    # Generic patterns; real deployments use tenant-specific subdomains.
    "https://api.cognitive.microsoft.com/openai/deployments/gpt-4/chat/completions",
    "https://eastus.api.cognitive.microsoft.com/openai/deployments/gpt-4o/chat/completions",

    # ── Microsoft Copilot ───────────────────────────────────────────────────
    "https://copilot.microsoft.com/api/chat",
    "https://sydney.bing.com/sydney/ChatHub",

    # ── Perplexity AI ───────────────────────────────────────────────────────
    "https://api.perplexity.ai/chat/completions",

    # ── Meta / Llama ────────────────────────────────────────────────────────
    "https://api.llama-api.com/chat/completions",
    "https://llama.developer.meta.com/api/chat/completions",

    # ── Mistral AI ──────────────────────────────────────────────────────────
    "https://api.mistral.ai/v1/chat/completions",
    "https://api.mistral.ai/v1/embeddings",

    # ── Cohere ──────────────────────────────────────────────────────────────
    "https://api.cohere.ai/v1/chat",
    "https://api.cohere.ai/v1/generate",
    "https://api.cohere.com/v2/chat",

    # ── xAI / Grok ──────────────────────────────────────────────────────────
    "https://api.x.ai/v1/chat/completions",

    # ── DeepSeek ────────────────────────────────────────────────────────────
    "https://api.deepseek.com/v1/chat/completions",

    # ── Groq ────────────────────────────────────────────────────────────────
    "https://api.groq.com/openai/v1/chat/completions",

    # ── Together AI ─────────────────────────────────────────────────────────
    "https://api.together.xyz/v1/chat/completions",
    "https://api.together.ai/v1/chat/completions",

    # ── Fireworks AI ────────────────────────────────────────────────────────
    "https://api.fireworks.ai/inference/v1/chat/completions",

    # ── OpenRouter (multi-provider gateway) ─────────────────────────────────
    "https://openrouter.ai/api/v1/chat/completions",

    # ── Amazon Bedrock ──────────────────────────────────────────────────────
    "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet-20240229-v1:0/invoke",
    "https://bedrock-runtime.us-east-1.amazonaws.com/model/amazon.titan-text-express-v1/invoke",
    "https://bedrock-runtime.us-west-2.amazonaws.com/model/meta.llama3-70b-instruct-v1:0/invoke",

    # ── Hugging Face Inference API ──────────────────────────────────────────
    "https://api-inference.huggingface.co/models/meta-llama/Llama-3.3-70B-Instruct",
    "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3",

    # ── Smaller / emerging providers ────────────────────────────────────────
    "https://api.ai21.com/studio/v1/chat/completions",
    "https://api.cerebras.ai/v1/chat/completions",
    "https://api.writer.com/v1/llm/chat",
    "https://api.scale.com/v1/chat",
    "https://inference.friendli.ai/v1/chat/completions",
    "https://api.nvidia.com/v1/chat/completions",
]

# ---------------------------------------------------------------------------
# LLM web UI endpoints — browser-facing URLs for major AI applications.
# Used for HEAD requests to exercise AI-category URL-filtering rules and
# Cato Networks AI Security app-discovery signatures.
# Covers: text generation, code generation, image generation, enterprise AI.
# ---------------------------------------------------------------------------
llm_web_endpoints = [
    # ── Text / chat ─────────────────────────────────────────────────────────
    "https://chat.openai.com",
    "https://chatgpt.com",
    "https://claude.ai",
    "https://claude.ai/new",
    "https://gemini.google.com",
    "https://bard.google.com",
    "https://copilot.microsoft.com",
    "https://perplexity.ai",
    "https://www.perplexity.ai",
    "https://poe.com",
    "https://you.com",
    "https://pi.ai",
    "https://character.ai",
    "https://beta.character.ai",
    "https://chat.deepseek.com",
    "https://grok.x.ai",
    "https://grok.com",
    "https://chat.mistral.ai",
    "https://coral.cohere.com",
    "https://meta.ai",
    "https://huggingface.co/chat",
    "https://lmsys.org/chat",
    "https://groq.com",

    # ── Code generation ─────────────────────────────────────────────────────
    "https://github.com/features/copilot",
    "https://copilot.github.com",
    "https://cursor.com",
    "https://www.cursor.com",
    "https://codeium.com",
    "https://tabnine.com",
    "https://replit.com/ai",
    "https://www.codewhisperer.aws",
    "https://aws.amazon.com/q/developer",

    # ── Image generation ────────────────────────────────────────────────────
    "https://midjourney.com",
    "https://www.midjourney.com",
    "https://platform.stability.ai",
    "https://stability.ai",
    "https://labs.openai.com",
    "https://firefly.adobe.com",
    "https://www.adobe.com/products/firefly.html",
    "https://leonardo.ai",
    "https://ideogram.ai",
    "https://playground.com",
    "https://www.bing.com/images/create",

    # ── Enterprise / productivity AI ────────────────────────────────────────
    "https://www.notion.so/product/ai",
    "https://slack.com/features/ai",
    "https://workspace.google.com/products/gemini",
    "https://microsoft365.com/copilot",
    "https://einstein.salesforce.com",
    "https://aws.amazon.com/bedrock",
    "https://azure.microsoft.com/en-us/products/ai-services/openai-service",
]

# ── S3 / Cloud Object Storage ─────────────────────────────────────────────────
#
# s3_download_urls: GET targets — mix of public AWS datasets and private-bucket
#   URLs.  Public ones return 200/XML; private ones return 403 AccessDenied.
#   Both generate CASB-visible S3 GET traffic.
#
# s3_upload_targets: PUT targets — realistic bucket/key paths.  All return 403
#   (no credentials) but the upload attempt + payload is visible to DLP/CASB.
#   Payloads are chosen in generator.py from a set of synthetic PII / secret
#   strings designed to trigger DLP content-inspection rules.

s3_download_urls: list[str] = [
    # Public AWS datasets — may return 200 with XML listing or object data
    "https://commoncrawl.s3.amazonaws.com/crawl-data/CC-MAIN-2023-50/warc.paths.gz",
    "https://noaa-goes16.s3.amazonaws.com/",
    "https://sentinel-s2-l1c.s3.amazonaws.com/",
    "https://s3.amazonaws.com/tripdata/",
    "https://landsat-pds.s3.amazonaws.com/",
    "https://aws-earth-mo-atmospheric-mogreps-uk-prd.s3.amazonaws.com/",
    # Private / corporate-style buckets — 403 expected, S3 traffic generated
    "https://s3.amazonaws.com/corporate-data-exports/report-2024-q4.csv",
    "https://company-backups.s3.amazonaws.com/full-backup-latest.tar.gz",
    "https://prod-db-snapshots.s3.us-west-2.amazonaws.com/snapshot-20241201.sql.gz",
    "https://s3.us-east-1.amazonaws.com/hr-records/employees.xlsx",
    "https://internal-docs.s3.amazonaws.com/architecture-overview.pdf",
    "https://app-logs.s3.us-east-2.amazonaws.com/logs/2024/11/app.log.gz",
    "https://my-website-assets.s3.amazonaws.com/images/banner.jpg",
    "https://s3.eu-west-1.amazonaws.com/gdpr-exports/data-subject-export.zip",
    # S3-compatible storage providers
    "https://s3.wasabisys.com/",
    "https://s3.us-west-002.backblazeb2.com/",
]

s3_upload_targets: list[str] = [
    # AWS S3 — realistic bucket/key paths for PUT simulation
    # All return 403 (no credentials) but the upload traffic is CASB/DLP visible
    "https://s3.amazonaws.com/data-exfil-test/financial-records.csv",
    "https://s3.amazonaws.com/backup-bucket-prod/sensitive-data.zip",
    "https://s3.us-east-1.amazonaws.com/corp-uploads/employee-list.xlsx",
    "https://uploads.s3.us-west-2.amazonaws.com/user-data/pii-export.json",
    "https://company-archive.s3.amazonaws.com/2024/confidential.tar.gz",
    "https://s3.amazonaws.com/cloud-sync/credentials.env",
    "https://s3.eu-west-1.amazonaws.com/gdpr-data/personal-records.csv",
    "https://s3.amazonaws.com/dev-artifacts/source-code.zip",
    "https://data-lake.s3.us-east-2.amazonaws.com/raw/customer-dump.parquet",
    "https://s3.ap-southeast-1.amazonaws.com/offshore-backup/db-export.sql.gz",
    # S3-compatible storage providers
    "https://s3.wasabisys.com/exfil-test-bucket/payload.bin",
    "https://s3.us-west-002.backblazeb2.com/traffgen-test/upload.dat",
]

# ── Shadow IT / unsanctioned cloud-app endpoints (shadow_it) ──────────────────
# CASB / SSE platforms (Zscaler, Netskope, Cato, Prisma) categorise these as
# personal file sharing, personal messaging, crypto, or shadow IT.  HEAD
# requests exercise app-control policies without uploading any data.
shadow_it_endpoints: list[str] = [
    # Personal cloud storage — "personal file sharing" CASB category
    "https://www.dropbox.com",
    "https://www.box.com",
    "https://mega.nz",
    "https://wetransfer.com",
    "https://transfer.sh",
    "https://onedrive.live.com",        # Microsoft consumer (not M365 corporate)
    "https://www.icloud.com",
    # Personal messaging / collaboration
    "https://discord.com",
    "https://web.telegram.org",
    "https://web.whatsapp.com",
    # Anonymising / privacy-first mail
    "https://proton.me",
    "https://tutanota.com",
    "https://guerrillamail.com",
    # Paste / file hosting (data-exfil category)
    "https://pastebin.com",
    "https://filebin.net",
    "https://gofile.io",
    # Crypto / blockchain (often blocked by financial/enterprise policy)
    "https://www.coinbase.com",
    "https://etherscan.io",
    "https://www.binance.com",
    # Unsanctioned productivity / no-code tools
    "https://notion.so",
    "https://trello.com",
    "https://www.airtable.com",
]

# ── Tor / anonymiser / VPN landing pages (tor_anonymizer) ────────────────────
# URL-filter "anonymizers" or "proxy avoidance" category on every major NGFW,
# SASE, and DNS-filter vendor (Cisco Umbrella, Palo Alto, Fortinet, Zscaler).
tor_anonymizer_endpoints: list[str] = [
    "https://check.torproject.org",
    "https://www.torproject.org",
    "https://protonvpn.com",
    "https://nordvpn.com",
    "https://mullvad.net",
    "https://www.expressvpn.com",
    "https://www.ipvanish.com",
    "https://kproxy.com",
    "https://hide.me",
    "https://hidemy.name",
    "https://www.anonymouse.org",
    "https://filterbypass.me",
    "https://www.croxyproxy.com",
    "https://www.proxysite.com",
    "https://4everproxy.com",
    "https://www.freeproxyserver.net",
]

# ── WAF-attack test targets ───────────────────────────────────────────────────
# Intentionally-vulnerable / pen-test-authorised web applications used as
# targets for WAF-bypass probes.  Do NOT add production sites.
waf_attack_targets: list[str] = [
    "https://juice-shop.herokuapp.com",
    "http://www.testmyids.com",
    "https://hackazon.webscantest.com",
    "http://testhtml5.vulnweb.com",
]

# ── HTTP data-exfil paste/upload targets (data_exfil_http) ───────────────────
# Public paste and file-drop services used by attackers to exfiltrate data via
# HTTP POST.  DLP and CASB inline inspectors should catch requests to these
# destinations containing PII / credential patterns.
data_exfil_targets: list[str] = [
    "https://pastebin.com/api/api_post.php",
    "https://hastebin.com/documents",
    "https://paste2.org/new-paste",
    "https://transfer.sh/upload",
    "https://filebin.net",
    "https://api.paste.fo/v1/pastes",
]
