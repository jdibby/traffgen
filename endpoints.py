#!/usr/bin/env python

dns_endpoints = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "208.67.220.220",
    "208.67.222.222",
    "149.112.112.112",
    "9.9.9.9",
    ]

dns_urls = [
    "accounts.google.com",
    "adn.com",
    "adobe.com",
    "apple.com",
    "docs.google.com",
    "en.wikipedia.org",
    "openai.com",
    "github.com",
    "linkedin.com",
    "maps.google.com",
    "microsoft.com",
    "mozilla.org",
    "play.google.com",
    "plus.google.com",
    "sites.google.com",
    "www.att.com",
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

icmp_endpoints = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "172.30.0.1",
    "172.22.11.1",
    "192.168.1.1",
    "12.12.12.12",
    "208.67.220.220",
    "208.67.222.222",
    "9.9.9.9",
    "12.12.12.1",
    "139.130.4.5",
    "84.200.69.80",
    "84.200.70.40",
    "149.112.112.112",
    "68.87.85.98",
    "68.87.64.146",
    "68.105.28.11",
    "24.116.0.201",
    "24.116.0.202",
    "209.18.47.61",
    "209.18.47.62",
    "103.8.45.5",
    "103.8.46.5",
    "80.10.246.2",
    "80.10.246.129",
    ]

ntp_endpoints = [
    "1.ro.pool.ntp.org",
    "0.us.pool.ntp.org",
    "1.us.pool.ntp.org",
    "2.us.pool.ntp.org",
    "3.us.pool.ntp.org",
    "time.google.com",
    "time-a-g.nist.gov",
    "time-b-g.nist.gov",
    "time-c-g.nist.gov",
    "time-d-g.nist.gov",
    "time-d-g.nist.gov",
    "time-e-g.nist.gov",
    "time-e-g.nist.gov",
    "time-a-wwv.nist.gov",
    "time-b-wwv.nist.gov",
    "time-c-wwv.nist.gov",
    "time-d-wwv.nist.gov",
    "time-d-wwv.nist.gov",
    "time-e-wwv.nist.gov",
    "time-e-wwv.nist.gov",
    "time-a-b.nist.gov",
    "time-b-b.nist.gov",
    "time-c-b.nist.gov",
    "time-d-b.nist.gov",
    "time-d-b.nist.gov",
    "time-e-b.nist.gov",
    "time-e-b.nist.gov",
    "time.nist.gov",
    "utcnist.colorado.edu",
    "utcnist2.colorado.edu",
    "ag.pool.ntp.org",
    "ai.pool.ntp.org",
    "bb.pool.ntp.org",
    "bl.pool.ntp.org",
    "bm.pool.ntp.org",
    "bq.pool.ntp.org",
    "bz.pool.ntp.org",
    "ca.pool.ntp.org",
    "cr.pool.ntp.org",
    "dm.pool.ntp.org",
    "gd.pool.ntp.org",
    "gl.pool.ntp.org",
    "hn.pool.ntp.org",
    "ht.pool.ntp.org",
    "ky.pool.ntp.org",
    "mf.pool.ntp.org",
    "mx.pool.ntp.org",
    "ni.pool.ntp.org",
    "pa.pool.ntp.org",
    "sv.pool.ntp.org",
    "sx.pool.ntp.org",
    "vc.pool.ntp.org",
    "vg.pool.ntp.org",
    "vi.pool.ntp.org",
    ]

ssh_endpoints = [
    "12.12.12.12",
    "192.168.1.1",
    "10.177.177.1",
    "10.188.188.1",
    "10.199.199.1",
    "10.211.211.1",
    "192.168.2.1",
    "172.30.0.1",
    "192.168.2.2",
    ]

nmap_endpoints = [
    "192.168.2.2",
    "192.168.1.1",
    "172.16.0.1",
    "192.168.2.100",
    "192.168.2.200",
    "12.12.12.12",
    "172.30.0.1",
    "172.30.0.21",
    "192.168.2.3",
    ]

http_endpoints = [
    "www.facebook.com",
    "www.foxnews.com",
    "www.google.com",
    "www.linkedin.com",
    "www.spotify.com",
    "www.twitter.com",
    ]

https_endpoints = [
    "https://abcnews.go.com",
    "https://aboutads.info",
    "https://amazon.com",
    "https://aol.com",
    "https://apache.org",
    "https://bbc.co.uk",
    "https://bbc.com",
    "https://bloomberg.com",
    "https://bp.blogspot.com",
    "https://buydomains.com",
    "https://cloudflare.com",
    "https://cnn.com",
    "https://openai.com",
    "https://developers.google.com",
    "https://draft.blogger.com",
    "https://engadget.com",
    "https://es.wikipedia.org",
    "https://europa.eu",
    "https://feedburner.com",
    "https://forbes.com",
    "https://fr.wikipedia.org",
    "https://google.co.jp",
    "https://google.co.uk",
    "https://google.com.br",
    "https://google.de",
    "https://google.es",
    "https://google.ru",
    "https://hugedomains.com",
    "https://line.me",
    "https://live.com",
    "https://medium.com",
    "https://msn.com",
    "https://networkadvertising.org",
    "https://news.google.com",
    "https://nih.gov",
    "https://nytimes.com",
    "https://opera.com",
    "https://oracle.com",
    "https://paypal.com",
    "https://policies.google.com",
    "https://pt.wikipedia.org",
    "https://reuters.com",
    "https://theguardian.com",
    "https://tinyurl.com",
    "https://tools.google.com",
    "https://un.org",
    "https://uol.com.br",
    "https://w3.org",
    "https://washingtonpost.com",
    "https://whatsapp.com",
    "https://wikimedia.org",
    "https://wired.com",
    "https://www.foxnews.com",
    "https://www.google.com",
    "https://www.gov.uk",
    "https://www.linkedin.com",
    "https://www.imdb.com",
    "https://bbc.co.uk",
    "https://www.office.com",
    "https://www.huffingtonpost.com",
    "https://www.yahoo.com",
    ]

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25',
    'Mozilla/5.0 (Linux; U; Android 5.1; locale; device Build/build) AppleWebKit/webkit (KHTML, like Gecko) Version/4.0 Chrome/chrome Safari/safari',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko)',
    'Mozilla/5.0 (iPad; CPU OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13G36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 12_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 5.1; rv:36.0) Gecko/20100101 Firefox/36.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)',
    'Mozilla/5.0 (Windows NT 5.1; rv:33.0) Gecko/20100101 Firefox/33.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
    'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
]

# See description of these test files at https://www.eicar.org/?page_id=3950
eicar_http_endpoints = [
    "http://2016.eicar.org/download/eicar.com",
    "http://2016.eicar.org/download/eicar.com.txt",
    "http://2016.eicar.org/download/eicar_com.zip",
    "http://2016.eicar.org/download/eicarcom2.zip",
]

# See description of these test files at https://www.eicar.org/?page_id=3950
eicar_https_endpoints = [
    "https://secure.eicar.org/eicar.com",
    "https://secure.eicar.org/eicar.com.txt",
    "https://secure.eicar.org/eicar_com.zip",
    "https://secure.eicar.org/eicarcom2.zip",
]
