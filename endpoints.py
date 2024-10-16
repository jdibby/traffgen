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

icmp_endpoints = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "172.30.0.1",
    "172.16.0.1",
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
    "172.16.1.1",
    "10.10.10.1",
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
    "10.10.10.1",
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
    "neverssl.com",
    "www.linkedin.com",
    "www.spotify.com",
    "info.cern.ch",
    "www.twitter.com",
    ]

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
    "google-analytics.com",
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
    "https://peacocktv.com",
    "https://www.max.com",
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
    'Mozilla/5.0 (iPhone14,6; U; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19E241 Safari/602.1',
    'Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1',
    'Mozilla/5.0 (iPhone13,2; U; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1',
    'Mozilla/5.0 (iPhone12,1; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1',
    'Mozilla/5.0 (iPhone12,1; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/69.0.3497.105 Mobile/15E148 Safari/605.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/13.2b11866 Mobile/16A366 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1',
    'Mozilla/5.0 (iPhone9,3; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1',
    'Mozilla/5.0 (iPhone9,4; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1',
    'Mozilla/5.0 (Apple-iPhone7C2/1202.466; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3',
    'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254',
    'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; RM-1127_16056) AppleWebKit/537.36(KHTML, like Gecko) Chrome/42.0.2311.135 Mobile Safari/537.36 Edge/12.10536',
    'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.1058',
    'Mozilla/5.0 (Linux; Android 12; SM-X906C Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Lenovo YT-J706X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; SHIELD Tablet K1 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 7.0; SM-T827R4 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.116 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-T550 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 4.4.3; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/47.1.79 like Chrome/47.0.2526.80 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 5.0.2; LG-V410/V41020c Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/34.0.1847.118 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
    'Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1',
    'Dalvik/2.1.0 (Linux; U; Android 9; ADT-2 Build/PTT5.181126.002)',
    'Mozilla/5.0 (CrKey armv7l 1.5.16041) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.0 Safari/537.36',
    'Mozilla/5.0 (Linux; U; Android 4.2.2; he-il; NEO-X5-116A Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30',
    'Mozilla/5.0 (Linux; Android 9; AFTWMST22 Build/PS7233; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.152 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36',
    'Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus Player Build/MMB29T)',
    'Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15',
    'Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)',
    'Mozilla/5.0 (PlayStation Vita 3.61) AppleWebKit/537.73 (KHTML, like Gecko) Silk/3.2',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/20.02',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; XBOX_ONE_ED) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393',
    'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586',
    'Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/601.6 (KHTML, like Gecko) NF/4.0.0.5.10 NintendoBrowser/5.1.0.13343',
    'Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US',
    'Mozilla/5.0 (Nintendo 3DS; U; ; en) Version/1.7412.EU',
    'Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+',
    'Mozilla/5.0 (Linux; U; en-US) AppleWebKit/528.5+ (KHTML, like Gecko, Safari/528.5+) Version/4.0 Kindle/3.0 (screen 600x800; rotate)',
]

eicar_http_endpoints = [
    "http://2016.eicar.org/download/eicar.com",
    "http://2016.eicar.org/download/eicar.com.txt",
    "http://2016.eicar.org/download/eicar_com.zip",
    "http://2016.eicar.org/download/eicarcom2.zip",
]

eicar_https_endpoints = [
    "https://secure.eicar.org/eicar.com",
    "https://secure.eicar.org/eicar.com.txt",
    "https://secure.eicar.org/eicar_com.zip",
    "https://secure.eicar.org/eicarcom2.zip",
]
