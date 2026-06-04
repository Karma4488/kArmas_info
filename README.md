# kArmas_info

pip install requests beautifulsoup4 colorama tqdm dnspython

# Basic scan
python kArmas_info.py -u https://example.com

# Deep scan with more threads
python kArmas_info.py -u https://example.com -d 3 -t 20

# Through a proxy (Burp Suite etc.)
python kArmas_info.py -u https://example.com --proxy http://127.0.0.1:8080

# With auth cookies
python kArmas_info.py -u https://example.com --cookies "session=abc123"


Recon Phase (before crawling)
DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
IP resolution, robots.txt & sitemap.xml parsing
Wayback Machine archived URL harvesting
Deep Crawl Engine
Multithreaded recursive crawler with configurable depth
Inline JS file fetching & analysis
Proxy, cookie, and delay support
Intelligence Extraction
Emails, phone numbers
Social profiles: Facebook, Twitter/X, Instagram, LinkedIn, GitHub, YouTube, TikTok
API key detection: Google, AWS, GitHub, Stripe, Slack, JWT, generic
Password pattern detection
IP addresses, subdomains
S3 buckets, internal paths, HTML/JS comments
File Discovery — docs, archives, data files, config files, certs, images, media
Fingerprinting — 20+ technologies detected (WordPress, React, Django, Cloudflare, etc.) plus full HTTP header analysis
Export — JSON + TXT + CSV output automatically saved
