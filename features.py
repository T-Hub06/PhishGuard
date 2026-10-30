import ipaddress
import math
import os
import time
import urllib.request
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'secure', 'bank', 'pay',
    'confirm', 'signin', 'password', 'wallet', 'alert', 'urgent',
    'suspend', 'kyc', 'netbanking', 'billing', 'support', 'token',
    'claim', 'reward', 'security', 'unlock', 'portal', 'auth'
]

_SHORTENER_FALLBACK = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorte.st',
    'v.gd', 'clck.ru', 'rb.gy', 's.gy', 'short.io',
    'shorturl.at', 'tiny.cc', 't.ly', 'qr.io', 'zws.im',
    'bl.ink', 'hyperurl.co', 'urlzs.com'
]

_SHORTENER_LIST_URL = (
    "https://raw.githubusercontent.com/"
    "PeterDaveHello/url-shorteners/master/list"
)

_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "shorteners_cache.txt"
)
_CACHE_TTL = 86400

def _load_shorteners():
    if os.path.exists(_CACHE_PATH):
        age = time.time() - os.path.getmtime(_CACHE_PATH)
        if age < _CACHE_TTL:
            with open(_CACHE_PATH, encoding='utf-8') as f:
                domains = [
                    l.strip().lower() for l in f
                    if l.strip() and not l.startswith('#')
                ]
            if domains:
                return sorted(set(domains) | set(_SHORTENER_FALLBACK))
    try:
        with urllib.request.urlopen(_SHORTENER_LIST_URL, timeout=5) as r:
            content = r.read().decode('utf-8')
        os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
        with open(_CACHE_PATH, 'w', encoding='utf-8') as f:
            f.write(content)
        domains = [
            l.strip().lower() for l in content.splitlines()
            if l.strip() and not l.startswith('#')
        ]
        return sorted(set(domains) | set(_SHORTENER_FALLBACK))
    except Exception:
        return _SHORTENER_FALLBACK

SHORTENERS = _load_shorteners()
_SHORTENER_SET = frozenset(SHORTENERS)

def _is_shortener(hostname):
    parts = hostname.split('.')
    return any('.'.join(parts[i:]) in _SHORTENER_SET for i in range(len(parts) - 1))

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.work', '.click', '.link', '.country', '.stream',
    '.gdn', '.mom', '.buzz', '.monster', '.rest'
]

FEATURE_NAMES = ['url_length','hostname_length','num_dots','num_hyphens','num_digits','num_special',
    'has_ip','uses_https','num_subdomains','has_suspicious_keyword','has_shortener','suspicious_tld',
    'path_depth','query_length','has_at_symbol','entropy','digit_ratio','special_ratio'
]

def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def calculate_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def extract_features(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        parsed_url = 'http://' + url
    else:
        parsed_url = url

    parsed = urlparse(parsed_url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    lower_url = url.lower()
    lower_host = hostname.lower()

    url_len = max(len(url), 1)
    num_digits = sum(c.isdigit() for c in url)
    special_chars = ['@', '?', '=', '&', '%', '#', ';', '_', '~', '!']
    num_special = sum(url.count(c) for c in special_chars)

    features = {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_digits': num_digits,
        'num_special': num_special,
        'has_ip': 1 if _is_ip(hostname) else 0,
        'uses_https': 1 if parsed.scheme == 'https' else 0,
        'num_subdomains': max(0, hostname.count('.') - 1),
        'has_suspicious_keyword': 1 if any(k in lower_url for k in SUSPICIOUS_KEYWORDS) else 0,
        'has_shortener': 1 if _is_shortener(lower_host) else 0,
        'suspicious_tld': 1 if any(lower_host.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
        'path_depth': len([p for p in path.split('/') if p]),
        'query_length': len(query),
        'has_at_symbol': 1 if '@' in url else 0,
        'entropy': round(calculate_entropy(url), 4),
        'digit_ratio': round(num_digits / url_len, 4),
        'special_ratio': round(num_special / url_len, 4)
    }
    return features