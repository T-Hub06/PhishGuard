import datetime
import difflib
import io
import re
import socket
import ssl
from urllib.parse import urlparse
import cv2
import numpy as np
from PIL import Image
import requests

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

TARGET_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'netflix', 'paypal',
    'facebook', 'instagram', 'whatsapp', 'twitter', 'linkedin',
    'spotify', 'dropbox', 'adobe', 'ebay', 'walmart', 'sbi',
    'hdfc', 'icici', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'paytm', 'phonepe', 'binance', 'coinbase',
    'telegram', 'github', 'yahoo', 'flipkart', 'steam'
]
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u03bf': 'o', '\u03c5': 'u', '\u03bd': 'v'
}


def _extract_domain(hostname):
    """Strip subdomains and TLD to isolate the core domain brand name."""
    parts = hostname.lower().split('.')
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-1] in ['in', 'uk', 'au', 'br', 'za'] and parts[-2] in ['co', 'com', 'gov', 'ac', 'org', 'edu']:
            return parts[-3], '.'.join(parts[-3:])
        return parts[-2], '.'.join(parts[-2:])
    return hostname.lower(), hostname.lower()

def get_domain_age(hostname):
    """
    Query WHOIS registry to determine domain creation date and age.
    """
    if not WHOIS_AVAILABLE:
        return {'status': 'unavailable', 'age_days': None, 'message': 'whois library not installed'}

    _, root_domain = _extract_domain(hostname)
    try:
        w = whois.whois(root_domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {'status': 'unknown', 'age_days': None, 'message': 'No creation date in registry'}
        if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        now = datetime.datetime.now()
        age_days = (now - creation_date).days
        is_young = age_days < 30

        return {
            'status': 'ok',
            'creation_date': creation_date.strftime('%Y-%m-%d'),
            'age_days': max(0, age_days),
            'age_years': round(max(0, age_days) / 365.25, 1),
            'is_young_domain': is_young,
            'registrar': str(w.registrar) if w.registrar else 'Unknown',
            'root_domain': root_domain
        }
    except Exception as e:
        return {'status': 'error', 'age_days': None, 'message': f'WHOIS query failed or private ({str(e)[:50]})'}


def check_dns_mx(hostname):
    """
    Check if the domain has configured Mail Exchange (MX) DNS records.
    Legitimate corporate websites configure email; throwaway phishing domains rarely do.
    """
    if not DNS_AVAILABLE:
        return {'status': 'unavailable', 'has_mx': False, 'message': 'dnspython not installed'}

    _, root_domain = _extract_domain(hostname)
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.5
        resolver.timeout = 2.0
        records = resolver.resolve(root_domain, 'MX')
        mx_list = [str(r.exchange).rstrip('.') for r in records]
        return {
            'status': 'ok',
            'has_mx': len(mx_list) > 0,
            'mx_records': mx_list[:3]
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {'status': 'none', 'has_mx': False, 'mx_records': []}
    except Exception as e:
        return {'status': 'error', 'has_mx': False, 'message': str(e)[:50]}


def check_ssl_certificate(hostname, port=443):
    """
    Connect via TLS/SSL socket and inspect certificate authority and validity.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                issuer = dict(x[0] for x in cert.get('issuer', []))
                common_name = issuer.get('commonName', 'Unknown Authority')
                org = issuer.get('organizationName', common_name)

                expires_dt = None
                expires_in_days = None
                if not_after:
                    expires_dt = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (expires_dt - datetime.datetime.utcnow()).days

                return {
                    'status': 'valid',
                    'has_ssl': True,
                    'issuer': org,
                    'expires_in_days': expires_in_days,
                    'message': 'Trusted SSL Certificate'
                }
    except ssl.SSLCertVerificationError as e:
        return {'status': 'invalid', 'has_ssl': False, 'issuer': 'Untrusted', 'message': f'Invalid/Self-signed SSL: {str(e)[:40]}'}
    except Exception as e:
        return {'status': 'none', 'has_ssl': False, 'issuer': 'None', 'message': f'No SSL on port 443 ({str(e)[:40]})'}


def unroll_url_redirects(url):
    """
    Trace HTTP 301/302 redirects to unmask shortened or cloaked URLs.
    """
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        target = 'http://' + url
    else:
        target = url

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    try:
        response = requests.get(target, allow_redirects=True, timeout=4.0, headers=headers, stream=True)
        history = [resp.url for resp in response.history]
        final_url = response.url
        response.close()

        return {
            'original_url': target,
            'final_url': final_url,
            'redirect_count': len(history),
            'hops': history + [final_url] if history else [final_url],
            'is_redirected': len(history) > 0
        }
    except Exception as e:
        return {
            'original_url': target,
            'final_url': target,
            'redirect_count': 0,
            'hops': [target],
            'is_redirected': False,
            'error': str(e)[:60]
        }

def levenshtein_distance(s1, s2):
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_typosquatting(hostname):
    """
    Detect if the domain is typosquatting or visually impersonating a high-value brand.
    Checks full domain as well as hyphen/underscore separated tokens (e.g. arnazon-support).
    """
    core_name, root_domain = _extract_domain(hostname)
    clean_core = re.sub(r'[^a-zA-Z0-9]', '', core_name)

    if clean_core in TARGET_BRANDS and (root_domain.endswith(('.com', '.org', '.net', '.in', '.co.in', '.gov.in'))):
        return {
            'is_typosquat': False,
            'targeted_brand': None,
            'similarity': 1.0,
            'message': 'Official root brand domain'
        }

    tokens = [t for t in re.split(r'[-_.]', hostname.lower()) if t]
    tokens.append(clean_core)

    for brand in TARGET_BRANDS:
        if (brand in core_name and core_name != brand) or (f"{brand}-" in hostname) or (f"-{brand}" in hostname):
            return {
                'is_typosquat': True,
                'targeted_brand': brand.upper(),
                'similarity': 0.95,
                'message': f'Brand Keyword Affixation detected (mimicking {brand.upper()})'
            }
        for token in set(tokens):
            clean_tok = re.sub(r'[^a-zA-Z0-9]', '', token)
            if not clean_tok or len(clean_tok) < 3:
                continue

            dist = levenshtein_distance(clean_tok, brand)
            ratio = difflib.SequenceMatcher(None, clean_tok, brand).ratio()

            if (dist in [1, 2] and len(clean_tok) >= 4 and clean_tok != brand) or (ratio >= 0.80 and clean_tok != brand):
                return {
                    'is_typosquat': True,
                    'targeted_brand': brand.upper(),
                    'similarity': round(ratio, 2),
                    'message': f'Typosquatting detected: "{clean_tok}" is {round(ratio*100)}% similar to {brand.upper()}'
                }

    return {
        'is_typosquat': False,
        'targeted_brand': None,
        'similarity': 0.0,
        'message': 'No brand typosquatting detected'
    }


def detect_homoglyphs(url):
    """
    Detect IDN Homograph attacks and Punycode spoofing (e.g. Cyrillic letters spoofing Latin).
    """
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
    hostname = parsed.hostname or ''
    if 'xn--' in hostname.lower():
        try:
            decoded = hostname.encode('ascii').decode('idna')
            return {
                'has_homoglyph': True,
                'is_punycode': True,
                'decoded': decoded,
                'message': f'IDN Punycode attack detected! Decoded domain: "{decoded}"'
            }
        except Exception:
            return {
                'has_homoglyph': True,
                'is_punycode': True,
                'decoded': hostname,
                'message': 'Suspicious encoded Punycode domain detected'
            }
    confusables_found = []
    for char in hostname:
        if char in HOMOGLYPH_MAP:
            confusables_found.append((char, HOMOGLYPH_MAP[char]))

    if confusables_found:
        samples = ', '.join([f"'{c}'->'{HOMOGLYPH_MAP[c]}'" for c, _ in confusables_found[:3]])
        return {
            'has_homoglyph': True,
            'is_punycode': False,
            'confusables': confusables_found,
            'message': f'Cyrillic/Greek Homoglyphs detected ({samples})'
        }

    return {
        'has_homoglyph': False,
        'is_punycode': False,
        'message': 'Clean character set (standard ASCII)'
    }


def _decode_with_any_detector(img):
    """
    Try every QR detector OpenCV offers and return the first payload found.
    QRCodeDetectorAruco is tried first because it is more robust (and the
    classic QRCodeDetector is unreliable in OpenCV 5.0). Any detector that
    raises an error is skipped instead of aborting the whole scan.
    """
    detectors = []
    if hasattr(cv2, 'QRCodeDetectorAruco'):
        detectors.append(cv2.QRCodeDetectorAruco())
    detectors.append(cv2.QRCodeDetector())

    for detector in detectors:
        try:
            data, _, _ = detector.detectAndDecode(img)
            if data and data.strip():
                return data.strip()
        except Exception:
            continue
    return None


def decode_qr_image(image_input):
    """
    Decode QR code from an uploaded image file, bytes, or PIL Image.
    Tries several detectors and image preprocessing variants.
    """
    try:
        if isinstance(image_input, (bytes, bytearray)):
            nparr = np.frombuffer(image_input, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        elif hasattr(image_input, 'read'):
            image_bytes = image_input.read()
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        elif isinstance(image_input, Image.Image):
            img = cv2.cvtColor(np.array(image_input.convert('RGB')), cv2.COLOR_RGB2BGR)
        elif isinstance(image_input, str):
            img = cv2.imread(image_input)
        else:
            return {'success': False, 'url': None, 'error': 'Unsupported image format'}

        if img is None:
            return {'success': False, 'url': None, 'error': 'Failed to decode image data'}

        img = np.ascontiguousarray(img, dtype=np.uint8)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        variants = [img, gray]
        if max(gray.shape) < 600:
            variants.append(cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
        thresh = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        thresh = np.ascontiguousarray((np.asarray(thresh) > 0).astype(np.uint8) * 255)
        variants.append(thresh)

        for variant in variants:
            url = _decode_with_any_detector(variant)
            if url:
                return {'success': True, 'url': url, 'error': None}

        return {
            'success': False,
            'url': None,
            'error': 'No QR code could be found or decoded in the image'
        }
    except Exception as e:
        return {'success': False, 'url': None, 'error': f'QR scanning error: {str(e)}'}