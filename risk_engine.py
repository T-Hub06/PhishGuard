from urllib.parse import urlparse
from features import _is_shortener
from forensics import (
    get_domain_age,
    check_dns_mx,
    check_ssl_certificate,
    detect_typosquatting,
    detect_homoglyphs,
    unroll_url_redirects
)
def evaluate_url(url, ml_phish_prob=0.5):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = 'http://' + url
    else:
        url_with_scheme = url

    parsed = urlparse(url_with_scheme)
    hostname = parsed.hostname or ''
    redirect_info = unroll_url_redirects(url_with_scheme)
    final_url = redirect_info.get('final_url', url_with_scheme)
    final_hostname = urlparse(final_url).hostname or hostname
    whois_info = get_domain_age(final_hostname)
    dns_info = check_dns_mx(final_hostname)
    ssl_info = check_ssl_certificate(final_hostname)
    typo_info = detect_typosquatting(final_hostname)
    homo_info = detect_homoglyphs(final_url)

    score = ml_phish_prob * 40.0
    positives = []
    cautions = []
    dangers = []

    if typo_info['is_typosquat']:
        score += 35.0
        dangers.append(f"🚨 {typo_info['message']}")
    else:
        positives.append("✅ No brand typosquatting detected")

    if homo_info['has_homoglyph']:
        score += 35.0
        dangers.append(f"🚨 {homo_info['message']}")
    else:
        positives.append("✅ Standard ASCII character set (no Punycode/Homoglyph spoofing)")

    age_days = whois_info.get('age_days')
    if age_days is not None:
        if age_days < 14:
            score += 25.0
            dangers.append(f"🚨 Zero-Day Domain: Registered only {age_days} days ago ({whois_info.get('creation_date')})")
        elif age_days < 45:
            score += 15.0
            cautions.append(f"⚠️ Newly registered domain: {age_days} days old")
        elif age_days > 365:
            score -= 15.0
            positives.append(f"✅ Established domain ({whois_info.get('age_years')} years old, registered {whois_info.get('creation_date')})")
    else:
        cautions.append("⚠️ Domain age could not be verified via public WHOIS")

    if dns_info.get('has_mx'):
        score -= 5.0
        positives.append(f"✅ Active business email infrastructure (MX: {', '.join(dns_info.get('mx_records', [])[:2])})")
    elif dns_info.get('status') == 'none':
        score += 10.0
        cautions.append("⚠️ No Mail Exchange (MX) DNS records configured (often characteristic of throwaway domains)")

    if ssl_info.get('has_ssl'):
        score -= 5.0
        positives.append(f"✅ Trusted SSL Certificate issued by {ssl_info.get('issuer')} (expires in {ssl_info.get('expires_in_days', '?')} days)")
    else:
        if parsed.scheme == 'https':
            score += 15.0
            dangers.append(f"🚨 Invalid or untrusted SSL certificate ({ssl_info.get('message')})")
        else:
            score += 10.0
            cautions.append("⚠️ Plain HTTP connection (no SSL encryption)")

    if redirect_info.get('redirect_count', 0) > 1:
        score += 10.0
        cautions.append(f"⚠️ Multiple redirect hops detected ({redirect_info.get('redirect_count')} hops)")

    is_shortened = _is_shortener(hostname.lower())
    if is_shortened:
        score += 20.0
        cautions.append(f"⚠️ URL shortener detected ({hostname}) - the real destination is hidden behind the short link")
        if redirect_info.get('error') or not redirect_info.get('is_redirected'):
            score += 10.0
            cautions.append("⚠️ Shortened link could not be resolved to a destination")
        else:
            cautions.append(f"🔗 Resolved destination: {final_url}")

    if is_shortened:
        score = max(score, 31.0)

    risk_score = round(max(0.0, min(100.0, score)), 1)

    if risk_score <= 30.0:
        verdict = "Low Risk (Safe)"
        tier = "safe"
        color = "#2ecc71"
        icon = "🟢"
        if age_days is not None and age_days > 365:
            summary = "This URL appears clean and legitimate with established domain credentials."
        else:
            summary = ("No strong phishing indicators were found, but the domain is not "
                       "long-established or its age could not be verified. Stay cautious "
                       "with logins and payments.")
    elif risk_score <= 65.0:
        verdict = "Medium Risk (Caution)"
        tier = "caution"
        color = "#f39c12"
        icon = "🟡"
        summary = "Exercise caution. The domain exhibits unverified or newly registered attributes, but no conclusive brand impersonation."
    else:
        verdict = "High Risk (Phishing)"
        tier = "phishing"
        color = "#e74c3c"
        icon = "🔴"
        summary = "Dangerous URL detected! Multiple critical threat indicators (brand spoofing, zero-day registration, or high lexical anomaly) were identified."

    return {
        'url': url,
        'final_url': final_url,
        'hostname': final_hostname,
        'risk_score': risk_score,
        'verdict': verdict,
        'tier': tier,
        'color': color,
        'icon': icon,
        'summary': summary,
        'ml_probability': round(ml_phish_prob * 100, 1),
        'positives': positives,
        'cautions': cautions,
        'dangers': dangers,
        'whois': whois_info,
        'dns': dns_info,
        'ssl': ssl_info,
        'typosquatting': typo_info,
        'homoglyphs': homo_info,
        'redirects': redirect_info,
        'is_shortened': is_shortened
    }