import re
import math
from urllib.parse import urlparse
from collections import Counter

def parse_domain_parts(url: str):
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc = parsed.netloc.split(":")[0]
    parts = netloc.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    elif len(parts) == 2:
        return "", parts[0], parts[1]
    return "", netloc, ""

SUSPICIOUS_KEYWORDS = [
    "secure", "account", "update", "banking", "login", "signin", "verify",
    "verification", "wallet", "support", "service", "confirm", "security",
    "ebayisapi", "webscr", "password", "credential", "auth", "token", "claim",
    "gift", "bonus", "free", "admin", "recover", "crypto", "binance", "metamask"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "club", "click", "stream", "gq", "cf",
    "tk", "ml", "ga", "fit", "buzz", "cc", "kim", "icu", "country"
}

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def extract_features_from_url(url: str) -> dict:
    """Extracts 65 URL lexical, structural, and information entropy features."""
    if not re.match(r'^[a-zA-Z]+://', url):
        full_url = 'http://' + url
    else:
        full_url = url

    parsed = urlparse(full_url)
    subdomain, domain_name, suffix = parse_domain_parts(full_url)
    
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    raw_url = url.lower()

    # Basic length features (10)
    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_length": len(subdomain),
        "suffix_length": len(suffix),
        "tld_length": len(suffix),
        "count_subdomains": len(subdomain.split('.')) if subdomain else 0,
        "path_depth": len([seg for seg in path.split('/') if seg]),
        "query_params_count": len(query.split('&')) if query else 0,
    }

    # Character counts & ratios (25)
    char_checks = [
        ('.', 'dot'), ('-', 'hyphen'), ('_', 'underscore'), ('/', 'slash'),
        ('?', 'question'), ('=', 'equal'), ('@', 'at'), ('&', 'ampersand'),
        ('!', 'exclamation'), ('~', 'tilde'), ('%', 'percent'), ('+', 'plus'),
        ('*', 'asterisk'), ('#', 'hash'), ('$', 'dollar'), (';', 'semicolon'),
        (',', 'comma'), (':', 'colon')
    ]
    for char, name in char_checks:
        features[f"count_{name}"] = raw_url.count(char)

    digits_count = sum(c.isdigit() for c in raw_url)
    alpha_count = sum(c.isalpha() for c in raw_url)
    total_len = max(len(raw_url), 1)

    features["count_digits"] = digits_count
    features["count_letters"] = alpha_count
    features["ratio_digits"] = digits_count / total_len
    features["ratio_letters"] = alpha_count / total_len
    features["ratio_non_alphanumeric"] = (total_len - digits_count - alpha_count) / total_len
    features["domain_digits_count"] = sum(c.isdigit() for c in domain)
    features["domain_digits_ratio"] = sum(c.isdigit() for c in domain) / max(len(domain), 1)

    # Entropies (4)
    features["url_entropy"] = round(shannon_entropy(url), 5)
    features["domain_entropy"] = round(shannon_entropy(domain), 5)
    features["path_entropy"] = round(shannon_entropy(path), 5)
    features["query_entropy"] = round(shannon_entropy(query), 5)

    # Patterns & Binary indicators (16)
    features["has_ip_in_host"] = int(bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain)))
    features["has_port"] = int(bool(parsed.port))
    features["is_https"] = int(parsed.scheme.lower() == 'https')
    features["has_at_symbol"] = int('@' in raw_url)
    features["has_double_slash_redirect"] = int('//' in path)
    features["has_dash_in_domain"] = int('-' in domain)
    features["starts_with_ip"] = int(bool(re.match(r'^https?://[0-9]{1,3}\.', raw_url)))
    features["is_suspicious_tld"] = int(suffix in SUSPICIOUS_TLDS)
    features["has_hex_encoding"] = int(bool(re.search(r'%[0-9a-fA-F]{2}', raw_url)))
    features["has_base64_marker"] = int("base64" in raw_url or "data:" in raw_url)
    features["has_client_side_nav"] = int('#!' in raw_url or '#/' in raw_url)
    features["has_punycode"] = int("xn--" in domain)
    features["has_exe_or_zip"] = int(bool(re.search(r'\.(exe|zip|iso|apk|bat|sh|msi|dmg)$', path, re.I)))
    features["has_php_or_jsp"] = int(bool(re.search(r'\.(php|asp|aspx|jsp|cgi)$', path, re.I)))
    features["subdomain_has_punycode"] = int("xn--" in subdomain)
    features["has_multiple_subdomains"] = int(features["count_subdomains"] > 2)

    # Targeted threat keywords (10)
    for kw in SUSPICIOUS_KEYWORDS[:10]:
        features[f"kw_{kw}"] = int(kw in raw_url)

    return features

FEATURE_NAMES = list(extract_features_from_url("http://example.com").keys())
