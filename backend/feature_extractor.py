import re
import urllib.parse
from datetime import datetime
import ipaddress

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'password', 'credential', 'webscr',
    'submit', 'redirect', 'click', 'free', 'lucky', 'service',
    'access', 'alert', 'authenticate', 'bonus', 'support'
]

# Common URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in',
    'short.link', 'rebrand.ly', 'cutt.ly', 'shorturl.at'
]


def is_valid_url(url):
    """Check if URL is valid and parseable."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def has_ip_address(url):
    """Check if domain is an IP address instead of domain name."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if host:
            ipaddress.ip_address(host)
            return 1
    except Exception:
        pass
    return 0


def extract_features(url):
    """
    Extract 32 lexical and host-based features from a URL string.
    Returns a dictionary of feature name to feature value.
    """
    features = {}

    # Handle invalid URLs gracefully
    if not url or not isinstance(url, str):
        return {f'feature_{i}': 0 for i in range(32)}

    # Ensure URL has a scheme for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        full_url = url.lower()

        # ── LEXICAL FEATURES (20) ──────────────────────────────────────────

        # 1. URL Length
        features['url_length'] = len(url)

        # 2. Number of dots in URL
        features['num_dots'] = url.count('.')

        # 3. Number of hyphens in URL
        features['num_hyphens'] = url.count('-')

        # 4. Number of special characters (@, ?, =, &, !, ~, +, %)
        features['num_special_chars'] = len(re.findall(r'[@?=&!~+%]', url))

        # 5. Presence of IP address in domain (1 = yes, 0 = no)
        features['has_ip_address'] = has_ip_address(url)

        # 6. Number of subdomains
        domain_parts = domain.split('.')
        features['num_subdomains'] = max(0, len(domain_parts) - 2)

        # 7. Use of URL shortening service (1 = yes, 0 = no)
        features['uses_url_shortener'] = int(
            any(shortener in domain for shortener in URL_SHORTENERS)
        )

        # 8. Presence of suspicious keywords (1 = yes, 0 = no)
        features['has_suspicious_keywords'] = int(
            any(keyword in full_url for keyword in SUSPICIOUS_KEYWORDS)
        )

        # 9. Use of HTTPS (1 = yes, 0 = no)
        features['uses_https'] = int(parsed.scheme == 'https')

        # 10. Length of domain name
        features['domain_length'] = len(domain)

        # 11. Number of digits in URL
        features['num_digits'] = sum(c.isdigit() for c in url)

        # 12. Presence of @ symbol (1 = yes, 0 = no)
        features['has_at_symbol'] = int('@' in url)

        # 13. Presence of double slash in path (1 = yes, 0 = no)
        features['has_double_slash'] = int('//' in path)

        # 14. URL depth (number of path segments)
        features['url_depth'] = len([p for p in path.split('/') if p])

        # 15. Number of query parameters
        features['num_query_params'] = len(
            urllib.parse.parse_qs(query)
        ) if query else 0

        # 16. Presence of port number in URL (1 = yes, 0 = no)
        features['has_port'] = int(parsed.port is not None)

        # 17. Number of fragments (# anchors)
        features['num_fragments'] = int(bool(parsed.fragment))

        # 18. Ratio of digits to URL length
        url_len = len(url) if len(url) > 0 else 1
        features['digit_ratio'] = features['num_digits'] / url_len

        # 19. Ratio of special characters to URL length
        features['special_char_ratio'] = features['num_special_chars'] / url_len

        # 20. Presence of encoded characters (%xx) (1 = yes, 0 = no)
        features['has_encoded_chars'] = int('%' in url)

        # ── HOST-BASED FEATURES (12) ───────────────────────────────────────
        # Note: In a live system these would use WHOIS/DNS APIs.
        # For the dataset-trained model these are pre-computed in the CSV.
        # The values below are defaults used at inference time when
        # live lookup data is unavailable.

        # 21. Domain age in days (default -1 = unknown)
        features['domain_age'] = -1

        # 22. Domain registration length in days (default -1 = unknown)
        features['domain_registration_length'] = -1

        # 23. DNS record availability (1 = available, 0 = not available)
        features['dns_record'] = 1

        # 24. WHOIS data completeness (1 = complete, 0 = incomplete)
        features['whois_complete'] = 1

        # 25. SSL certificate validity (1 = valid, 0 = invalid/absent)
        features['ssl_valid'] = int(parsed.scheme == 'https')

        # 26. Domain expiration proximity in days (default -1 = unknown)
        features['domain_expiry_days'] = -1

        # 27. Number of redirects (default 0)
        features['num_redirects'] = 0

        # 28. Page rank (default 0 = unknown)
        features['page_rank'] = 0

        # 29. Web traffic rank (default 0 = unknown)
        features['web_traffic'] = 0

        # 30. Links pointing to the page (default 0)
        features['links_in_tags'] = 0

        # 31. Statistical report flag (1 = flagged, 0 = not flagged)
        features['statistical_report'] = 0

        # 32. Domain in top-level suspicious TLD (.tk, .ml, .ga, .cf, .gq)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        features['suspicious_tld'] = int(
            any(domain.endswith(tld) for tld in suspicious_tlds)
        )

    except Exception as e:
        # Return zero-filled features if extraction fails
        features = {f'feature_{i}': 0 for i in range(32)}

    return features


def get_feature_vector(url):
    """
    Extract features and map them to the 12 features expected by the trained ML models.
    The models expect values typically in {-1, 0, 1}.
    """
    features = extract_features(url)
    
    # Map extracted features to the 12 selected features
    
    # 1. PrefixSuffix- (Hyphen in domain)
    f1 = -1 if features.get('num_hyphens', 0) > 0 else 1
    
    # 2. SubDomains (>1 means suspicious)
    f2 = -1 if features.get('num_subdomains', 0) > 1 else 1
    
    # 3. HTTPS
    f3 = 1 if features.get('uses_https', 0) == 1 else -1
    
    # 4. DomainRegLen (dummy based on domain length)
    f4 = 1
    # 5. RequestURL (dummy)
    f5 = 1
    # 6. AnchorURL (dummy)
    f6 = 1
    # 7. LinksInScriptTags (dummy)
    f7 = 1
    # 8. ServerFormHandler (dummy)
    f8 = 1
    # 9. AgeofDomain (dummy)
    f9 = 1
    # 10. WebsiteTraffic (dummy)
    f10 = 1
    # 11. PageRank (dummy)
    f11 = 1
    # 12. GoogleIndex (dummy)
    f12 = 1
    
    # Strong phishing indicators
    is_phish = (
        features.get('has_suspicious_keywords', 0) == 1 or 
        features.get('uses_url_shortener', 0) == 1 or 
        features.get('has_ip_address', 0) == 1 or
        features.get('suspicious_tld', 0) == 1 or
        features.get('domain_length', 0) > 30 or
        features.get('url_length', 0) > 75 or
        features.get('num_dots', 0) > 3
    )
    
    if is_phish:
        # Aggressively set the UCI simulated features to -1 (Phishing)
        f4 = -1
        f5 = -1
        f6 = -1
        f7 = -1
        f8 = -1
        f9 = -1
        f10 = -1
        f11 = -1
        f12 = -1
        
    return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12]


def get_feature_names():
    """Return ordered list of the 12 feature names expected by the model."""
    return [
        'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 
        'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 
        'AgeofDomain', 'WebsiteTraffic', 'PageRank', 'GoogleIndex'
    ]