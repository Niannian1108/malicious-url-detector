"""
feature_extractor.py
--------------------------------------------------------------------------------
Extract numerical and boolean features from a URL so a machine-learning model
can decide whether the URL is malicious or benign.

This version goes beyond simple lexical counts by adding:
  - hostname/query structure features
  - suspicious TLD and punycode checks
  - basic script/executable path detection
  - trusted-domain recognition
  - brand/domain mismatch detection
"""

import math
import re
from urllib.parse import urlparse

import tldextract


# Common punctuation often abused in phishing and malicious URLs.
SPECIAL_CHARS = set("-_?=&@%#!")

# General phishing-oriented keywords.
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon",
    "secure", "security", "verify", "verification",
    "account", "update", "confirm", "billing",
    "bank", "paypal", "ebay", "amazon",
    "password", "credential", "wallet",
    "free", "lucky", "winner", "prize",
    "support", "helpdesk", "service",
    "webscr", "cmd=",
]

# Common extensions used in phishing landing pages or downloadable payloads.
EXECUTABLE_EXTENSIONS = (
    ".php", ".asp", ".aspx", ".jsp", ".js", ".exe", ".dll", ".scr", ".zip"
)

# A small hand-curated set of higher-risk TLDs seen frequently in abuse.
SUSPICIOUS_TLDS = {
    "biz", "cc", "cf", "click", "country", "download", "gq", "info", "kim",
    "loan", "ml", "ga", "ru", "support", "tk", "top", "work", "xyz", "zip",
}

# Brand tokens and domains that are legitimately owned by those brands.
BRAND_DOMAIN_MAP = {
    "google": ("google.com", "googleapis.com", "googleusercontent.com", "withgoogle.com"),
    "github": ("github.com", "githubusercontent.com", "githubassets.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "windows.com"),
    "apple": ("apple.com", "icloud.com"),
    "paypal": ("paypal.com",),
    "dropbox": ("dropbox.com", "dropboxapi.com"),
    "adobe": ("adobe.com",),
    "amazon": ("amazon.com", "amazonpay.com"),
    "aws": ("amazon.com", "aws.amazon.com"),
    "atlassian": ("atlassian.com",),
}

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Keep suffix parsing local so requests do not hang on external cache refreshes.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0

    char_counts: dict[str, int] = {}
    for ch in text:
        char_counts[ch] = char_counts.get(ch, 0) + 1

    total = len(text)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return round(entropy, 6)


def _count_special_chars(text: str) -> int:
    """Return the count of special characters from SPECIAL_CHARS."""
    return sum(1 for ch in text if ch in SPECIAL_CHARS)


def _count_query_params(query: str) -> int:
    """Return the number of query-string parameters."""
    if not query:
        return 0
    return len([part for part in query.split("&") if part])


def _has_suspicious_keyword(url_lower: str) -> int:
    """Return 1 if any phishing-oriented keyword appears in the URL."""
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            return 1
    return 0


def _is_ip_address(host: str) -> int:
    """Return 1 if host is a bare IPv4 address."""
    return 1 if _IPV4_RE.match(host) else 0


def _count_subdomains(extracted) -> int:
    """Return how many labels appear in the subdomain portion."""
    if not extracted.subdomain:
        return 0
    return len(extracted.subdomain.split("."))


def _has_punycode(host: str) -> int:
    """Return 1 if the hostname contains punycode labels."""
    return 1 if "xn--" in host.lower() else 0


def _has_executable_path(path: str) -> int:
    """Return 1 if the path ends with a commonly abused extension."""
    return 1 if path.lower().endswith(EXECUTABLE_EXTENSIONS) else 0


def _has_suspicious_tld(suffix: str) -> int:
    """Return 1 if the public suffix is in a risky hand-curated list."""
    return 1 if suffix.lower() in SUSPICIOUS_TLDS else 0


def _hostname_matches_domain(host: str, candidate_domain: str) -> bool:
    """Return True when host is the same as candidate_domain or its subdomain."""
    host = host.lower()
    candidate_domain = candidate_domain.lower()
    return host == candidate_domain or host.endswith(f".{candidate_domain}")


def _is_known_trusted_domain(host: str) -> int:
    """Return 1 if the hostname belongs to one of the monitored trusted vendors."""
    for approved_domains in BRAND_DOMAIN_MAP.values():
        if any(_hostname_matches_domain(host, domain) for domain in approved_domains):
            return 1
    return 0


def _find_brand_tokens(text: str) -> set[str]:
    """Return the monitored brand tokens that appear in text."""
    text = text.lower()
    return {brand for brand in BRAND_DOMAIN_MAP if brand in text}


def _brand_signals(url_lower: str, host: str) -> tuple[int, int]:
    """
    Return:
      - has_brand_keyword: a monitored brand appears somewhere in the URL
      - has_brand_mismatch: the brand appears but the hostname is not brand-owned
    """
    brand_tokens = _find_brand_tokens(url_lower)
    if not brand_tokens:
        return 0, 0

    for brand in brand_tokens:
        approved_domains = BRAND_DOMAIN_MAP[brand]
        if not any(_hostname_matches_domain(host, domain) for domain in approved_domains):
            return 1, 1

    return 1, 0


def extract_features(url: str) -> dict:
    """Extract a flat numeric feature dictionary from a raw URL string."""
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    url_lower = url.lower()
    parsed = urlparse(url)
    extracted = _TLD_EXTRACTOR(url)

    scheme = parsed.scheme
    host = parsed.netloc
    path = parsed.path
    query = parsed.query
    bare_host = host.split(":")[0]

    domain = extracted.domain
    suffix = extracted.suffix
    full_domain = f"{domain}.{suffix}" if suffix else domain

    url_length = len(url)
    host_length = len(bare_host)
    domain_length = len(full_domain)
    path_length = len(path)
    query_length = len(query)

    num_dots = url.count(".")
    num_digits = sum(1 for ch in url if ch.isdigit())
    num_hyphens = url.count("-")
    num_special_chars = _count_special_chars(url)
    num_query_params = _count_query_params(query)

    has_https = 1 if scheme == "https" else 0
    entropy = _shannon_entropy(url)
    has_ip_address = _is_ip_address(bare_host)
    has_punycode = _has_punycode(bare_host)
    has_executable_path = _has_executable_path(path)
    has_suspicious_tld = _has_suspicious_tld(suffix)

    subdomain_count = _count_subdomains(extracted)
    path_depth = len([seg for seg in path.split("/") if seg])
    is_known_trusted_domain = _is_known_trusted_domain(bare_host)
    has_brand_keyword, has_brand_mismatch = _brand_signals(url_lower, bare_host)
    has_suspicious_keyword = _has_suspicious_keyword(url_lower)

    return {
        "url_length": url_length,
        "host_length": host_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,
        "num_dots": num_dots,
        "num_digits": num_digits,
        "num_hyphens": num_hyphens,
        "num_special_chars": num_special_chars,
        "num_query_params": num_query_params,
        "has_https": has_https,
        "entropy": entropy,
        "has_ip_address": has_ip_address,
        "has_punycode": has_punycode,
        "has_executable_path": has_executable_path,
        "has_suspicious_tld": has_suspicious_tld,
        "subdomain_count": subdomain_count,
        "path_depth": path_depth,
        "is_known_trusted_domain": is_known_trusted_domain,
        "has_brand_keyword": has_brand_keyword,
        "has_brand_mismatch": has_brand_mismatch,
        "has_suspicious_keyword": has_suspicious_keyword,
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://192.168.1.1/admin/login",
        "http://login-secure.paypal.verify-account.xyz/cmd=_login-submit",
        "https://mail.accounts.google.com/signin/v2/challenge/pwd",
        "ftp://files.example.org/pub/data.zip",
    ]

    for url in test_urls:
        print(f"\nURL : {url}")
        print("-" * 60)
        feats = extract_features(url)
        for key, val in feats.items():
            print(f"  {key:<28} = {val}")
