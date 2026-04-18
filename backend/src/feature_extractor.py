"""
feature_extractor.py
────────────────────────────────────────────────────────────────────────────────
Extracts numerical / boolean features from a raw URL string so that a machine-
learning model can decide whether the URL is malicious or benign.

Features returned (all in a flat dict):
  url_length          – total character count of the URL
  domain_length       – character count of the registered domain only
  path_length         – character count of the URL path
  num_dots            – number of '.' characters in the full URL
  num_digits          – number of 0-9 digits in the full URL
  num_special_chars   – count of selected special characters (-, _, ?, =, &, @, %, #, !)
  has_https           – 1 if the scheme is https, 0 otherwise
  entropy             – Shannon entropy of the URL string (higher ⟹ more random-looking)
  has_ip_address      – 1 if the host looks like a raw IPv4 address, 0 otherwise
  subdomain_count     – number of subdomain labels (e.g. "a.b.example.com" ⟹ 2)
  path_depth          – number of '/' segments in the path (e.g. "/a/b/c" ⟹ 3)
  has_suspicious_keyword – 1 if any known phishing keyword is present in the URL

Dependencies:
  pip install tldextract   (already listed in requirements.txt)
  urllib.parse             (Python standard library)
"""

import math
import re
import string
from urllib.parse import urlparse

import tldextract


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

# Special characters that are commonly abused in phishing / malicious URLs.
SPECIAL_CHARS = set("-_?=&@%#!")

# Keywords frequently found in phishing URLs that try to impersonate
# legitimate services (banks, payment processors, social platforms, etc.).
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon",
    "secure", "security", "verify", "verification",
    "account", "update", "confirm", "billing",
    "bank", "paypal", "ebay", "amazon",
    "password", "credential", "wallet",
    "free", "lucky", "winner", "prize",
    "support", "helpdesk", "service",
    "webscr", "cmd=",                   # PayPal phishing patterns
]

# Simple IPv4 pattern: four groups of digits separated by dots.
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Entropy measures how unpredictable / random a string is.
    Malicious URLs often have high entropy because they contain
    randomly generated subdomains or paths (e.g. base64 payloads).

    Formula:  H = -Σ p(c) * log2(p(c))   for each unique character c.

    Returns 0.0 for an empty string.
    """
    if not text:
        return 0.0

    # Count how often each character appears.
    char_counts: dict[str, int] = {}
    for ch in text:
        char_counts[ch] = char_counts.get(ch, 0) + 1

    total = len(text)

    # Apply the Shannon entropy formula.
    entropy = 0.0
    for count in char_counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return round(entropy, 6)


def _count_special_chars(text: str) -> int:
    """Return how many characters in *text* belong to SPECIAL_CHARS."""
    return sum(1 for ch in text if ch in SPECIAL_CHARS)


def _has_suspicious_keyword(url_lower: str) -> int:
    """
    Return 1 if *url_lower* contains at least one keyword from
    SUSPICIOUS_KEYWORDS, otherwise 0.

    The URL is pre-lowercased by the caller so the comparison is
    case-insensitive without calling .lower() repeatedly.
    """
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            return 1
    return 0


def _is_ip_address(host: str) -> int:
    """Return 1 if *host* is a bare IPv4 address, 0 otherwise."""
    return 1 if _IPV4_RE.match(host) else 0


def _count_subdomains(extracted) -> int:
    """
    Count the number of subdomain labels.

    tldextract splits a host into:
      subdomain  –  everything left of the registered domain
      domain     –  the registered domain name (e.g. "google")
      suffix     –  the public suffix / TLD (e.g. "com")

    Example: "mail.accounts.google.com"
      subdomain = "mail.accounts"  →  2 labels
    """
    subdomain = extracted.subdomain  # e.g. "mail.accounts" or ""
    if not subdomain:
        return 0
    return len(subdomain.split("."))


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract a dictionary of numerical / boolean features from a URL.

    Parameters
    ----------
    url : str
        The raw URL string (e.g. "https://example.com/path?q=1").

    Returns
    -------
    dict
        A flat dictionary where every value is a number (int or float).
        Ready to be converted into a single-row DataFrame or feature vector.

    Example
    -------
    >>> features = extract_features("http://login-secure.bankofamerica.verify.xyz/update")
    >>> features["has_https"]
    0
    >>> features["has_suspicious_keyword"]
    1
    """

    # ── 1. Normalise the URL ──────────────────────────────────────────────────
    # Strip surrounding whitespace; ensure there is a scheme so that
    # urlparse can correctly identify the host and path.
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url  # add a default scheme for parsing only

    url_lower = url.lower()  # reuse for keyword search (avoids repeated .lower())

    # ── 2. Parse the URL into components ─────────────────────────────────────
    parsed = urlparse(url)          # standard-library parser
    extracted = tldextract.extract(url)  # domain / TLD-aware parser

    # Individual components (may be empty strings if absent).
    scheme = parsed.scheme          # "https", "http", …
    host   = parsed.netloc          # "sub.example.com:8080"
    path   = parsed.path            # "/login/update"
    query  = parsed.query           # "user=foo&token=bar"

    # Registered domain only (e.g. "google" from "mail.google.com").
    domain = extracted.domain       # without subdomain or TLD
    suffix = extracted.suffix       # TLD, e.g. "co.uk"

    # Full domain string for length measurement (domain + suffix).
    full_domain = f"{domain}.{suffix}" if suffix else domain

    # ── 3. Compute each feature ───────────────────────────────────────────────

    # --- Basic length features ---
    url_length    = len(url)
    domain_length = len(full_domain)
    path_length   = len(path)

    # --- Character-count features ---
    num_dots         = url.count(".")
    num_digits       = sum(1 for ch in url if ch.isdigit())
    num_special_chars = _count_special_chars(url)

    # --- Security scheme ---
    has_https = 1 if scheme == "https" else 0

    # --- Entropy (randomness of the URL string) ---
    entropy = _shannon_entropy(url)

    # --- IP address in host field (phishing trick) ---
    # Remove port number before checking (e.g. "192.168.1.1:8080" → "192.168.1.1").
    bare_host = host.split(":")[0]
    has_ip_address = _is_ip_address(bare_host)

    # --- Subdomain depth ---
    subdomain_count = _count_subdomains(extracted)

    # --- Path depth (number of '/' segments) ---
    # Split on '/' and filter out empty strings produced by leading '/'.
    path_depth = len([seg for seg in path.split("/") if seg])

    # --- Suspicious keyword ---
    has_suspicious_keyword = _has_suspicious_keyword(url_lower)

    # ── 4. Bundle and return ─────────────────────────────────────────────────
    features = {
        "url_length":              url_length,
        "domain_length":           domain_length,
        "path_length":             path_length,
        "num_dots":                num_dots,
        "num_digits":              num_digits,
        "num_special_chars":       num_special_chars,
        "has_https":               has_https,
        "entropy":                 entropy,
        "has_ip_address":          has_ip_address,
        "subdomain_count":         subdomain_count,
        "path_depth":              path_depth,
        "has_suspicious_keyword":  has_suspicious_keyword,
    }

    return features


# ──────────────────────────────────────────────────────────────────────────────
# Quick manual test  (run:  python feature_extractor.py)
# ──────────────────────────────────────────────────────────────────────────────

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
