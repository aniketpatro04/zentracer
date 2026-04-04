"""
sanitiser.py — Module 1: URL Input Sanitisation & Validation
=============================================================
Responsibilities:
    - Accept a raw URL string from ANY source (user input, Excel cell, subdomain list)
    - Validate and clean it into a structured, reliable format
    - Reject or flag anything that cannot be safely used downstream
"""

import re
from urllib.parse import urlparse,urlunparse


#Define the Supported and Unsupported Schemes
SUPPORTED_SCHEMES = {"http" , "https"}
UNSUPPORTED_SCHEMES = {"ftp", "ftps", "ws", "wss", "mailto", "ssh", "sftp", "telnet"}

MAX_URL_LENGTH = 2048


#RegEx for valdating host names
HOSTNAME_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'                # each label starts with alphanumeric
    r'(?:[a-zA-Z0-9\-]{0,61}'         # label body: alphanumeric + hyphens
    r'[a-zA-Z0-9])?'                  # each label ends with alphanumeric
    r'\.)*'                           # repeat for each subdomain level
    r'[a-zA-Z0-9]'                    # TLD starts with alphanumeric
    r'(?:[a-zA-Z0-9\-]{0,61}'
    r'[a-zA-Z0-9])?$'
)

# Regex for an IPv4 address (Valid)
IPV4_REGEX = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)

# Regex for a bracketed IPv6 address in a URL, e.g. http://[::1]/path
IPV6_BRACKETED_REGEX = re.compile(r'^\[.*\]$')


def _make_result(original, **kwargs):
    """
    Builds a result dict, filling in defaults for any unspecified keys.
    Internal helper — not part of the public API.
    """
    base = {
        "is_valid":       False,
        "error":          None,
        "original":       original,
        "scheme":         None,
        "hostname":       None,
        "port":           None,
        "path":           None,
        "query":          None,
        "fragment":       None,
        "normalised_url": None,
    }
    base.update(kwargs)
    return base
 

#Validations for Host Name

# Non Empty Check
def _check_not_empty(raw):
    """
    Rejects None, empty strings, and whitespace-only strings.
    """
    if raw is None:
        return "Input is None — expected a string."
    if not isinstance(raw, str):
        return f"Expected a string, got {type(raw).__name__}."
    if not raw.strip():
        return "Input is empty or contains only whitespace."
    return None  # None means "no error"


# Length Check
def _check_length(raw):
    """
    Rejects URLs that are implausibly long.
 
    Extremely long strings are usually:
    - Accidental pastes of multi-line content
    - Fuzzing/injection attempts
    - A full HTML page pasted into a URL field
    """
    if len(raw) > MAX_URL_LENGTH:
        return (
            f"Input is {len(raw)} characters — exceeds the maximum "
            f"of {MAX_URL_LENGTH}. This does not look like a URL."
        )
    return None


# Check for Spaces
def _check_no_spaces(raw):
    """
    Rejects strings that contain internal spaces after stripping outer whitespace.
 
    A URL can never contain a raw space (it would be %20 if intentional).
    """
    stripped = raw.strip()
    if ' ' in stripped:
        return (
            "Input contains spaces. Please enter a single URL. "
            "If this is a label + URL, remove the label first."
        )
    return None


#Inject Default scheme if not present
def _inject_default_scheme(raw):
    """
    If the input has no scheme, prepend 'https://'.
    Else urlpasrse won't work
    """
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', raw.strip()):
        return "https://" + raw.strip()
    return raw.strip()

# Check for Scheme
def _check_scheme(parsed_scheme):
    """
    Validates the URL scheme.
 
    Three outcomes:
    1. Supported  (http, https)    → None (no error)
    2. Recognised but unsupported  → specific message telling the user why
    3. Completely unknown          → generic invalid-scheme message
    """
    scheme = parsed_scheme.lower()
 
    if scheme in SUPPORTED_SCHEMES:
        return None
 
    if scheme in UNSUPPORTED_SCHEMES:
        return (
            f"Scheme '{scheme}://' is not supported. "
            "Only http:// and https:// URLs can be probed for response time and headers."
        )
 
    return (
        f"Unrecognised scheme '{scheme}://'. "
        "Only http:// and https:// are supported."
    )


# Validate Hostname function. Combines the other functions
def _validate_hostname(hostname):

    if not hostname:
        return "No hostname found in the URL. Did you forget the domain name?"
 
    # Strip brackets from IPv6 addresses before further checks
    if IPV6_BRACKETED_REGEX.match(hostname):
        return None  # Accept IPv6 — deeper validation is left to the OS resolver
 
    # IPv4 check
    ipv4_match = IPV4_REGEX.match(hostname)
    if ipv4_match:
        octets = [int(ipv4_match.group(i)) for i in range(1, 5)]
        if all(0 <= o <= 255 for o in octets):
            return None  # Valid IPv4
        return f"'{hostname}' looks like an IPv4 address but has octets out of range (0–255)."
 
    # Consecutive dots
    if '..' in hostname:
        return f"'{hostname}' contains consecutive dots, which is not a valid hostname."
 
    # Total length (DNS limit)
    if len(hostname) > 253:
        return f"Hostname '{hostname}' is {len(hostname)} chars — exceeds the DNS limit of 253."
 
    # Label-level checks
    labels = hostname.split('.')
    for label in labels:
        if len(label) > 63:
            return (
                f"Label '{label}' in hostname is {len(label)} chars — "
                "DNS labels cannot exceed 63 characters."
            )
 
    # All-numeric TLD (e.g. example.123) — not a real domain
    if labels[-1].isdigit():
        return (
            f"TLD '.{labels[-1]}' is all-numeric. "
            "This doesn't match any real top-level domain."
        )
 
    # Full hostname regex
    if not HOSTNAME_REGEX.match(hostname):
        return (
            f"'{hostname}' is not a valid hostname. "
            "Check for invalid characters or formatting issues."
        )
 
    return None  # Passed all checks


# Port Validation
def _validate_port(port_string):
    """
    Validates an explicit port number if one was present in the URL.
    e.g. https://example.com:8080/path  →  port_string = "8080"
 
    urlparse() extracts this as a string (or raises ValueError for non-integers).
    Valid range is 1–65535. Port 0 is reserved and not usable.
    """
    if port_string is None:
        return None, None  # no port specified — that's fine
 
    try:
        port_int = int(port_string)
    except (ValueError, TypeError):
        return None, f"Port '{port_string}' is not a valid integer."
 
    if not (1 <= port_int <= 65535):
        return None, f"Port {port_int} is out of the valid range (1–65535)."
 
    return port_int, None  # (validated port, no error)


# Public Fuction for sanitising hostname
def sanitise(raw_url):
    """
    Main entry point. Takes a raw URL string and returns a structured result dict.
 
    Usage:
        from sanitiser import sanitise
 
        result = sanitise("https://example.com/pages/catalogue")
        if not result["is_valid"]:
            print(result["error"])
        else:
            print(result["hostname"])        # "example.com"
            print(result["path"])            # "/pages/catalogue"
            print(result["normalised_url"])  # "https://example.com/pages/catalogue"
 
    This function is intentionally a thin orchestrator — each validation step
    is a separate private function so they can be unit tested independently.
    """
 
    # ---- Step 1: Type and emptiness check ----
    error = _check_not_empty(raw_url)
    if error:
        return _make_result(str(raw_url) if raw_url is not None else "", error=error)
 
    # Preserve the truly unmodified input — callers need this to log exactly
    # what came from the user or the Excel cell, before any processing touches it.
    original = raw_url
 
    # Work on the stripped version from here on
    raw = raw_url.strip()
 
    # ---- Step 2: Length check ----
    error = _check_length(raw)
    if error:
        return _make_result(original, error=error)
 
    # ---- Step 3: Internal spaces check ----
    error = _check_no_spaces(raw)
    if error:
        return _make_result(original, error=error)
 
    # ---- Step 3b: Detect bare-colon schemes (mailto:, tel:, data:) ----
    # These have a scheme but no '//', so _inject_default_scheme won't recognise
    # them as having a scheme and will prepend https://, turning
    # "mailto:user@example.com" into "https://mailto:user@example.com".
    # urlparse then reads "mailto" as a username — silently passing validation.
    # We catch this pattern explicitly before injection.
    bare_scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):(?!//)', raw)
    if bare_scheme_match:
        detected = bare_scheme_match.group(1).lower()
        if detected in UNSUPPORTED_SCHEMES:
            return _make_result(original, error=(
                f"Scheme '{detected}:' is not supported. "
                "Only http:// and https:// URLs can be probed for response time and headers."
            ))
        elif detected not in SUPPORTED_SCHEMES:
            return _make_result(original, error=(
                f"Unrecognised scheme '{detected}:'. "
                "Only http:// and https:// are supported."
            ))
 
    # ---- Step 4: Inject scheme if missing so urlparse works correctly ----
    with_scheme = _inject_default_scheme(raw)
 
    # ---- Step 5: Parse with urlparse ----
    try:
        parsed = urlparse(with_scheme)
    except Exception as e:
        return _make_result(original, error=f"URL parsing failed: {str(e)}")
 
    # ---- Step 6: Scheme validation ----
    error = _check_scheme(parsed.scheme)
    if error:
        return _make_result(original, error=error)
 
    # ---- Step 7: Hostname validation ----
    hostname = parsed.hostname  # urlparse lowercases this automatically
    error = _validate_hostname(hostname)
    if error:
        return _make_result(original, error=error)
 
    # ---- Step 8: Port validation (if explicitly specified) ----
    try:
        raw_port = parsed.port  # urlparse returns int or None; raises ValueError if malformed
    except ValueError:
        return _make_result(original, error=f"Port in URL is not a valid number.")
 
    port, error = _validate_port(str(raw_port) if raw_port is not None else None)
    if error:
        return _make_result(original, error=error)
 
    # ---- Step 9: Normalise and rebuild ----
    # Rebuild using urlunparse to get a clean, consistent URL.
    # - scheme is lowercased
    # - hostname is lowercased
    # - path, query, fragment are preserved exactly as given
    scheme    = parsed.scheme.lower()
    netloc    = hostname + (f":{port}" if port else "")
    path      = parsed.path      or ""
    query     = parsed.query     or ""
    fragment  = parsed.fragment  or ""
 
    normalised_url = urlunparse((scheme, netloc, path, "", query, fragment))
 
    return _make_result(
        original,
        is_valid       = True,
        scheme         = scheme,
        hostname       = hostname,
        port           = port,
        path           = path      or None,
        query          = query     or None,
        fragment       = fragment  or None,
        normalised_url = normalised_url,
    )
 
 
def sanitise_batch(url_list):
    """
    Convenience wrapper for processing a list of URLs (e.g. from Excel or a
    subdomain enumeration tool).
 
    Returns a list of result dicts in the same order as the input.
    Invalid entries are included with is_valid=False — they are never silently
    dropped, so the caller always gets one output per input.
 
    Usage:
        results = sanitise_batch(["https://example.com", "bad input", ""])
        for r in results:
            if r["is_valid"]:
                print(r["normalised_url"])
            else:
                print(f"Skipped: {r['original']} — {r['error']}")
    """
    return [sanitise(url) for url in url_list]


# Module Tests / Demo

if __name__ == "__main__":
 
    test_cases = [
        # (label, input)
        ("Standard HTTPS",              "https://example.com"),
        ("Standard HTTP",               "http://example.com"),
        ("No scheme",                   "example.com"),
        ("With path",                   "https://example.com/pages/catalogue"),
        ("Subdomain with path",         "https://api.store.example.co.uk/v2/products?sort=asc"),
        ("With port",                   "https://example.com:8080/admin"),
        ("IPv4 address",                "http://93.184.216.34/path"),
        ("Trailing slash",              "https://example.com/"),
        ("Fragment in URL",             "https://example.com/page#section-2"),
        ("Empty string",                ""),
        ("None",                        None),
        ("Whitespace only",             "   "),
        ("Has internal spaces",         "https://exam ple.com"),
        ("Unsupported scheme (ftp)",    "ftp://example.com"),
        ("Unknown scheme",              "xyz://example.com"),
        ("Consecutive dots",            "https://example..com"),
        ("All-numeric TLD",             "https://example.123"),
        ("Too long",                    "https://" + "a" * 2050),
        ("Scheme only",                 "https://"),
        ("Path-only subdomain result",  "example.com/pages/products"),
    ]
 
    for label, url in test_cases:
        result = sanitise(url)
        status = "✅ VALID" if result["is_valid"] else "❌ INVALID"
        print(f"\n{status} | {label}")
        print(f"  Input     : {repr(url)}")
        if result["is_valid"]:
            print(f"  Hostname  : {result['hostname']}")
            print(f"  Path      : {result['path']}")
            print(f"  Port      : {result['port']}")
            print(f"  Final URL : {result['normalised_url']}")
        else:
            print(f"  Error     : {result['error']}")