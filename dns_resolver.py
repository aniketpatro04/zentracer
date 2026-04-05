import socket
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)

#TIME After which DNS lookout aborts
DNS_TIMEOUT = 5

#TCP Probing Timeout
TCP_PROBE_TIMEOUT = 3

#Default Ports if No port is specified
DEFAULT_PROBE_PORTS = [80, 443]


#IP Address Classification Labels
IP_CLASS_PUBLIC    = "public"
IP_CLASS_PRIVATE   = "private"     # RFC 1918: 10.x, 172.16-31.x, 192.168.x
IP_CLASS_LOOPBACK  = "loopback"    # 127.x.x.x / ::1
IP_CLASS_LINK_LOCAL = "link_local" # 169.254.x.x / fe80::/10
IP_CLASS_RESERVED  = "reserved"    # IANA reserved, documentation ranges, etc.
IP_CLASS_UNKNOWN   = "unknown" 


# ----------------------------------------------------------------------------------
# RESULT SCHEMA
# ----------------------------------------------------------------------------------
# resolve() always returns a dict with this structure.
# Check "success" before using any address or probe fields.
#
# {
#     "success"      : bool,
#     "hostname"     : str,            # the hostname that was queried
#     "error"        : str | None,     # set on failure, None on success
#
#     "ipv4"         : str | None,     # first A record resolved
#     "ipv4_all"     : list[str],      # all A records (empty list if none)
#     "ipv4_class"   : str | None,     # classification of primary IPv4
#
#     "ipv6"         : str | None,     # first AAAA record resolved
#     "ipv6_all"     : list[str],      # all AAAA records (empty list if none)
#     "ipv6_class"   : str | None,     # classification of primary IPv6
#
#     "probes"       : dict,           # { port_int: bool } — True = open
#     "port_80"      : bool,           # convenience alias for probes[80]
#     "port_443"     : bool,           # convenience alias for probes[443]
#
#     "warnings"     : list[str],      # non-fatal observations (e.g. private IP)
# }


def _make_result(hostname: str, **kwargs) -> dict:
    """
    Builds a fully populated result dict with safe defaults.
    """
    base = {
        "success":     False,
        "hostname":    hostname,
        "error":       None,
        "ipv4":        None,
        "ipv4_all":    [],
        "ipv4_class":  None,
        "ipv6":        None,
        "ipv6_all":    [],
        "ipv6_class":  None,
        "probes":      {},
        "port_80":     False,
        "port_443":    False,
        "warnings":    [],
    }
    base.update(kwargs)
    return base


# Helper and Validation Functions

def _classify_ip(ip_str: str) -> str:

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return IP_CLASS_UNKNOWN
    

    if ip_obj.is_loopback:
        return IP_CLASS_LOOPBACK
    if ip_obj.is_link_local:
        return IP_CLASS_LINK_LOCAL
    if ip_obj.is_private:
        return IP_CLASS_PRIVATE
    if ip_obj.is_reserved:
        return IP_CLASS_RESERVED
    if ip_obj.is_global:
        return IP_CLASS_PUBLIC
 
    return IP_CLASS_UNKNOWN


# Probing for Open Ports
def _probe_port(hostname: str, port: int, timeout: int = TCP_PROBE_TIMEOUT) -> bool:

    """
    Attempts a TCP connection to (hostname, port) and returns True if it succeeds. 
    Return values:
        True  — TCP handshake completed; the port is open and listening
        False — any failure: refused, timeout, no route, hostname unresolvable
 
    Note: a True result only confirms the port is open at the TCP level.
    It does not guarantee a valid HTTP/HTTPS response — that is http_probe's job.
    """
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except socket.timeout:
        logger.debug("TCP probe timed out: %s:%d", hostname, port)
        return False
    except ConnectionRefusedError:
        logger.debug("TCP probe refused: %s:%d", hostname, port)
        return False
    except socket.gaierror as e:
        # Hostname unresolvable during probe — different from the main DNS lookup
        # because getaddrinfo may have succeeded but a second resolution failed.
        logger.debug("TCP probe DNS error: %s:%d — %s", hostname, port, e)
        return False
    except OSError as e:
        # Covers: network unreachable, no route to host, etc.
        logger.debug("TCP probe OS error: %s:%d — %s", hostname, port, e)
        return False


#host Name Validation
def _validate_hostname_input(hostname) -> Optional[str]:

    """
    Guards against bad input before the DNS lookup runs.
    Returns an error string if invalid, None if fine.
 
    This module receives its hostname from sanitiser.sanitise()["hostname"],
    which is already validated. These guards exist for:
    - Direct calls that bypass the sanitiser (e.g. test code, shell scripts)
    - Batch processing where a cell value slips through without sanitisation
    """
    if hostname is None:
        return "Hostname is None — pass result['hostname'] from sanitiser.sanitise()."
    if not isinstance(hostname, str):
        return f"Hostname must be a string, got {type(hostname).__name__}."
    if not hostname.strip():
        return "Hostname is empty or whitespace."
 
    # Reject full URLs — a common mistake when wiring modules together.
    # getaddrinfo("https://example.com") will fail with a gaierror, but the
    # error message is confusing. We give a clear message instead.
    if hostname.startswith(("http://", "https://", "ftp://", "//")):
        return (
            f"'{hostname}' looks like a full URL, not a bare hostname. "
            "Pass result['hostname'] from sanitiser.sanitise(), not normalised_url."
        )
 
    # Reject hostnames with a path component — again a wiring mistake.
    if "/" in hostname:
        return (
            f"'{hostname}' contains a '/' — this looks like a URL path, not a hostname. "
            "Pass result['hostname'] from sanitiser.sanitise()."
        )
 
    return None



#Core Resolver Functions 


def resolve(hostname: str, probe_ports: list = None) -> dict:
    
    """
    Main entry point. Resolves a hostname and returns a structured result dict.
 
    Args:
        hostname    — bare hostname, e.g. "api.example.com"
                      Obtain this from sanitiser.sanitise()["hostname"].
        probe_ports — list of integer port numbers to TCP-probe after resolution.
                      Defaults to DEFAULT_PROBE_PORTS [80, 443].
                      Pass an empty list [] to skip all port probing.
 
    Returns:
        A result dict (see RESULT SCHEMA above). Always returns a dict —
        never raises an exception. Check result["success"] before using
        address fields; check result["warnings"] for non-fatal observations.
 
    Example:
        from sanitiser import sanitise
        from dns_resolver import resolve
 
        san = sanitise("https://api.example.com/v2/products")
        if san["is_valid"]:
            dns = resolve(san["hostname"])
            if dns["success"]:
                print(dns["ipv4"])        # "93.184.216.34"
                print(dns["port_443"])    # True
            else:
                print(dns["error"])
    """
 
    if probe_ports is None:
        probe_ports = DEFAULT_PROBE_PORTS
 
    # ---- Guard: validate input before touching the network ----
    input_error = _validate_hostname_input(hostname)
    if input_error:
        return _make_result(hostname or "", error=input_error)
 
    hostname = hostname.strip()
    result   = _make_result(hostname)
 
    # ---- DNS lookup with scoped timeout ----
    # socket.setdefaulttimeout() is process-global. We save and restore it
    # so we don't interfere with any other socket operations running in the
    # same process (e.g. in a multi-threaded batch runner).
    # Note: this is NOT thread-safe for the window between set and restore.
    # For a threaded batch runner, use concurrent.futures with per-thread
    # socket timeouts or switch to asyncio with aiodns.
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
 
    try:
        records = socket.getaddrinfo(hostname, None)
 
    except socket.timeout:
        result["error"] = (
            f"DNS lookup timed out after {DNS_TIMEOUT}s. "
            "The resolver is unresponsive or the hostname is unreachable."
        )
        return result
 
    except socket.gaierror as e:
        # errno 8  → nodename nor servname provided (bad hostname format)
        # errno 11 → resource temporarily unavailable (resolver down)
        # errno -2 → name or service not known (NXDOMAIN)
        result["error"] = (
            f"DNS resolution failed for '{hostname}': {e.strerror} "
            f"(error code {e.errno})"
        )
        return result
 
    except OSError as e:
        # Covers: network unreachable, no route to host at the OS level
        result["error"] = f"Network error during DNS lookup: {str(e)}"
        return result
 
    except Exception as e:
        # True catch-all — should never happen but must not surface as a crash
        result["error"] = f"Unexpected error during DNS lookup: {type(e).__name__}: {str(e)}"
        return result
 
    finally:
        socket.setdefaulttimeout(old_timeout)
 
    # ---- Parse records ----
    # getaddrinfo returns: (family, type, proto, canonname, sockaddr)
    # sockaddr for AF_INET  is (ip, port)
    # sockaddr for AF_INET6 is (ip, port, flowinfo, scope_id)
    # port will always be 0 because we passed None as the service argument.
 
    ipv4_all = []
    ipv6_all = []
 
    for family, _, _, _, sockaddr in records:
        ip_addr = sockaddr[0]
 
        if family == socket.AF_INET:
            if ip_addr not in ipv4_all:   # deduplicate — some resolvers return dupes
                ipv4_all.append(ip_addr)
 
        elif family == socket.AF_INET6:
            if ip_addr not in ipv6_all:
                ipv6_all.append(ip_addr)
 
    result["ipv4_all"] = ipv4_all
    result["ipv6_all"] = ipv6_all
 
    # Primary addresses — first record of each family
    if ipv4_all:
        result["ipv4"]       = ipv4_all[0]
        result["ipv4_class"] = _classify_ip(ipv4_all[0])
 
    if ipv6_all:
        result["ipv6"]       = ipv6_all[0]
        result["ipv6_class"] = _classify_ip(ipv6_all[0])
 
    # ---- Warn on non-public addresses ----
    # These aren't errors — the DNS lookup succeeded — but they're worth flagging.
    if result["ipv4_class"] and result["ipv4_class"] != IP_CLASS_PUBLIC:
        result["warnings"].append(
            f"IPv4 address {result['ipv4']} is classified as "
            f"'{result['ipv4_class']}' — this is not a public internet address. "
            "Ensure this is the intended target."
        )
 
    if result["ipv6_class"] and result["ipv6_class"] != IP_CLASS_PUBLIC:
        result["warnings"].append(
            f"IPv6 address {result['ipv6']} is classified as "
            f"'{result['ipv6_class']}' — this is not a public internet address."
        )
 
    # ---- Warn if hostname resolved to nothing ----
    # Technically getaddrinfo() with no results shouldn't happen without raising
    # gaierror, but some platforms behave differently. Defensive check.
    if not ipv4_all and not ipv6_all:
        result["warnings"].append(
            "DNS lookup returned no address records. "
            "The hostname may exist but have no A or AAAA records."
        )
        result["error"] = "No address records returned for this hostname."
        return result
 
    # ---- TCP port probes ----
    # Run after DNS — we only probe if resolution succeeded.
    # If probe_ports is empty, this loop is a no-op.
    probes = {}
    for port in probe_ports:
        if not isinstance(port, int) or not (1 <= port <= 65535):
            result["warnings"].append(
                f"Skipped invalid probe port: {port!r}. "
                "Ports must be integers in range 1–65535."
            )
            continue
        probes[port] = _probe_port(hostname, port)
 
    result["probes"] = probes
 
    # Convenience aliases for the two default ports
    result["port_80"]  = probes.get(80,  False)
    result["port_443"] = probes.get(443, False)
 
    result["success"] = True
    return result
 
 
def resolve_batch(hostnames: list, probe_ports: list = None) -> list:
    """
    Resolves a list of hostnames, returning one result dict per input.
 
    Designed for the Excel module — pass the list of values from the
    "Web Address" column (after sanitising each one) and get back a
    parallel list of results.
 
    Invalid or failing entries are included with success=False — they
    are never silently dropped. The caller always gets len(input) results.
 
    Example:
        from sanitiser import sanitise_batch
        from dns_resolver import resolve_batch
 
        raw_urls  = ["https://example.com", "https://google.com", "bad input"]
        sanitised = sanitise_batch(raw_urls)
        hostnames = [r["hostname"] if r["is_valid"] else None for r in sanitised]
        dns_results = resolve_batch(hostnames)
    """
    if probe_ports is None:
        probe_ports = DEFAULT_PROBE_PORTS
 
    return [resolve(h, probe_ports=probe_ports) for h in hostnames]
 
 
# ----------------------------------------------------------------------------------
# MAIN — manual test / demonstration
# ----------------------------------------------------------------------------------
 
if __name__ == "__main__":
 
    # Import sanitiser so we demonstrate the correct wiring
    try:
        from sanitiser import sanitise
    except ImportError:
        print("[Error] sanitiser.py not found. Run from the project root directory.")
        exit(1)
 
    test_cases = [
        # (label, raw_input)
        ("Public HTTPS site",        "https://example.com"),
        ("Google — expect dual stack","https://google.com"),
        ("Subdomain with path",      "https://api.github.com/v2/users"),
        ("Bare domain",              "example.com"),
        ("Loopback (localhost)",     "localhost"),
        ("Non-existent domain",      "https://this-does-not-exist-xyz123.com"),
        ("Wiring mistake — full URL","https://example.com"),  # will be caught
        ("IPv4 as hostname",         "http://1.1.1.1"),
    ]
 
    for label, raw in test_cases:
        san = sanitise(raw)
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"  Input: {raw!r}")
 
        if not san["is_valid"]:
            print(f"  [Sanitiser rejected] {san['error']}")
            continue
 
        dns = resolve(san["hostname"])
 
        if not dns["success"]:
            print(f"  [DNS Failed] {dns['error']}")
        else:
            print(f"  IPv4        : {dns['ipv4'] or 'None'} ({dns['ipv4_class']})")
            print(f"  IPv4 all    : {dns['ipv4_all']}")
            print(f"  IPv6        : {dns['ipv6'] or 'None'} ({dns['ipv6_class']})")
            print(f"  IPv6 all    : {dns['ipv6_all']}")
            print(f"  Port 80     : {'Open' if dns['port_80']  else 'Closed/Filtered'}")
            print(f"  Port 443    : {'Open' if dns['port_443'] else 'Closed/Filtered'}")
            print(f"  All probes  : {dns['probes']}")
 
        if dns["warnings"]:
            for w in dns["warnings"]:
                print(f"  [Warning] {w}")
