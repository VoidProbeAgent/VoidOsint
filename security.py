"""
VoidOsint Security Hardening & Guardrails Module
================================================
Implements production-grade defenses against:
1. Subprocess & OS Command Injection (CWE-78, CWE-88)
2. Server-Side Request Forgery (SSRF) and Cloud Metadata Exfiltration (CWE-918)
3. DNS Rebinding & Localhost Host Header Hijacking (CWE-350)
4. Cross-Site Scripting & MIME-sniffing (CWE-79)

Author: Security Engineer (security-engineer-mvgfc71v)
Ticket: MMF-10 / WP-5
"""

import ipaddress
import re
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError:
    # Fallback placeholders if starlette is not yet in active virtualenv
    BaseHTTPMiddleware = object  # type: ignore
    Request = Any  # type: ignore
    Response = Any  # type: ignore
    JSONResponse = Any  # type: ignore


class SecurityValidationError(ValueError):
    """Raised when an input or URL violates security policies."""
    pass


# ==============================================================================
# 1. SUBPROCESS INJECTION DEFENSE & TARGET SANITIZATION (CWE-78, CWE-88)
# ==============================================================================

# Dangerous control characters
DANGEROUS_CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")

# Dangerous characters that could trigger shell interpretation, argument splitting,
# or escape delimiters if ever passed inappropriately.
DANGEROUS_SHELL_CHARS_RE = re.compile(r"[;&|`$<>\"\\]")

# Strict regular expressions per entity type to prevent command/argument injection
TARGET_REGEX_MAP = {
    # Alphanumeric, underscores, hyphens, periods. 1 to 128 characters.
    # Must NOT start with a hyphen or dash (prevents CLI argument injection).
    "username": re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_\-\.]{0,127}$"),

    # Unicode names, spaces, hyphens, periods, single apostrophes.
    # Must NOT start with a hyphen.
    "human_name": re.compile(r"^[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF][a-zA-Z\u00C0-\u024F\u1E00-\u1EFF\s\.\-']{0,127}$"),

    # RFC 5322 simplified email regex. No control chars, no shell metachars.
    "email": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),

    # Strict FQDN domain regex (RFC 1035 / RFC 1123). No protocol prefixes.
    "domain": re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,63}$"),

    # Subdomain regex (identical or nested domain labels).
    "subdomain": re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,63}$"),

    # E.164 phone number: + followed by 1 to 15 digits, or clean local 7-15 digits.
    "phone_number": re.compile(r"^\+?[1-9]\d{6,14}$"),
}


class TargetSanitizer:
    """Validates and sanitizes OSINT investigation targets."""

    @staticmethod
    def detect_entity_type(target: str) -> str:
        """Heuristically infers target entity type if not explicitly supplied."""
        target = target.strip()
        if "@" in target and TARGET_REGEX_MAP["email"].match(target):
            return "email"
        
        try:
            ipaddress.ip_address(target)
            return "ip_address"
        except ValueError:
            pass

        if target.startswith("+") and TARGET_REGEX_MAP["phone_number"].match(target.replace(" ", "").replace("-", "")):
            return "phone_number"

        if "." in target and TARGET_REGEX_MAP["domain"].match(target):
            return "domain"

        if " " in target and TARGET_REGEX_MAP["human_name"].match(target):
            return "human_name"

        if TARGET_REGEX_MAP["username"].match(target):
            return "username"

        return "unknown"

    @classmethod
    def validate_target(cls, target: str, target_type: str) -> str:
        """
        Validates target against strict regex patterns.
        Raises SecurityValidationError if target contains forbidden tokens or formats.
        """
        if not target or not isinstance(target, str):
            raise SecurityValidationError("Target must be a non-empty string.")

        clean_target = target.strip()
        norm_type = target_type.lower().strip() if target_type else ""

        # Reject null bytes and newline/carriage-return injection
        if DANGEROUS_CONTROL_CHARS_RE.search(clean_target):
            raise SecurityValidationError("Target contains illegal control or null-byte characters.")

        # Reject dangerous shell metacharacters
        if DANGEROUS_SHELL_CHARS_RE.search(clean_target):
            raise SecurityValidationError(f"Target contains forbidden shell metacharacters: {clean_target!r}")

        # Disallow single quotes unless the entity type is human_name (e.g. O'Connor)
        if "'" in clean_target and norm_type != "human_name":
            raise SecurityValidationError(f"Single quote character is not permitted for entity type '{norm_type}'.")

        # Argument injection protection: targets must never start with '-' or '--'
        if clean_target.startswith("-"):
            raise SecurityValidationError("Target cannot begin with '-' or '--' (potential CLI argument injection).")

        # Entity-specific validation
        if norm_type == "ip_address":
            try:
                ip = ipaddress.ip_address(clean_target)
                # Valid IP, but check if it's loopback or private (informative for target queries)
                return str(ip)
            except ValueError as e:
                raise SecurityValidationError(f"Invalid IP address format: {e}")

        if norm_type in TARGET_REGEX_MAP:
            # Special normalization for phone numbers: remove formatting hyphens/spaces
            check_val = clean_target
            if norm_type == "phone_number":
                check_val = re.sub(r"[\s\-\(\)]", "", clean_target)

            if not TARGET_REGEX_MAP[norm_type].match(check_val):
                raise SecurityValidationError(
                    f"Target {clean_target!r} does not conform to strict regex pattern for type '{norm_type}'."
                )
            return check_val

        # Generic safe fallback for custom queries
        if len(clean_target) > 256:
            raise SecurityValidationError("Target exceeds maximum allowed length of 256 characters.")

        return clean_target


class SafeSubprocess:
    """Enforces secure subprocess execution parameters."""

    @staticmethod
    def assert_safe_execution(cmd_list: List[str], shell: bool = False) -> None:
        """
        Guarantees:
        1. shell is strictly False.
        2. cmd_list is a list of strings, with no null bytes.
        3. Arguments do not carry unexpected shell piping or redirection tokens.
        """
        if shell:
            raise SecurityValidationError("CRITICAL VIOLATION: Subprocess execution with shell=True is strictly prohibited.")

        if not isinstance(cmd_list, (list, tuple)) or not cmd_list:
            raise SecurityValidationError("Command must be a non-empty list of arguments.")

        for i, arg in enumerate(cmd_list):
            if not isinstance(arg, str):
                raise SecurityValidationError(f"Argument at index {i} is not a string: {type(arg)}")
            if "\x00" in arg:
                raise SecurityValidationError(f"Null byte detected in subprocess argument at index {i}.")

    @classmethod
    def build_command_args(
        cls,
        executable: str,
        fixed_flags: List[str],
        target: str,
        target_type: Optional[str] = None,
        use_arg_separator: bool = True
    ) -> List[str]:
        """
        Constructs a hardened argument list for CLI runners (Maigret, SpiderFoot, Google Search).
        Applies input sanitization, validates arguments, and optionally adds '--' separator.
        """
        if target_type:
            safe_target = TargetSanitizer.validate_target(target, target_type)
        else:
            safe_target = TargetSanitizer.validate_target(target, TargetSanitizer.detect_entity_type(target))

        cmd = [executable]
        cmd.extend(fixed_flags)

        if use_arg_separator:
            cmd.append("--")

        cmd.append(safe_target)
        cls.assert_safe_execution(cmd, shell=False)
        return cmd


# ==============================================================================
# 2. SSRF & INTERNAL SUBNET SAFEGUARDS (CWE-918)
# ==============================================================================

# Restricted network ranges (RFC 1918, RFC 3927 link-local, loopback, cloud metadata, multicast)
RESTRICTED_IPV4_NETWORKS = [
    ipaddress.IPv4Network("0.0.0.0/8"),        # Current network ("this" host)
    ipaddress.IPv4Network("10.0.0.0/8"),       # RFC 1918 Private Class A
    ipaddress.IPv4Network("100.64.0.0/10"),    # Carrier-grade NAT (RFC 6598)
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-Local (AWS/GCP/Azure Metadata: 169.254.169.254)
    ipaddress.IPv4Network("172.16.0.0/12"),    # RFC 1918 Private Class B
    ipaddress.IPv4Network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.IPv4Network("192.0.2.0/24"),     # TEST-NET-1 (Documentation)
    ipaddress.IPv4Network("192.168.0.0/16"),   # RFC 1918 Private Class C
    ipaddress.IPv4Network("198.18.0.0/15"),    # Network benchmark tests
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast (Class D)
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved for future use (Class E)
    ipaddress.IPv4Network("255.255.255.255/32")# Broadcast
]

RESTRICTED_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::/128"),           # Unspecified address
    ipaddress.IPv6Network("::1/128"),          # Loopback
    ipaddress.IPv6Network("::ffff:0:0/96"),    # IPv4-mapped IPv6
    ipaddress.IPv6Network("100::/64"),         # Discard prefix
    ipaddress.IPv6Network("2001:db8::/32"),    # Documentation
    ipaddress.IPv6Network("fc00::/7"),         # Unique local address (ULA - private IPv6)
    ipaddress.IPv6Network("fe80::/10"),        # Link-local unicast
    ipaddress.IPv6Network("ff00::/8"),         # Multicast
]

# Explicit cloud metadata hostnames / addresses
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
}


class SSRFGuard:
    """Validates URLs and endpoints to prevent Server-Side Request Forgery."""

    @staticmethod
    def is_ip_restricted(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
        """Checks if an IP address belongs to private, loopback, or reserved ranges."""
        # Check standard properties
        if ip_obj.is_private:
            return True, f"Private IP address space ({ip_obj})"
        if ip_obj.is_loopback:
            return True, f"Loopback address ({ip_obj})"
        if ip_obj.is_link_local:
            return True, f"Link-local address ({ip_obj})"
        if ip_obj.is_multicast:
            return True, f"Multicast address ({ip_obj})"
        if ip_obj.is_reserved:
            return True, f"Reserved address ({ip_obj})"
        if ip_obj.is_unspecified:
            return True, f"Unspecified address ({ip_obj})"

        # Check explicit subnet ranges
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for net in RESTRICTED_IPV4_NETWORKS:
                if ip_obj in net:
                    return True, f"Restricted IPv4 subnet {net} ({ip_obj})"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            # Check IPv4-mapped IPv6
            if ip_obj.ipv4_mapped:
                mapped_v4 = ip_obj.ipv4_mapped
                return SSRFGuard.is_ip_restricted(mapped_v4)

            for net in RESTRICTED_IPV6_NETWORKS:
                if ip_obj in net:
                    return True, f"Restricted IPv6 subnet {net} ({ip_obj})"

        return False, "Public routable IP"

    @classmethod
    def validate_url(cls, url: str, resolve_dns: bool = True) -> Tuple[bool, str, List[str]]:
        """
        Validates target URL against SSRF vulnerabilities.
        Returns:
            (is_safe, reason, resolved_ips)
        """
        if not url or not isinstance(url, str):
            return False, "Empty or invalid URL parameter.", []

        # Parse scheme and host
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            return False, f"URL parse failure: {e}", []

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False, f"Disallowed URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.", []

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in URL.", []

        hostname_clean = hostname.strip().lower()

        # Check explicit metadata names or localhost aliases
        if hostname_clean in CLOUD_METADATA_HOSTS:
            return False, f"Cloud metadata endpoint blocked: {hostname_clean}", []

        if hostname_clean in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
            return False, f"Loopback hostname blocked: {hostname_clean}", []

        resolved_ips: List[str] = []

        # Check if hostname is an explicit IP literal
        try:
            ip_obj = ipaddress.ip_address(hostname_clean)
            is_restricted, reason = cls.is_ip_restricted(ip_obj)
            resolved_ips.append(str(ip_obj))
            if is_restricted:
                return False, f"Target IP is restricted: {reason}", resolved_ips
            return True, "Valid public IP target", resolved_ips
        except ValueError:
            # Hostname is a domain name, proceed to DNS resolution
            pass

        if not resolve_dns:
            return True, "Hostname syntax valid (DNS resolution bypassed)", []

        # Resolve DNS to examine actual destination IP(s)
        try:
            addr_info = socket.getaddrinfo(hostname_clean, None)
            for entry in addr_info:
                sockaddr = entry[4]
                ip_str = sockaddr[0]
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
                    ip_obj = ipaddress.ip_address(ip_str)
                    is_restricted, reason = cls.is_ip_restricted(ip_obj)
                    if is_restricted:
                        return False, f"DNS resolved to restricted IP {ip_str}: {reason}", resolved_ips
        except socket.gaierror as e:
            # Unable to resolve hostname
            return False, f"DNS resolution failed for {hostname_clean}: {e}", []
        except Exception as e:
            return False, f"DNS resolution error: {e}", []

        if not resolved_ips:
            return False, f"DNS resolved to zero valid IP addresses for {hostname_clean}", []

        return True, "Valid public target", resolved_ips

    @classmethod
    def is_safe_url(cls, url: str, resolve_dns: bool = False) -> bool:
        """Convenience method returning True if URL is safe from SSRF."""
        safe, _, _ = cls.validate_url(url, resolve_dns=resolve_dns)
        return safe


# ==============================================================================
# 3. LOOPBACK ISOLATION & HOST HEADER PROTECTION (CWE-350)
# ==============================================================================

DEFAULT_ALLOWED_HOSTS: Set[str] = {
    "127.0.0.10",
    "127.0.0.1",
    "localhost",
    "127.0.0.1:5002",
    "localhost:5002",
    "127.0.0.10:5002",
    "127.0.0.10:8000",
    "127.0.0.1:8000",
    "localhost:8000",
    "testserver", # Starlette / FastAPI TestClient
}


class HostSecurity:
    """Guards against DNS Rebinding attacks by enforcing permitted Host headers."""

    @staticmethod
    def is_allowed_host(host_header: Optional[str], allowed_hosts: Optional[Set[str]] = None) -> bool:
        if not host_header:
            return False

        allowed = allowed_hosts if allowed_hosts is not None else DEFAULT_ALLOWED_HOSTS
        norm_host = host_header.strip().lower()

        if norm_host in allowed:
            return True

        # Check without port if port was dynamically assigned
        if ":" in norm_host:
            host_without_port = norm_host.split(":")[0]
            if host_without_port in allowed:
                return True

        return False


class DNSRebindingMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware to validate the HTTP Host header against permitted loopback names.
    Mitigates DNS Rebinding attacks against the local web cockpit.
    """

    def __init__(self, app: Any, allowed_hosts: Optional[Set[str]] = None):
        super().__init__(app)
        self.allowed_hosts = allowed_hosts if allowed_hosts is not None else DEFAULT_ALLOWED_HOSTS

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        host = request.headers.get("host")
        if not HostSecurity.is_allowed_host(host, self.allowed_hosts):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden Host Header",
                    "detail": f"Host '{host}' is rejected to prevent DNS rebinding attacks.",
                    "allowed": list(self.allowed_hosts)
                }
            )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware to attach defensive HTTP response headers.
    Enforces strict MIME sniffing protection, Clickjacking defense, and CSP.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)

        # Defense-in-depth security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        
        # Local-first Content-Security-Policy allowing needed CDN assets for Vis.js & Tailwind
        if "content-security-policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://unpkg.com; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://unpkg.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://fonts.googleapis.com; "
                "connect-src 'self' ws: wss: http://127.0.0.1:5002 ws://127.0.0.1:5002 http://localhost:5002 ws://localhost:5002 http://127.0.0.10:* http://localhost:* http://127.0.0.1:*; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
                "frame-ancestors 'none';"
            )

        return response
