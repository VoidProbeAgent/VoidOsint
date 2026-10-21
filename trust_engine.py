"""
VoidOsint Multi-Factor Trust Scoring Engine
===========================================
Mathematical confidence scoring and heuristic verification pipeline for OSINT discoveries.

Evaluates response validity (HTTP status, soft-404 / false 200 heuristics),
string closeness (Levenshtein & token sort ratios), cross-tool consensus,
and applies defensive penalties for WAF challenges, login walls, and parked domains.

Complies strictly with Section 5 of hive/specs/osint-platform-spec.md.
"""

from __future__ import annotations

import re
import asyncio
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, parse_qs
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums and Data Models
# ---------------------------------------------------------------------------

class TrustGrade(str, Enum):
    """Visual trust grade assigned to an OSINT discovery."""
    CONFIRMED = "CONFIRMED"           # 85 - 100: Verified match, cross-corroborated, clean 200 OK
    HIGH = "HIGH"                     # 70 - 84:  High confidence, clean DOM, near-exact name
    PROBABLE = "PROBABLE"             # 50 - 69:  Plausible match, single engine, slight variance
    SUSPICIOUS = "SUSPICIOUS"         # 30 - 49:  Low similarity or partial soft-404 markers
    FALSE_POSITIVE = "FALSE_POSITIVE" # 0 - 29:   Verified soft-404, error page, non-matching entity


class TrustMetrics(BaseModel):
    """Multi-factor trust evaluation results for an OSINT discovery."""
    validity_score: float = Field(..., ge=0.0, le=1.0, description="Response validity score [0.0, 1.0]")
    accuracy_score: float = Field(..., ge=0.0, le=1.0, description="String and entity closeness score [0.0, 1.0]")
    consensus_score: float = Field(..., ge=0.0, le=1.0, description="Cross-tool corroboration score [0.0, 1.0]")
    penalty: float = Field(default=0.0, ge=0.0, le=1.0, description="Deductions applied [0.0, 0.40]")
    composite_score: float = Field(..., ge=0.0, le=100.0, description="Composite trust score [0.0, 100.0]")
    grade: TrustGrade = Field(..., description="Visual trust grade classification")
    audit_trail: List[str] = Field(default_factory=list, description="Audit log of heuristic rules triggered")

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for API/WebSocket/DB storage."""
        return self.model_dump()

    @property
    def is_confirmed(self) -> bool:
        return self.grade == TrustGrade.CONFIRMED

    @property
    def is_false_positive(self) -> bool:
        return self.grade == TrustGrade.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Heuristic Lexicons and Patterns
# ---------------------------------------------------------------------------

# Critical soft-404 phrases indicating non-existent user or missing content
SOFT_404_PHRASES: Tuple[str, ...] = (
    "user not found",
    "profile not found",
    "account not found",
    "page not found",
    "member not found",
    "author not found",
    "channel not found",
    "account does not exist",
    "user does not exist",
    "profile does not exist",
    "page does not exist",
    "channel does not exist",
    "profile unavailable",
    "account unavailable",
    "user unavailable",
    "profile doesn't exist",
    "page removed",
    "page has been removed",
    "content not available",
    "this content is not available",
    "content unavailable",
    "no longer with us",
    "nobody by this name",
    "no user with this name",
    "the user you are looking for does not exist",
    "the specified profile could not be found",
    "sorry, this page isn't available",
    "this page isn't available",
    "this page is not available",
    "this account has been suspended",
    "account has been suspended",
    "account suspended",
    "user suspended",
    "user disabled",
    "user has been deleted",
    "deleted user",
    "404 not found",
    "404 error",
    "error 404",
    "page cannot be found",
    "we couldn't find that page",
    "nothing here",
    "there's nothing here",
    "nothing to see here",
    "does not exist on this server",
    "item not found",
    "does not exist anymore",
)

# DOM markers commonly found in 404/error templates
DOM_ERROR_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r'class=["\'][^"\']*\b(error-404|not-found|profile-not-found|user-not-found|empty-state-404|error-page|error-container)\b[^"\']*["\']', re.IGNORECASE),
    re.compile(r'id=["\'][^"\']*\b(error-404|not-found|user-not-found|error-page)\b[^"\']*["\']', re.IGNORECASE),
    re.compile(r'<h[1-3][^>]*>\s*(404|not found|page not found|user not found|error|access denied)\s*</h[1-3]>', re.IGNORECASE),
    re.compile(r'<title>\s*(404|not found|error)\s*</title>', re.IGNORECASE),
)

# CAPTCHA, WAF challenges, and anti-bot barriers
WAF_CHALLENGE_PATTERNS: Tuple[str, ...] = (
    "attention required! | cloudflare",
    "cf-browser-verification",
    "ddos protection by cloudflare",
    "just a moment...",
    "please verify you are a human",
    "verify you are human",
    "challenge-platform",
    "challenge-running",
    "recaptcha",
    "hcaptcha",
    "perimeterx",
    "incapsula",
    "access denied | ray id",
    "checking your browser",
    "security check to continue",
)

# Parked and for-sale domain signatures
PARKED_DOMAIN_PATTERNS: Tuple[str, ...] = (
    "buy this domain",
    "domain is for sale",
    "domain name is for sale",
    "parked domain",
    "hugedomains",
    "dan.com",
    "godaddy parking",
    "sedo parking",
    "this domain is registered and protected",
    "inquire about this domain",
    "parking page",
)

# Generic title suffixes to discard during title-based candidate extraction
GENERIC_PLATFORM_TOKENS: Set[str] = {
    "github", "gitlab", "bitbucket", "twitter", "x", "instagram", "facebook",
    "linkedin", "reddit", "youtube", "tiktok", "pinterest", "medium", "devto",
    "twitch", "steam", "spotify", "soundcloud", "flickr", "tumblr", "mastodon",
    "threads", "patreon", "telegram", "discord", "home", "profile", "user"
}


# ---------------------------------------------------------------------------
# String Closeness Algorithms
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Compute Levenshtein edit distance between two strings using two-row dynamic programming.
    Runs in O(min(len1, len2)) space and minimal CPU overhead.
    """
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    # Keep s1 as the shorter string for space optimization
    if len1 > len2:
        s1, s2 = s2, s1
        len1, len2 = len2, len1

    prev_row = list(range(len1 + 1))
    for j, c2 in enumerate(s2):
        curr_row = [j + 1] * (len1 + 1)
        for i, c1 in enumerate(s1):
            cost = 0 if c1 == c2 else 1
            curr_row[i + 1] = min(
                curr_row[i] + 1,       # Insertion
                prev_row[i + 1] + 1,   # Deletion
                prev_row[i] + cost     # Substitution
            )
        prev_row = curr_row

    return prev_row[len1]


def levenshtein_ratio(s1: str, s2: str) -> float:
    """
    Normalized Levenshtein similarity ratio in [0.0, 1.0].
    1.0 = identical; 0.0 = completely disjoint.
    """
    clean1 = s1.lower().strip()
    clean2 = s2.lower().strip()
    if clean1 == clean2:
        return 1.0
    max_len = max(len(clean1), len(clean2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(clean1, clean2)
    return max(0.0, 1.0 - (dist / max_len))


def token_sort_ratio(s1: str, s2: str) -> float:
    """
    Tokenize strings, sort tokens alphabetically, and compute Levenshtein ratio.
    Addresses out-of-order words (e.g., 'Doe, John' vs 'John Doe').
    """
    def _tokenize_and_sort(text: str) -> str:
        tokens = [t for t in re.split(r'[^a-zA-Z0-9]+', text.lower()) if t]
        tokens.sort()
        return " ".join(tokens)

    sorted1 = _tokenize_and_sort(s1)
    sorted2 = _tokenize_and_sort(s2)
    if not sorted1 and not sorted2:
        return 1.0
    return levenshtein_ratio(sorted1, sorted2)


def hybrid_fuzzy_closeness(target: str, candidate: str) -> float:
    """
    Formula from Spec Section 5:
    S_fuzzy = 0.5 * LevenshteinRatio(target, match) + 0.5 * TokenSortRatio(target, match)
    """
    lev = levenshtein_ratio(target, candidate)
    tok = token_sort_ratio(target, candidate)
    return 0.5 * lev + 0.5 * tok


# ---------------------------------------------------------------------------
# Trust Engine Core Implementation
# ---------------------------------------------------------------------------

class TrustEngine:
    """
    Multi-Factor Trust Scoring Engine for VoidOsint.
    
    Formula:
    T_composite = max(0, min(100, (w1*S_validity + w2*S_accuracy + w3*S_consensus - P_penalty) * 100))
    Where:
      w1 = 0.40 (Response validity / soft-404)
      w2 = 0.35 (Accuracy / string closeness)
      w3 = 0.25 (Consensus across active engines)
      P_penalty in [0.0, 0.40] (WAF, soft-404, login barriers, parked domains, mismatch)
    """

    DEFAULT_W_VALIDITY: float = 0.40
    DEFAULT_W_ACCURACY: float = 0.35
    DEFAULT_W_CONSENSUS: float = 0.25
    MAX_PENALTY: float = 0.40

    def __init__(
        self,
        w_validity: float = DEFAULT_W_VALIDITY,
        w_accuracy: float = DEFAULT_W_ACCURACY,
        w_consensus: float = DEFAULT_W_CONSENSUS,
        max_penalty: float = MAX_PENALTY,
    ):
        self.w_validity = w_validity
        self.w_accuracy = w_accuracy
        self.w_consensus = w_consensus
        self.max_penalty = max_penalty

    # -----------------------------------------------------------------------
    # Heuristic Sub-Evaluators
    # -----------------------------------------------------------------------

    def detect_soft_404(
        self,
        status_code: int,
        title: str,
        body_text: str,
        url: str = "",
    ) -> Tuple[float, float, bool, List[str]]:
        """
        Evaluate response validity and detect soft-404 / false 200 responses.
        
        Returns:
            Tuple of (validity_score in [0.0, 1.0], soft_404_penalty in [0.0, 0.35], is_soft_404: bool, audit_trail)
        """
        audit: List[str] = []
        soft_404_penalty = 0.0
        is_soft_404 = False

        # Hard HTTP status check
        if status_code in (404, 410):
            audit.append(f"HTTP status {status_code} confirms resource does not exist")
            return 0.0, 0.30, True, audit

        if status_code >= 500:
            audit.append(f"HTTP status {status_code} indicates server error / endpoint unavailable")
            return 0.0, 0.20, True, audit

        if status_code in (401, 403):
            audit.append(f"HTTP status {status_code} indicates access forbidden or auth required")
            return 0.15, 0.15, False, audit

        clean_title = (title or "").lower().strip()
        clean_body = (body_text or "").lower()
        combined_text = f"{clean_title} {clean_body}"

        # 1. Anti-Bot / WAF Challenge Barrier Check
        for marker in WAF_CHALLENGE_PATTERNS:
            if marker in combined_text or marker in clean_title:
                audit.append(f"WAF/CAPTCHA challenge detected on endpoint: '{marker}'")
                return 0.10, 0.0, False, audit

        # 2. Parked Domain Check
        for marker in PARKED_DOMAIN_PATTERNS:
            if marker in combined_text:
                audit.append(f"Parked / for-sale domain detected: '{marker}'")
                return 0.10, 0.0, False, audit

        # Baseline validity for 200 OK
        validity = 1.0 if status_code == 200 else 0.80
        if status_code == 200:
            audit.append("HTTP 200 OK response baseline established")
        else:
            audit.append(f"HTTP status {status_code} received")

        # 3. Soft-404 Negative Indicator in Title (Highest Confidence Signal)
        for phrase in SOFT_404_PHRASES:
            if phrase in clean_title:
                validity = 0.02
                soft_404_penalty = 0.30
                is_soft_404 = True
                audit.append(f"Soft-404 marker in title: '{phrase}'")
                break

        # 4. Soft-404 Negative Indicator in Body Text
        if not is_soft_404:
            for phrase in SOFT_404_PHRASES:
                if phrase in clean_body:
                    validity = 0.05
                    soft_404_penalty = 0.30
                    is_soft_404 = True
                    audit.append(f"Soft-404 phrase in page body: '{phrase}'")
                    break

        # 5. DOM Structural 404 Markers
        if not is_soft_404:
            for pattern in DOM_ERROR_PATTERNS:
                if pattern.search(body_text or ""):
                    validity = 0.05
                    soft_404_penalty = 0.30
                    is_soft_404 = True
                    audit.append("DOM structural error pattern matched")
                    break

        # 6. Minimum Content Length Threshold Heuristic on Full HTML Pages
        raw_body = (body_text or "").strip()
        is_html_document = bool(re.search(r'(<!doctype|<html|<body|<div)', raw_body, re.IGNORECASE))
        if is_html_document and not is_soft_404:
            if len(raw_body) < 300:
                # Check if short body is explicitly an error stub
                if any(w in clean_body for w in ("error", "not found", "404", "denied", "unavailable")):
                    validity = 0.05
                    soft_404_penalty = 0.30
                    is_soft_404 = True
                    audit.append(f"Short HTML error stub ({len(raw_body)} bytes < 300 threshold)")
                else:
                    validity = max(0.20, validity - 0.50)
                    audit.append(f"Short HTML response body on platform ({len(raw_body)} bytes < 300 threshold)")

        validity = max(0.0, min(1.0, validity))
        return validity, soft_404_penalty, is_soft_404, audit

    def calculate_string_accuracy(
        self,
        target: str,
        query_type: str,
        url: str,
        title: str = "",
        body_text: str = "",
        is_soft_404: bool = False,
    ) -> Tuple[float, float, List[str]]:
        """
        Evaluate string match and entity closeness between search target and discovery.
        
        Returns:
            Tuple of (accuracy_score in [0.0, 1.0], mismatch_penalty in [0.0, 0.25], audit_trail)
        """
        audit: List[str] = []
        norm_target = target.strip().lower()

        if not norm_target:
            audit.append("Empty target query provided")
            return 0.0, 0.25, audit

        # If confirmed soft-404, the page does not represent the target entity
        if is_soft_404:
            audit.append("Entity presence negated due to soft-404 validation failure")
            return 0.05, 0.0, audit

        # Extract candidate tokens from URL
        candidates: List[str] = []
        parsed_url = urlparse(url)
        path = parsed_url.path.strip("/")
        if path:
            path_segments = [p for p in path.split("/") if p]
            # Strip file extensions
            stripped_segments = [re.sub(r'\.(html|htm|php|aspx|jsp)$', '', s, flags=re.I) for s in path_segments]
            # Filter generic routing tokens
            meaningful_segments = [
                s for s in stripped_segments
                if s.lower() not in {"user", "users", "u", "profile", "profiles", "p", "id", "c", "channel", "in", "pub", "accounts"}
            ]
            if meaningful_segments:
                candidates.extend(meaningful_segments)
            elif stripped_segments:
                candidates.append(stripped_segments[-1])

        # Check URL query parameters (e.g. ?user=target, ?u=target)
        if parsed_url.query:
            q_params = parse_qs(parsed_url.query)
            for k in ("user", "username", "u", "id", "q", "name", "login"):
                if k in q_params and q_params[k]:
                    candidates.append(q_params[k][0])

        # Extract candidate tokens from Title
        clean_title = (title or "").strip()
        if clean_title:
            title_parts = [t.strip() for t in re.split(r'[-|•·—:(),]+', clean_title) if t.strip()]
            for part in title_parts:
                part_lower = part.lower()
                if part_lower not in GENERIC_PLATFORM_TOKENS and len(part) >= 2:
                    candidates.append(part)

        best_score = 0.0
        best_candidate = ""
        best_match_type = ""

        # Entity-specific preprocessing
        if query_type == "email":
            email_handle = norm_target.split("@")[0] if "@" in norm_target else norm_target
            effective_targets = [norm_target, email_handle]
        elif query_type in ("domain", "subdomain"):
            effective_targets = [norm_target]
            if parsed_url.netloc:
                candidates.append(parsed_url.netloc)
                candidates.append(parsed_url.netloc.replace("www.", ""))
        elif query_type == "phone_number":
            target_digits = re.sub(r'\D', '', norm_target)
            effective_targets = [target_digits]
            found_digits = re.sub(r'\D', '', url + " " + title + " " + (body_text or "")[:500])
            if target_digits and target_digits in found_digits:
                audit.append("Exact phone number digits match found in discovery")
                return 1.0, 0.0, audit
        elif query_type == "ip_address":
            effective_targets = [norm_target]
            if parsed_url.netloc == norm_target or parsed_url.hostname == norm_target:
                audit.append("Exact IP address match on hostname")
                return 1.0, 0.0, audit
        else:
            effective_targets = [norm_target]

        # Evaluate similarity across all candidates
        for eff_target in effective_targets:
            eff_alphanumeric = re.sub(r'[^a-zA-Z0-9]', '', eff_target)

            for cand in candidates:
                cand_norm = cand.strip().lower()
                cand_alphanumeric = re.sub(r'[^a-zA-Z0-9]', '', cand_norm)

                # 1. Exact Match
                if cand_norm == eff_target:
                    score = 1.0
                    match_type = "Exact string match"
                # 2. Candidate contains spaces for a username query (e.g. 'John Doe' vs 'johndoe')
                elif " " in cand_norm and query_type == "username":
                    if eff_alphanumeric and cand_alphanumeric and cand_alphanumeric == eff_alphanumeric:
                        score = 0.84
                        match_type = "Display name alignment to handle"
                    else:
                        score = min(0.80, hybrid_fuzzy_closeness(eff_target, cand_norm))
                        match_type = f"Fuzzy display name closeness ({score:.2f})"
                # 3. Normalized Alphanumeric Match without spaces (e.g. john-doe vs johndoe)
                elif eff_alphanumeric and cand_alphanumeric and cand_alphanumeric == eff_alphanumeric:
                    score = 0.98
                    match_type = "Normalized alphanumeric exact match"
                # 4. Contiguous Substring with Delimiter (e.g. johndoe_dev)
                elif eff_target in cand_norm or cand_norm in eff_target:
                    shorter = min(len(eff_target), len(cand_norm))
                    longer = max(len(eff_target), len(cand_norm))
                    len_ratio = shorter / longer if longer > 0 else 1.0
                    delimited = bool(re.search(rf'(\b|[-_.0-9]){re.escape(eff_target)}(\b|[-_.0-9])', cand_norm))
                    score = min(0.85, 0.74 + 0.12 * len_ratio) if delimited else min(0.78, 0.65 + 0.15 * len_ratio)
                    match_type = "Delimited substring match" if delimited else "Substring match"
                # 5. Hybrid Fuzzy Match
                else:
                    score = hybrid_fuzzy_closeness(eff_target, cand_norm)
                    match_type = f"Hybrid fuzzy closeness ({score:.2f})"

                if score > best_score:
                    best_score = score
                    best_candidate = cand
                    best_match_type = match_type

        # Check if target appears directly in page title or body if candidate matches are low
        clean_body_sample = (body_text or "")[:3000].lower()
        if norm_target in clean_title.lower() and best_score < 0.85:
            best_score = max(best_score, 0.85)
            best_match_type = "Target query present in page title"
        elif norm_target in clean_body_sample and best_score < 0.65:
            best_score = max(best_score, 0.65)
            best_match_type = "Target query present in page body"

        best_score = max(0.0, min(1.0, best_score))

        # Check for non-matching entity mismatch penalty
        mismatch_penalty = 0.0
        if best_score < 0.25:
            mismatch_penalty = 0.20
            audit.append(f"Accuracy: Low string alignment between '{norm_target}' and discovery tokens (< 0.25)")
        else:
            audit.append(f"Accuracy: {best_match_type} on '{best_candidate or norm_target}' (score: {best_score:.2f})")

        return best_score, mismatch_penalty, audit

    def calculate_consensus(
        self,
        active_engines: Optional[Sequence[str]] = None,
        confirming_engines: Optional[Sequence[str]] = None,
        contradiction: bool = False,
    ) -> Tuple[float, List[str]]:
        """
        Evaluate cross-tool consensus corroboration.
        
        Rules:
          - Contradiction: 0.0
          - 0 confirming engines: 0.0
          - 1 confirming engine: 0.50
          - 2 confirming engines: 0.85
          - 3+ confirming engines: 1.00
          
        Returns:
            Tuple of (consensus_score in [0.0, 1.0], audit_trail)
        """
        audit: List[str] = []

        if contradiction:
            audit.append("Consensus contradiction: An active engine explicitly verified non-existence (score: 0.00)")
            return 0.0, audit

        conf_set = set(confirming_engines or [])
        active_set = set(active_engines or [])
        n_confirming = len(conf_set)
        n_active = max(len(active_set), n_confirming)

        if n_confirming == 0:
            audit.append("Cross-tool consensus: 0 engines confirmed discovery (score: 0.00)")
            return 0.0, audit
        elif n_confirming == 1:
            engine_name = list(conf_set)[0]
            audit.append(f"Single tool discovery confirmed by '{engine_name}' ({n_confirming}/{n_active} engines, score: 0.50)")
            return 0.50, audit
        elif n_confirming == 2:
            names = ", ".join(sorted(conf_set))
            audit.append(f"Dual tool corroboration confirmed by {names} ({n_confirming}/{n_active} engines, score: 0.85)")
            return 0.85, audit
        else:
            names = ", ".join(sorted(conf_set))
            audit.append(f"Multi-engine unanimous consensus confirmed by {names} ({n_confirming}/{n_active} engines, score: 1.00)")
            return 1.00, audit

    def calculate_penalties(
        self,
        url: str,
        title: str,
        body_text: str,
        soft_404_penalty: float = 0.0,
        mismatch_penalty: float = 0.0,
    ) -> Tuple[float, List[str]]:
        """
        Evaluate penalties for WAF challenges, login walls, parked domains, soft-404s, and mismatches.
        
        Returns:
            Tuple of (penalty in [0.0, max_penalty], audit_trail)
        """
        audit: List[str] = []
        total_penalty = soft_404_penalty + mismatch_penalty

        if soft_404_penalty > 0.0:
            audit.append(f"Penalty: Soft-404 / false 200 deduction (+{soft_404_penalty:.2f})")
        if mismatch_penalty > 0.0:
            audit.append(f"Penalty: Non-matching entity deduction (+{mismatch_penalty:.2f})")

        clean_url = (url or "").lower()
        clean_title = (title or "").lower()
        clean_body = (body_text or "")[:4000].lower()
        combined_text = f"{clean_title} {clean_body}"

        # 1. WAF / CAPTCHA / Cloudflare Anti-Bot Challenge
        for marker in WAF_CHALLENGE_PATTERNS:
            if marker in combined_text or marker in clean_title:
                total_penalty += 0.30
                audit.append(f"Penalty: Anti-bot/WAF challenge barrier detected ('{marker}') (+0.30)")
                break

        # 2. Parked or For-Sale Domain
        for marker in PARKED_DOMAIN_PATTERNS:
            if marker in combined_text:
                total_penalty += 0.35
                audit.append(f"Penalty: Parked or for-sale domain detected ('{marker}') (+0.35)")
                break

        # 3. Authentication Wall / Login Redirection
        parsed = urlparse(url)
        path = parsed.path.lower().rstrip("/")
        is_login_path = path in {"/login", "/signin", "/auth", "/session/new", "/accounts/login", "/login.php"}
        has_login_query = any(k in parsed.query.lower() for k in ("next=", "return_to=", "redirect=", "auth="))
        is_login_title = any(clean_title.startswith(p) for p in ("log in", "login", "sign in", "signin"))

        if is_login_path or has_login_query or is_login_title:
            total_penalty += 0.20
            audit.append("Penalty: Authentication wall / login barrier redirection detected (+0.20)")

        # Cap total penalty at configured max
        capped_penalty = min(self.max_penalty, total_penalty)
        return capped_penalty, audit

    # -----------------------------------------------------------------------
    # Grade Classification
    # -----------------------------------------------------------------------

    @staticmethod
    def classify_grade(composite_score: float) -> TrustGrade:
        """
        Map a composite 0-100 score to its visual TrustGrade.
        
        CONFIRMED (>=85), HIGH (70-84), PROBABLE (50-69), SUSPICIOUS (30-49), FALSE_POSITIVE (<30).
        """
        if composite_score >= 85.0:
            return TrustGrade.CONFIRMED
        elif composite_score >= 70.0:
            return TrustGrade.HIGH
        elif composite_score >= 50.0:
            return TrustGrade.PROBABLE
        elif composite_score >= 30.0:
            return TrustGrade.SUSPICIOUS
        else:
            return TrustGrade.FALSE_POSITIVE

    # -----------------------------------------------------------------------
    # Synchronous and Asynchronous Evaluation
    # -----------------------------------------------------------------------

    def evaluate(
        self,
        target: str,
        query_type: str = "username",
        url: str = "",
        title: str = "",
        body_text: str = "",
        status_code: int = 200,
        active_engines: Optional[Sequence[str]] = None,
        confirming_engines: Optional[Sequence[str]] = None,
        contradiction: bool = False,
    ) -> TrustMetrics:
        """
        Synchronously evaluate an OSINT discovery and return TrustMetrics.
        Execution runs under 1ms with zero external network blocking.
        """
        audit_trail: List[str] = []

        # 1. Validity & Soft-404 Analysis
        validity_score, soft_404_penalty, is_soft_404, val_audit = self.detect_soft_404(
            status_code=status_code,
            title=title,
            body_text=body_text,
            url=url,
        )
        audit_trail.extend(val_audit)

        # 2. String Closeness & Accuracy Analysis
        accuracy_score, mismatch_penalty, acc_audit = self.calculate_string_accuracy(
            target=target,
            query_type=query_type,
            url=url,
            title=title,
            body_text=body_text,
            is_soft_404=is_soft_404,
        )
        audit_trail.extend(acc_audit)

        # 3. Cross-Tool Consensus Analysis
        consensus_score, con_audit = self.calculate_consensus(
            active_engines=active_engines,
            confirming_engines=confirming_engines,
            contradiction=contradiction,
        )
        audit_trail.extend(con_audit)

        # 4. Defensive Penalties
        penalty, pen_audit = self.calculate_penalties(
            url=url,
            title=title,
            body_text=body_text,
            soft_404_penalty=soft_404_penalty,
            mismatch_penalty=mismatch_penalty,
        )
        audit_trail.extend(pen_audit)

        # 5. Composite Score Calculation
        # T = max(0, min(100, (w1*S_val + w2*S_acc + w3*S_con - P) * 100))
        raw_composite = (
            self.w_validity * validity_score
            + self.w_accuracy * accuracy_score
            + self.w_consensus * consensus_score
            - penalty
        ) * 100.0

        composite_score = round(max(0.0, min(100.0, raw_composite)), 2)

        # 6. Trust Grade Assignment
        grade = self.classify_grade(composite_score)
        audit_trail.append(f"Trust Evaluation Complete: Score={composite_score:.2f}, Grade={grade.value}")

        return TrustMetrics(
            validity_score=round(validity_score, 4),
            accuracy_score=round(accuracy_score, 4),
            consensus_score=round(consensus_score, 4),
            penalty=round(penalty, 4),
            composite_score=composite_score,
            grade=grade,
            audit_trail=audit_trail,
        )

    async def evaluate_async(
        self,
        target: str,
        query_type: str = "username",
        url: str = "",
        title: str = "",
        body_text: str = "",
        status_code: int = 200,
        active_engines: Optional[Sequence[str]] = None,
        confirming_engines: Optional[Sequence[str]] = None,
        contradiction: bool = False,
    ) -> TrustMetrics:
        """
        Asynchronously evaluate an OSINT discovery.
        Yields control to event loop ensuring zero thread starvation in high-throughput streams.
        """
        await asyncio.sleep(0)
        return self.evaluate(
            target=target,
            query_type=query_type,
            url=url,
            title=title,
            body_text=body_text,
            status_code=status_code,
            active_engines=active_engines,
            confirming_engines=confirming_engines,
            contradiction=contradiction,
        )


# ---------------------------------------------------------------------------
# Global Singleton and Top-Level Async Dispatcher
# ---------------------------------------------------------------------------

_GLOBAL_TRUST_ENGINE = TrustEngine()


async def evaluate_discovery(
    target: str,
    query_type: str = "username",
    url: str = "",
    title: str = "",
    body_text: str = "",
    status_code: int = 200,
    active_engines: Optional[Sequence[str]] = None,
    confirming_engines: Optional[Sequence[str]] = None,
    contradiction: bool = False,
) -> TrustMetrics:
    """
    Top-level asynchronous entry point for evaluating an OSINT discovery.
    Matches the exact signature specified in Section 5 and contract MMF-6.
    
    Args:
        target: The queried entity target (handle, domain, name, etc.).
        query_type: Target entity type ('username', 'domain', 'email', etc.).
        url: The discovered URL.
        title: Discovered page or metadata title.
        body_text: Discovered page body text or snippet.
        status_code: HTTP response status code (default 200).
        active_engines: List of engines executed during the scan.
        confirming_engines: List of engines that found or corroborated this discovery.
        contradiction: Whether any engine explicitly disproved existence.
        
    Returns:
        TrustMetrics containing validity, accuracy, consensus, penalties, composite score, and grade.
    """
    return await _GLOBAL_TRUST_ENGINE.evaluate_async(
        target=target,
        query_type=query_type,
        url=url,
        title=title,
        body_text=body_text,
        status_code=status_code,
        active_engines=active_engines,
        confirming_engines=confirming_engines,
        contradiction=contradiction,
    )


def evaluate_discovery_sync(
    target: str,
    query_type: str = "username",
    url: str = "",
    title: str = "",
    body_text: str = "",
    status_code: int = 200,
    active_engines: Optional[Sequence[str]] = None,
    confirming_engines: Optional[Sequence[str]] = None,
    contradiction: bool = False,
) -> TrustMetrics:
    """Synchronous convenience wrapper for non-async callers."""
    return _GLOBAL_TRUST_ENGINE.evaluate(
        target=target,
        query_type=query_type,
        url=url,
        title=title,
        body_text=body_text,
        status_code=status_code,
        active_engines=active_engines,
        confirming_engines=confirming_engines,
        contradiction=contradiction,
    )
