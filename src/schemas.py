"""Structured result objects for the phishing-rag-mvp pipeline.

Plain ``dataclasses`` are used (instead of pydantic) to keep the dependency
footprint small. Every dataclass exposes a ``to_dict`` helper so results can be
serialised to JSON for reports and the Streamlit ``st.json`` viewer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class URLFeatureResult:
    """Features extracted from a single URL."""

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    domain: str
    suffix: str
    path: str
    query: str
    url_length: int
    hostname_length: int
    number_of_dots: int
    number_of_hyphens: int
    number_of_digits: int
    number_of_subdomains: int
    contains_ip_address: bool
    contains_at_symbol: bool
    contains_punycode: bool
    uses_https: bool
    suspicious_keywords_found: List[str] = field(default_factory=list)
    suspicious_keywords_in_host: List[str] = field(default_factory=list)
    is_shortened_url: bool = False
    entropy_score: float = 0.0
    registered_domain: str = ""
    impersonated_brand: str = ""
    lookalike_brand: str = ""
    suspicious_tld: bool = False
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrawlResult:
    """Result of (safely) fetching a webpage or loading sample HTML."""

    requested_url: str
    final_url: str
    status_code: Optional[int]
    redirect_chain: List[str] = field(default_factory=list)
    html: str = ""
    visible_text: str = ""
    page_title: str = ""
    source: str = "live"  # "live" or "sample"
    success: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Avoid dumping huge HTML blobs into reports; keep a trimmed preview.
        data["html"] = self.html[:2000]
        data["visible_text"] = self.visible_text[:2000]
        return data


@dataclass
class HTMLAnalysisResult:
    """Structured analysis of HTML and visible page text."""

    page_title: str = ""
    meta_description: str = ""
    number_of_forms: int = 0
    number_of_password_fields: int = 0
    number_of_input_fields: int = 0
    number_of_external_links: int = 0
    number_of_script_tags: int = 0
    suspicious_keywords_found: List[str] = field(default_factory=list)
    brand_like_words: List[str] = field(default_factory=list)
    credential_request_detected: bool = False
    credential_patterns_found: List[str] = field(default_factory=list)
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PromptInjectionResult:
    """Result of scanning page content for prompt-injection attempts."""

    injection_detected: bool = False
    matched_patterns: List[str] = field(default_factory=list)
    suspicious_snippets: List[str] = field(default_factory=list)
    severity: str = "low"  # low / medium / high
    found_in_hidden: bool = False
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BrandCheckResult:
    """Result of comparing brand-like words on the page with the domain."""

    detected_brands: List[str] = field(default_factory=list)
    registered_domain: str = ""
    brand_domain_match: bool = False
    possible_brand_mismatch: bool = False
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RetrievedEvidence:
    """A single knowledge-base entry returned by the RAG retriever."""

    id: str
    title: str
    category: str
    source_type: str
    trust_level: str
    content: str
    indicators: List[str] = field(default_factory=list)
    recommended_action: str = ""
    similarity_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatIntelResult:
    """Result of checking a URL/domain against external threat-intel feeds.

    ``checked`` records whether any feed was actually consulted (so an offline
    demo with no data is distinguishable from a genuine "not listed" result).
    ``listed`` is the actual hit. ``source`` names the feed that matched.
    """

    checked: bool = False
    listed: bool = False
    source: str = ""  # matched feed, e.g. "OpenPhish" / "PhishTank" ("" if none)
    sources_checked: List[str] = field(default_factory=list)
    matched_value: str = ""  # the URL or domain that matched (for evidence)
    confidence_note: str = ""
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomainIntelResult:
    """Domain-reputation signals: WHOIS age, DNS records, TLS certificate.

    Each source carries its own ``*_available`` flag so the UI can honestly show
    "data not available" when a lookup timed out or failed (WHOIS especially is
    flaky). ``checked`` is False when domain intel was disabled or skipped.
    """

    checked: bool = False
    domain: str = ""
    # --- WHOIS ---
    whois_available: bool = False
    registrar: str = ""
    domain_created: str = ""  # ISO date, e.g. "2019-05-04"
    domain_age_days: Optional[int] = None
    is_newly_registered: Optional[bool] = None  # age < configured threshold
    registrant_country: str = ""
    registrant_email: str = ""
    # --- DNS ---
    dns_available: bool = False
    resolves: Optional[bool] = None  # has at least one A record
    has_mx: Optional[bool] = None
    # --- TLS (HTTPS URLs only) ---
    tls_available: bool = False
    cert_issuer: str = ""
    cert_org: str = ""  # certificate SUBJECT organization (OV/EV only; DV = empty)
    cert_valid_from: str = ""
    cert_valid_until: str = ""
    cert_currently_valid: Optional[bool] = None
    cert_self_signed: Optional[bool] = None
    # --- ASN / IP geolocation (OPTIONAL, LOW confidence) ---
    asn_available: bool = False
    ip_country: str = ""
    asn_org: str = ""
    # --- Cross-signal conflict layer (novel) ---
    conflict_count: int = 0
    conflicts: List[str] = field(default_factory=list)  # names of conflicts that fired
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MultimodalResult:
    """Optional screenshot + OCR analysis of the rendered page.

    ``checked`` is False when the stage was disabled/skipped; ``available`` is
    True only when a screenshot was captured and OCR ran successfully. All OCR
    text is treated as UNTRUSTED (scanned for prompt injection, never obeyed).
    """

    checked: bool = False
    available: bool = False
    screenshot_path: str = ""
    ocr_char_count: int = 0
    ocr_text_excerpt: str = ""  # bounded, untrusted — for evidence display only
    # Signal 1: text OCR sees rendered but that is weakly present in the DOM text.
    text_divergence: bool = False
    divergence_ratio: float = 0.0
    divergent_terms: List[str] = field(default_factory=list)
    # Signal 2: a known brand name in the screenshot whose domain does not match.
    brand_in_image: str = ""
    # OCR is an injection surface ("Clouding the Mirror"): hidden instructions can
    # be rendered as low-contrast/tiny image text. Detected, reported, never obeyed.
    injection_in_ocr: bool = False
    injection_severity: str = "low"
    note: str = ""
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomSnapshot:
    """Counts of credential-relevant DOM elements at one point in time."""

    forms: int = 0
    inputs: int = 0
    password_fields: int = 0
    visible_password_fields: int = 0
    hidden_inputs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicAnalysisResult:
    """Pre- vs post-interaction DOM diff, to catch content revealed only after
    rendering/interaction (a deliberate cloaking technique static HTML misses).

    ``checked`` is False when the stage was disabled/skipped; ``available`` is
    True only when the page was rendered and both snapshots were taken.
    """

    checked: bool = False
    available: bool = False
    clicked_login: bool = False
    pre: DomSnapshot = field(default_factory=DomSnapshot)
    post: DomSnapshot = field(default_factory=DomSnapshot)
    # ABSOLUTE deltas (the key case is 0 -> 1 password field appearing).
    delta_forms: int = 0
    delta_inputs: int = 0
    delta_password_fields: int = 0
    delta_visible_password_fields: int = 0
    cloaking_detected: bool = False
    reasons: List[str] = field(default_factory=list)
    note: str = ""
    evidence_messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessmentResult:
    """Output of the transparent rule-based risk engine."""

    score: int = 0
    classification: str = ""  # internal label (Likely Benign / Suspicious / Likely Phishing)
    ui_label: str = ""  # user-friendly label (Likely Safe / Needs Caution / High Risk)
    recommended_action: str = ""  # plain-English guidance for the user
    confidence_label: str = "Low"  # Low / Medium / High
    risk_factors: List[str] = field(default_factory=list)
    safe_factors: List[str] = field(default_factory=list)
    explanation_points: List[str] = field(default_factory=list)
    # Per-category point contributions, for a transparent UI breakdown.
    score_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FinalAnalysisResult:
    """The complete, top-level analysis result for one URL."""

    requested_url: str
    timestamp: str
    classification: str
    risk_score: int
    confidence_label: str
    url_features: URLFeatureResult
    crawl: CrawlResult
    html_analysis: HTMLAnalysisResult
    prompt_injection: PromptInjectionResult
    brand_check: Optional["BrandCheckResult"] = None
    is_trusted_domain: bool = False
    threat_intel: Optional["ThreatIntelResult"] = None
    domain_intel: Optional["DomainIntelResult"] = None
    multimodal: Optional["MultimodalResult"] = None
    dynamic_analysis: Optional["DynamicAnalysisResult"] = None
    retrieved_evidence: List[RetrievedEvidence] = field(default_factory=list)
    risk_assessment: Optional[RiskAssessmentResult] = None
    explanation: str = ""
    explanation_source: str = "fallback"  # "fallback" or "llm"
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "timestamp": self.timestamp,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "confidence_label": self.confidence_label,
            "url_features": self.url_features.to_dict(),
            "crawl": self.crawl.to_dict(),
            "html_analysis": self.html_analysis.to_dict(),
            "prompt_injection": self.prompt_injection.to_dict(),
            "brand_check": self.brand_check.to_dict() if self.brand_check else None,
            "is_trusted_domain": self.is_trusted_domain,
            "threat_intel": self.threat_intel.to_dict() if self.threat_intel else None,
            "domain_intel": self.domain_intel.to_dict() if self.domain_intel else None,
            "multimodal": self.multimodal.to_dict() if self.multimodal else None,
            "dynamic_analysis": self.dynamic_analysis.to_dict() if self.dynamic_analysis else None,
            "retrieved_evidence": [e.to_dict() for e in self.retrieved_evidence],
            "risk_assessment": (
                self.risk_assessment.to_dict() if self.risk_assessment else None
            ),
            "explanation": self.explanation,
            "explanation_source": self.explanation_source,
            "limitations": self.limitations,
        }
