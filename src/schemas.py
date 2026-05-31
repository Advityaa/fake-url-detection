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
    is_shortened_url: bool = False
    entropy_score: float = 0.0
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
class RiskAssessmentResult:
    """Output of the transparent rule-based risk engine."""

    score: int = 0
    classification: str = ""
    confidence_label: str = "Low"  # Low / Medium / High
    risk_factors: List[str] = field(default_factory=list)
    safe_factors: List[str] = field(default_factory=list)
    explanation_points: List[str] = field(default_factory=list)

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
            "retrieved_evidence": [e.to_dict() for e in self.retrieved_evidence],
            "risk_assessment": (
                self.risk_assessment.to_dict() if self.risk_assessment else None
            ),
            "explanation": self.explanation,
            "explanation_source": self.explanation_source,
            "limitations": self.limitations,
        }
