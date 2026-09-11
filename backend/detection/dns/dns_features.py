from dataclasses import dataclass
from typing import Any

from backend.features.entropy import shannon_entropy


@dataclass
class DNSFeatures:
    query: str
    query_length: int
    label_count: int
    maximum_label_length: int
    entropy: float
    digit_ratio: float
    alphabetic_ratio: float
    numeric_character_count: int
    suspicious_length: bool
    high_entropy: bool
    high_digit_ratio: bool
    deep_subdomain: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "query_length": self.query_length,
            "label_count": self.label_count,
            "maximum_label_length": self.maximum_label_length,
            "entropy": round(self.entropy, 4),
            "digit_ratio": round(self.digit_ratio, 4),
            "alphabetic_ratio": round(
                self.alphabetic_ratio,
                4,
            ),
            "numeric_character_count": (
                self.numeric_character_count
            ),
            "suspicious_length": self.suspicious_length,
            "high_entropy": self.high_entropy,
            "high_digit_ratio": self.high_digit_ratio,
            "deep_subdomain": self.deep_subdomain,
        }


class DNSFeatureExtractor:
    """
    Extract metadata-only features from a DNS query.

    No DNS request is generated.
    No external DNS server is contacted.
    """

    def extract(
        self,
        query: str,
    ) -> DNSFeatures:

        normalized = query.rstrip(".").lower()

        labels = [
            label
            for label in normalized.split(".")
            if label
        ]

        query_length = len(normalized)

        label_count = len(labels)

        maximum_label_length = (
            max(
                (len(label) for label in labels),
                default=0,
            )
        )

        entropy = shannon_entropy(
            normalized.replace(".", "")
        )

        total_characters = max(
            len(normalized.replace(".", "")),
            1,
        )

        numeric_character_count = sum(
            character.isdigit()
            for character in normalized
        )

        alphabetic_character_count = sum(
            character.isalpha()
            for character in normalized
        )

        digit_ratio = (
            numeric_character_count
            / total_characters
        )

        alphabetic_ratio = (
            alphabetic_character_count
            / total_characters
        )

        suspicious_length = (
            query_length >= 50
        )

        high_entropy = (
            entropy >= 3.5
        )

        high_digit_ratio = (
            digit_ratio >= 0.30
        )

        deep_subdomain = (
            label_count >= 5
        )

        return DNSFeatures(
            query=normalized,
            query_length=query_length,
            label_count=label_count,
            maximum_label_length=maximum_label_length,
            entropy=entropy,
            digit_ratio=digit_ratio,
            alphabetic_ratio=alphabetic_ratio,
            numeric_character_count=(
                numeric_character_count
            ),
            suspicious_length=suspicious_length,
            high_entropy=high_entropy,
            high_digit_ratio=high_digit_ratio,
            deep_subdomain=deep_subdomain,
        )