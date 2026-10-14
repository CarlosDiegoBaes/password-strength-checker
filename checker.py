"""Password strength checker.

Estimates entropy, flags common patterns, and checks the Have I Been Pwned
breach database using k-anonymity (only the first 5 characters of the
SHA-1 hash ever leave your machine).
"""
from __future__ import annotations

import getpass
import hashlib
import math
import re
import string
import urllib.request
from dataclasses import dataclass, field
from enum import Enum


class Rating(Enum):
    WEAK = "WEAK"
    FAIR = "FAIR"
    STRONG = "STRONG"


@dataclass(frozen=True)
class StrengthReport:
    entropy_bits: float
    warnings: list[str] = field(default_factory=list)
    breach_count: int | None = None  # None means the check was skipped
    rating: Rating = Rating.WEAK


class EntropyEstimator:
    """Estimates entropy from length and the character classes used."""

    def charset_size(self, password: str) -> int:
        size = 0
        if re.search(r"[a-z]", password):
            size += 26
        if re.search(r"[A-Z]", password):
            size += 26
        if re.search(r"\d", password):
            size += 10
        if re.search(f"[{re.escape(string.punctuation)}]", password):
            size += len(string.punctuation)
        if re.search(r"\s", password):
            size += 1
        return size

    def estimate(self, password: str) -> float:
        if not password:
            return 0.0
        return len(password) * math.log2(self.charset_size(password))


class PatternDetector:
    """Flags patterns that attackers' wordlists and rules try first."""

    COMMON: frozenset[str] = frozenset(
        {"password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou"}
    )
    LEET: dict[int, int] = str.maketrans("@40313$75", "aaoeiests")
    SEQUENCES: re.Pattern[str] = re.compile(r"012|123|234|345|456|567|678|789|abc|qwe")

    def __init__(self, min_length: int = 12) -> None:
        self.min_length = min_length

    def detect(self, password: str) -> list[str]:
        warnings: list[str] = []
        base = re.sub(r"[\d!@#$%^&*]+$", "", password.lower()).translate(self.LEET)
        if base in self.COMMON:
            warnings.append("Based on a very common password (even with substitutions).")
        if re.search(r"(.)\1{2,}", password):
            warnings.append("Has repeated characters (e.g. 'aaa').")
        if self.SEQUENCES.search(password.lower()):
            warnings.append("Has a keyboard or number sequence.")
        if re.search(r"(19|20)\d{2}$", password):
            warnings.append("Ends in what looks like a year.")
        if len(password) < self.min_length:
            warnings.append(f"Shorter than {self.min_length} characters.")
        return warnings


class BreachChecker:
    """Queries Have I Been Pwned's range API with k-anonymity."""

    API_URL = "https://api.pwnedpasswords.com/range/"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def count(self, password: str) -> int:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        request = urllib.request.Request(
            self.API_URL + prefix, headers={"User-Agent": "pw-strength-checker"}
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            for line in response.read().decode().splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return int(count)
        return 0


class PasswordStrengthChecker:
    """Combines entropy, pattern, and breach checks into one report."""

    def __init__(
        self,
        estimator: EntropyEstimator | None = None,
        detector: PatternDetector | None = None,
        breach_checker: BreachChecker | None = None,
    ) -> None:
        self.estimator = estimator or EntropyEstimator()
        self.detector = detector or PatternDetector()
        self.breach_checker = breach_checker or BreachChecker()

    def check(self, password: str) -> StrengthReport:
        bits = self.estimator.estimate(password)
        warnings = self.detector.detect(password)
        try:
            breaches: int | None = self.breach_checker.count(password)
        except OSError:
            breaches = None
        return StrengthReport(bits, warnings, breaches, self._rate(bits, warnings, breaches))

    @staticmethod
    def _rate(bits: float, warnings: list[str], breaches: int | None) -> Rating:
        if breaches:
            return Rating.WEAK
        if bits < 40 or len(warnings) >= 3:
            return Rating.WEAK
        if bits < 60 or warnings:
            return Rating.FAIR
        return Rating.STRONG


def print_report(report: StrengthReport) -> None:
    print(f"\nEstimated entropy: {report.entropy_bits:.0f} bits")
    if report.breach_count is None:
        print("(Breach check skipped: no connection.)")
    elif report.breach_count:
        print(f"Seen in {report.breach_count:,} breached passwords!")
    else:
        print("Not found in known breaches.")
    for warning in report.warnings:
        print(f"- {warning}")
    print(f"Rating: {report.rating.value}")


def main() -> None:
    password = getpass.getpass("Password to check (input hidden): ")
    print_report(PasswordStrengthChecker().check(password))


if __name__ == "__main__":
    main()
