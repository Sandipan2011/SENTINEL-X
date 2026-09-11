from collections import Counter
from math import log2


def shannon_entropy(value: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy means the characters are distributed
    more randomly.

    Used later for:
    - DGA detection
    - DNS tunneling detection
    - Source-IP/domain analysis
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * log2(probability)

    return entropy