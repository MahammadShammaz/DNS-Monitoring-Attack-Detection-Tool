import math
from collections import Counter


DNS_QUERY_TYPES = {

    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA"
}


SUSPICIOUS_KEYWORDS = [
    "malware",
    "phishing",
    "steal",
    "hack",
    "evil",
    "botnet"
]


def decode_query_type(query_type):

    return DNS_QUERY_TYPES.get(
        query_type,
        "UNKNOWN"
    )


def calculate_entropy(domain):

    domain = domain.replace(".", "")

    probabilities = [
        count / len(domain)
        for count in Counter(domain).values()
    ]

    entropy = -sum(
        p * math.log2(p)
        for p in probabilities
    )

    return round(entropy, 2)


def is_suspicious_domain(domain):

    domain = domain.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in domain:
            return True

    entropy = calculate_entropy(domain)

    if entropy > 4.0:
        return True

    return False


def generate_threat_score(domain):

    score = 0

    entropy = calculate_entropy(domain)

    if entropy > 4.0:
        score += 40

    if len(domain) > 40:
        score += 30

    if is_suspicious_domain(domain):
        score += 30

    return min(score, 100)