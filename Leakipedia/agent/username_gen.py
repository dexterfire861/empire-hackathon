from __future__ import annotations

from typing import Optional


def generate_username_permutations(full_name: str, known_usernames: Optional[list[str]] = None) -> list[str]:
    """
    Generate common username permutations from a full name.
    Returns deduplicated list of plausible usernames.
    """
    parts = full_name.strip().lower().split()
    if len(parts) < 2:
        return known_usernames or []

    first = parts[0]
    last = parts[-1]

    permutations = [
        # Basic combinations
        f"{first}{last}",           # aryaanverma
        f"{last}{first}",           # vermaaryaan
        f"{first}.{last}",          # aryaan.verma
        f"{last}.{first}",          # verma.aryaan
        f"{first}_{last}",          # aryaan_verma
        f"{last}_{first}",          # verma_aryaan
        f"{first}-{last}",          # aryaan-verma
        f"{last}-{first}",          # verma-aryaan
        # Initial combos
        f"{first[0]}{last}",        # averma
        f"{first}{last[0]}",        # aryaanv
        f"{first[0]}.{last}",       # a.verma
        f"{first}.{last[0]}",       # aryaan.v
        f"{first[0]}{last[0]}",     # av
        # With numbers
        f"{first}{last}1",
        f"{first}{last}123",
        f"{first}.{last}1",
        f"{first}_{last}1",
        # Just first or last
        first,
        last,
    ]

    # Add known usernames
    if known_usernames:
        permutations.extend(known_usernames)

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for p in permutations:
        if p and p not in seen and len(p) > 1:
            seen.add(p)
            result.append(p)

    return result


def build_username_candidate_sets(
    full_name: str, known_usernames: list[str] | None = None
) -> dict[str, list[str]]:
    """
    Split generated usernames into conservative auto-search and deferred buckets.
    """
    known = [u.strip().lower() for u in (known_usernames or []) if u and u.strip()]
    all_candidates = generate_username_permutations(full_name, known)

    parts = full_name.strip().lower().split()
    if len(parts) < 2:
        return {"auto_search": known, "deferred": []}

    first = parts[0]
    last = parts[-1]
    conservative_patterns = [
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first}-{last}",
    ]

    auto_search: list[str] = []
    seen: set[str] = set()
    for candidate in known + conservative_patterns:
        if candidate in all_candidates and candidate not in seen:
            seen.add(candidate)
            auto_search.append(candidate)

    deferred = [candidate for candidate in all_candidates if candidate not in seen]

    return {"auto_search": auto_search, "deferred": deferred}
