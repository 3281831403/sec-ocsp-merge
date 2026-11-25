"""Multi-source revocation response merging.

The eight public functions below are the whole implementation surface.  Tests
exercise status precedence, source ordering, freshness, signer authorization,
per-source traceability, cache-key isolation, policy validation, and batch
isolation.
"""

import json

_STATUS_RANKS = {
    "good": 0,
    "unknown": 1,
    "revoked": 2,
}


def parse_response(response: dict) -> dict:
    """Normalize one response into cert_id, issuer, status, this_update,
    next_update, signer, and source without losing the source label.
    """
    return {
        "source": response.get("source"),
        "cert_id": response.get("cert_id"),
        "issuer": response.get("issuer"),
        "status": response.get("status") or "unknown",
        "this_update": response.get("this_update"),
        "next_update": response.get("next_update"),
        "signer": response.get("signer"),
    }


def authorized(signer, cert_issuer, delegates) -> bool:
    """Return True only for the certificate issuer or an explicitly delegated
    responder.  A name match outside the issuer and delegate list is not enough.
    """
    if signer == cert_issuer:
        return True
    return signer in (delegates or [])


def freshness_ok(response, now, max_age) -> bool:
    """Return True only when now is within both update bounds and the response
    is no older than max_age.  A past next_update is expired, not good.
    """
    this_update = response.get("this_update")
    next_update = response.get("next_update")
    if this_update is None or next_update is None:
        return False
    if this_update > now:
        return False
    if next_update < now:
        return False
    if max_age is not None and (now - this_update).total_seconds() > max_age:
        return False
    return True


def status_rank(status) -> int:
    """Rank status so revoked outranks unknown and unknown outranks good."""
    return _STATUS_RANKS.get(status, _STATUS_RANKS["unknown"])


def merge_sources(responses, now, policy) -> dict:
    """Merge all eligible sources without depending on input order and return
    the final status plus per-source accepted or rejected reasons.
    """
    policy = policy or {}
    max_age = policy.get("max_age")
    require_auth = policy.get("require_signer_authorization", True)
    delegates_by_issuer = policy.get("delegates") or {}

    reasons = []
    best_status = None
    best_rank = None
    for response in responses:
        parsed = parse_response(response)
        accepted = True
        reason = "accepted"
        if require_auth and not authorized(
            parsed["signer"],
            parsed["issuer"],
            delegates_by_issuer.get(parsed["issuer"], []),
        ):
            accepted = False
            reason = "unauthorized"
        elif not freshness_ok(parsed, now, max_age):
            accepted = False
            reason = "expired"

        reasons.append(
            {
                "source": parsed["source"],
                "cert_id": parsed["cert_id"],
                "issuer": parsed["issuer"],
                "status": parsed["status"],
                "accepted": accepted,
                "reason": reason,
            }
        )

        if accepted:
            rank = status_rank(parsed["status"])
            if best_rank is None or rank > best_rank:
                best_rank = rank
                best_status = parsed["status"]

    return {
        "status": best_status if best_status is not None else "unknown",
        "reasons": reasons,
    }


def cache_key(cert_id, issuer) -> str:
    """Build an unambiguous cache key that always includes the issuer."""
    return json.dumps([cert_id, issuer])


def validate_policy(policy) -> list[str]:
    """Return issue codes for missing max_age, unknown treated as good, or
    missing signer-authorization enforcement.
    """
    issues = []
    if policy.get("max_age") is None:
        issues.append("max_age")
    if policy.get("allow_unknown_as_good"):
        issues.append("allow_unknown_as_good")
    if not policy.get("require_signer_authorization"):
        issues.append("require_signer_authorization")
    return issues


def merge_batch(batches, policy, now) -> dict:
    """Merge each batch independently and return a batches list; no state or
    cached decision may leak from one batch to another.
    """
    return {
        "batches": [merge_sources(batch, now, policy) for batch in batches],
    }
