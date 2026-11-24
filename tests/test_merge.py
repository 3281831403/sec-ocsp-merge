"""Strict red tests for the multi-source revocation merge exercise.

The first ten tests map one-to-one onto the ten specification defects.  The
remaining five cover the required merge sanity checks.
"""

from datetime import datetime, timedelta, timezone

from revoke.merge import (
    authorized,
    cache_key,
    freshness_ok,
    merge_batch,
    merge_sources,
    status_rank,
    validate_policy,
)

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
ISSUER = "CN=Root CA"
DELEGATE = "CN=OCSP Responder"
CERT_ID = "serial-0A1B"


def _response(
    source,
    status,
    *,
    cert_id=CERT_ID,
    issuer=ISSUER,
    signer=ISSUER,
    this_update=None,
    next_update=None,
):
    return {
        "source": source,
        "cert_id": cert_id,
        "issuer": issuer,
        "status": status,
        "this_update": this_update if this_update is not None else NOW - timedelta(minutes=5),
        "next_update": next_update if next_update is not None else NOW + timedelta(minutes=30),
        "signer": signer,
    }


def _policy(**overrides):
    policy = {
        "max_age": 3600,
        "allow_unknown_as_good": False,
        "require_signer_authorization": True,
        "delegates": {ISSUER: [DELEGATE]},
    }
    policy.update(overrides)
    return policy


def _trace(result):
    return sorted(
        (
            item["source"],
            item["cert_id"],
            item["issuer"],
            item["status"],
            item["accepted"],
            item["reason"],
        )
        for item in result["reasons"]
    )


def test_merge_does_not_use_first_response_order():
    """缺陷 1：合并取第一条响应，顺序决定结果。"""
    good = _response("A", "good")
    revoked = _response("B", "revoked")

    forward = merge_sources([good, revoked], NOW, _policy())
    backward = merge_sources([revoked, good], NOW, _policy())

    assert forward["status"] == "revoked"
    assert backward["status"] == "revoked"


def test_unknown_status_is_not_treated_as_good():
    """缺陷 2：未知状态被当作有效，缺少吊销信息反而放行。"""
    unknown = _response("A", "unknown")
    good = _response("B", "good")

    only_unknown = merge_sources([unknown], NOW, _policy())
    mixed = merge_sources([good, unknown], NOW, _policy())

    assert only_unknown["status"] == "unknown"
    assert mixed["status"] == "unknown"


def test_status_rank_orders_revoked_above_unknown_above_good():
    """缺陷 3：状态优先级把有效排在未知之前。"""
    assert status_rank("revoked") > status_rank("unknown")
    assert status_rank("unknown") > status_rank("good")


def test_freshness_checks_this_and_next_update():
    """缺陷 4：新鲜度只看本次更新时间，不看下次更新时间。"""
    expired_next = _response(
        "A",
        "good",
        this_update=NOW - timedelta(minutes=5),
        next_update=NOW - timedelta(minutes=1),
    )
    ancient_this = _response(
        "B",
        "good",
        this_update=NOW - timedelta(hours=2),
        next_update=NOW + timedelta(minutes=30),
    )
    fresh = _response(
        "C",
        "good",
        this_update=NOW - timedelta(minutes=5),
        next_update=NOW + timedelta(minutes=30),
    )

    assert freshness_ok(expired_next, NOW, 3600) is False
    assert freshness_ok(ancient_this, NOW, 3600) is False
    assert freshness_ok(fresh, NOW, 3600) is True


def test_expired_response_is_not_treated_as_good():
    """缺陷 5：过期响应被当成有效而不是丢弃。"""
    expired = _response(
        "A",
        "good",
        this_update=NOW - timedelta(hours=2),
        next_update=NOW - timedelta(hours=1),
    )

    result = merge_sources([expired], NOW, _policy())

    assert result["status"] == "unknown"


def test_authorized_requires_issuer_or_explicit_delegate():
    """缺陷 6：签名者授权只校验名称相等，不校验签发者与授权列表。"""
    assert authorized(ISSUER, ISSUER, []) is True
    assert authorized(DELEGATE, ISSUER, [DELEGATE]) is True
    assert authorized(DELEGATE, ISSUER, []) is False
    assert authorized("CN=Impostor", ISSUER, [DELEGATE]) is False

    trusted = _response("A", "good")
    forged = _response("B", "revoked", signer="CN=Impostor")
    merged = merge_sources([trusted, forged], NOW, _policy())
    by_source = {entry["source"]: entry for entry in merged["reasons"]}

    assert merged["status"] == "good"
    assert by_source["B"]["accepted"] is False
    assert by_source["B"]["reason"] == "unauthorized"


def test_cache_key_includes_issuer_without_collisions():
    """缺陷 7：缓存键不含签发者，跨签发者串用结果。"""
    same_cert_issuer_a = cache_key("serial-01", "CN=Root A")
    same_cert_issuer_b = cache_key("serial-01", "CN=Root B")

    assert same_cert_issuer_a != same_cert_issuer_b
    assert same_cert_issuer_a == cache_key("serial-01", "CN=Root A")
    assert cache_key("ab", "c") != cache_key("a", "bc")


def test_merge_keeps_per_source_reasons():
    """缺陷 8：合并结果不保留逐源依据，无法追溯。"""
    good = _response("A", "good")
    revoked = _response("B", "revoked")

    result = merge_sources([good, revoked], NOW, _policy())
    reasons = result["reasons"]

    assert len(reasons) == 2
    for entry in reasons:
        assert {"source", "cert_id", "issuer", "status", "accepted", "reason"} <= set(entry)
        assert entry["reason"]

    by_source = {entry["source"]: entry for entry in reasons}
    assert by_source["A"]["status"] == "good"
    assert by_source["A"]["accepted"] is True
    assert by_source["B"]["status"] == "revoked"
    assert by_source["B"]["accepted"] is True
    assert result["status"] == "revoked"


def test_validate_policy_flags_unknown_as_good():
    """缺陷 9：策略校验不检查是否允许未知当有效。"""
    assert validate_policy(_policy()) == []

    issues = validate_policy(_policy(allow_unknown_as_good=True))
    assert "allow_unknown_as_good" in issues

    assert "max_age" in validate_policy(_policy(max_age=None))
    assert "require_signer_authorization" in validate_policy(
        _policy(require_signer_authorization=False)
    )


def test_merge_batch_does_not_share_cached_result():
    """缺陷 10：批量合并复用缓存，第二个批次命中第一个批次的结果。"""
    first_batch = [_response("A", "revoked")]
    second_batch = [_response("B", "good")]

    merged = merge_batch([first_batch, second_batch], _policy(), NOW)
    batches = merged["batches"]

    assert [batch["status"] for batch in batches] == ["revoked", "good"]
    assert {entry["source"] for entry in batches[1]["reasons"]} == {"B"}


def test_two_good_sources_merge_to_good():
    """补充：两个源都说有效时结果为有效。"""
    result = merge_sources(
        [_response("A", "good"), _response("B", "good")],
        NOW,
        _policy(),
    )

    assert result["status"] == "good"
    assert len(result["reasons"]) == 2
    assert all(entry["accepted"] is True for entry in result["reasons"])


def test_revoked_and_good_merge_to_revoked():
    """补充：一源撤销一源有效时结果为撤销。"""
    result = merge_sources(
        [_response("A", "good"), _response("B", "revoked")],
        NOW,
        _policy(),
    )

    assert result["status"] == "revoked"


def test_reversed_sources_keep_same_result():
    """补充：响应顺序颠倒结果不变。"""
    sources = [_response("A", "good"), _response("B", "revoked")]

    forward = merge_sources(sources, NOW, _policy())
    backward = merge_sources(list(reversed(sources)), NOW, _policy())

    assert forward["status"] == "revoked"
    assert backward["status"] == "revoked"
    assert _trace(forward) == _trace(backward)


def test_expired_source_does_not_participate():
    """补充：过期响应不参与合并。"""
    fresh_good = _response("A", "good")
    stale_revoked = _response(
        "B",
        "revoked",
        this_update=NOW - timedelta(hours=2),
        next_update=NOW - timedelta(hours=1),
    )

    result = merge_sources([fresh_good, stale_revoked], NOW, _policy())
    by_source = {entry["source"]: entry for entry in result["reasons"]}

    assert result["status"] == "good"
    assert by_source["B"]["accepted"] is False
    assert by_source["B"]["reason"] == "expired"


def test_batches_equal_standalone_merges():
    """补充：两批独立合并与单独合并相同。"""
    first_batch = [_response("A", "revoked")]
    second_batch = [_response("B", "good")]

    batched = merge_batch([first_batch, second_batch], _policy(), NOW)
    standalone = {
        "batches": [
            merge_sources(first_batch, NOW, _policy()),
            merge_sources(second_batch, NOW, _policy()),
        ]
    }

    assert batched == standalone