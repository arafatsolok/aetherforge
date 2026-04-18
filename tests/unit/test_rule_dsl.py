"""Unit tests for the rule DSL evaluator.

Covers every combinator + op + binding-propagation path.
"""

from __future__ import annotations

import pytest

from app.core.rule_engine import Fact, evaluate_when
from app.core.rule_engine.dsl import DslError


def _fact(t: str, body: dict[str, object], *, tool: str = "t", iteration: int = 0, fp: str = "") -> Fact:
    return Fact(
        fact_type=t, body=body, source_tool=tool, scan_id="s1",
        iteration=iteration, fingerprint=fp or f"{t}:{sorted(body.items())}",
    )


# ---------------------------------------------------------------------------
# fact_type leaf
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestFactType:
    def test_single_matching_fact(self) -> None:
        facts = [_fact("port_open", {"host": "1.1.1.1", "port": 80})]
        matches = evaluate_when({"fact_type": "port_open"}, facts)
        assert len(matches) == 1
        assert matches[0].triggering_fact == facts[0]
        assert matches[0].bindings["fact"] == {"host": "1.1.1.1", "port": 80}

    def test_zero_matches_when_empty(self) -> None:
        assert evaluate_when({"fact_type": "port_open"}, []) == []

    def test_many_matches_produce_one_per_fact(self) -> None:
        facts = [
            _fact("port_open", {"host": "a", "port": 80}),
            _fact("port_open", {"host": "b", "port": 443}),
            _fact("http_response", {"host": "a", "port": 80}),
        ]
        matches = evaluate_when({"fact_type": "port_open"}, facts)
        assert len(matches) == 2
        assert {m.bindings["fact"]["host"] for m in matches} == {"a", "b"}

    def test_where_filters_facts(self) -> None:
        facts = [
            _fact("port_open", {"host": "a", "port": 22}),
            _fact("port_open", {"host": "a", "port": 443}),
        ]
        matches = evaluate_when(
            {"fact_type": "port_open", "where": {"port": 443}}, facts
        )
        assert len(matches) == 1
        assert matches[0].bindings["fact"]["port"] == 443


# ---------------------------------------------------------------------------
# where operators
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestWhereOps:
    facts = [
        _fact("http_response", {"host": "a", "status_code": 200, "title": "login page"}),
        _fact("http_response", {"host": "b", "status_code": 404, "title": "not found"}),
        _fact("http_response", {"host": "c", "status_code": 500, "title": "error"}),
    ]

    def test_in(self) -> None:
        matches = evaluate_when(
            {"fact_type": "http_response", "where": {"status_code": {"in": [200, 301]}}},
            self.facts,
        )
        assert {m.bindings["fact"]["host"] for m in matches} == {"a"}

    def test_ne(self) -> None:
        matches = evaluate_when(
            {"fact_type": "http_response", "where": {"status_code": {"ne": 200}}},
            self.facts,
        )
        assert {m.bindings["fact"]["host"] for m in matches} == {"b", "c"}

    def test_matches_regex(self) -> None:
        matches = evaluate_when(
            {"fact_type": "http_response", "where": {"title": {"matches": "^login"}}},
            self.facts,
        )
        assert {m.bindings["fact"]["host"] for m in matches} == {"a"}

    def test_contains(self) -> None:
        matches = evaluate_when(
            {"fact_type": "http_response", "where": {"title": {"contains": "not"}}},
            self.facts,
        )
        assert {m.bindings["fact"]["host"] for m in matches} == {"b"}

    def test_gt_lte(self) -> None:
        hi = evaluate_when(
            {"fact_type": "http_response", "where": {"status_code": {"gt": 400}}},
            self.facts,
        )
        assert len(hi) == 2

        lo = evaluate_when(
            {"fact_type": "http_response", "where": {"status_code": {"lte": 200}}},
            self.facts,
        )
        assert len(lo) == 1


# ---------------------------------------------------------------------------
# all combinator
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestAll:
    def test_cross_product_correlates_by_where(self) -> None:
        """Two ``fact_type`` children share ``$fact``; correlate via ``where:``."""
        facts = [
            _fact("host_alive", {"host": "a"}),
            _fact("host_alive", {"host": "b"}),
            _fact("dns_record", {"host": "a", "type": "A"}),
        ]
        matches = evaluate_when(
            {
                "all": [
                    {"fact_type": "host_alive"},
                    {"fact_type": "dns_record", "where": {"host": "$fact.host"}},
                ]
            },
            facts,
        )
        # Host "a" has both; host "b" has only host_alive.
        assert len(matches) == 1
        assert matches[0].bindings["fact"]["host"] == "a"

    def test_empty_child_list_raises(self) -> None:
        with pytest.raises(DslError):
            evaluate_when({"all": []}, [])

    def test_any_child_empty_prunes_result(self) -> None:
        facts = [_fact("host_alive", {"host": "a"})]
        matches = evaluate_when(
            {"all": [{"fact_type": "host_alive"}, {"fact_type": "never_exists"}]},
            facts,
        )
        assert matches == []


# ---------------------------------------------------------------------------
# any combinator
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestAny:
    def test_union_dedupes(self) -> None:
        facts = [_fact("port_open", {"host": "a", "port": 80})]
        matches = evaluate_when(
            {"any": [{"fact_type": "port_open"}, {"fact_type": "port_open"}]},
            facts,
        )
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# not_fact
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestNotFact:
    def test_matches_when_absent(self) -> None:
        facts = [_fact("host_alive", {"host": "a"})]
        matches = evaluate_when(
            {"not_fact": {"fact_type": "subdomain"}},
            facts,
        )
        assert len(matches) == 1

    def test_no_match_when_present(self) -> None:
        facts = [_fact("subdomain", {"host": "a.b.c"})]
        matches = evaluate_when({"not_fact": {"fact_type": "subdomain"}}, facts)
        assert matches == []

    def test_respects_where_filter(self) -> None:
        facts = [_fact("port_open", {"host": "a", "port": 80})]
        # Rule asks "no port_open with port=443"? — that's vacuously true here.
        matches = evaluate_when(
            {"not_fact": {"fact_type": "port_open", "where": {"port": 443}}},
            facts,
        )
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Binding propagation (all + not_fact with $fact refs)
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestBindings:
    def test_not_fact_sees_parent_bindings(self) -> None:
        """Classic rule: `port_open AND no service_banner for same port`."""
        facts = [
            _fact("port_open", {"host": "a", "port": 80}),
            _fact("port_open", {"host": "a", "port": 443}),
            _fact("service_banner", {"host": "a", "port": 443, "banner": "nginx"}),
        ]
        when = {
            "all": [
                {"fact_type": "port_open"},
                {
                    "not_fact": {
                        "fact_type": "service_banner",
                        "where": {"host": "$fact.host", "port": "$fact.port"},
                    }
                },
            ]
        }
        matches = evaluate_when(when, facts)
        assert len(matches) == 1
        assert matches[0].bindings["fact"]["port"] == 80


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------
@pytest.mark.unit
class TestErrors:
    def test_empty_predicate_raises(self) -> None:
        with pytest.raises(DslError):
            evaluate_when({}, [])

    def test_unknown_predicate_shape_raises(self) -> None:
        with pytest.raises(DslError):
            evaluate_when({"wat": 1}, [])
