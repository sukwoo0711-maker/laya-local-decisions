"""Offline, numeric-only scenario calculator; no inference or network access."""
import json
import math
from pathlib import Path
import sys

FIELDS = {
    "requests", "rule_resolved", "cache_hit_rate_after_rules",
    "laya_resolved_rate_after_cache", "baseline_input_tokens",
    "baseline_output_tokens", "candidate_input_tokens", "candidate_output_tokens",
}


def calculate(data):
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError("Expected exactly the documented numeric scenario fields")
    for key, value in data.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("All fields must be finite numbers")
        if not math.isfinite(value) or value < 0 or value > 10**12:
            raise ValueError("Numeric value outside supported range")
    for key in ("requests", "rule_resolved"):
        if int(data[key]) != data[key]:
            raise ValueError("Request counts must be integers")
    if data["rule_resolved"] > data["requests"]:
        raise ValueError("Rule-resolved count exceeds total requests")
    for key in ("cache_hit_rate_after_rules", "laya_resolved_rate_after_cache"):
        if data[key] > 1:
            raise ValueError("Rates must be between zero and one")
    after_rules = data["requests"] - data["rule_resolved"]
    hits = after_rules * data["cache_hit_rate_after_rules"]
    laya_calls = after_rules - hits
    laya_resolved = laya_calls * data["laya_resolved_rate_after_cache"]
    large_calls = laya_calls - laya_resolved
    baseline_in = data["requests"] * data["baseline_input_tokens"]
    baseline_out = data["requests"] * data["baseline_output_tokens"]
    candidate_in = large_calls * data["candidate_input_tokens"]
    candidate_out = large_calls * data["candidate_output_tokens"]
    baseline = baseline_in + baseline_out
    candidate = candidate_in + candidate_out
    return {
        "kind": "assumption_based_expected_counts_not_benchmark",
        "after_rules": after_rules, "cache_hits": hits,
        "laya_calls": laya_calls, "laya_resolved": laya_resolved,
        "large_model_calls": large_calls,
        "baseline_large_model_input_tokens": baseline_in,
        "baseline_large_model_output_tokens": baseline_out,
        "candidate_large_model_input_tokens": candidate_in,
        "candidate_large_model_output_tokens": candidate_out,
        "baseline_large_model_tokens": baseline,
        "candidate_large_model_tokens": candidate,
        "large_model_token_reduction_percent": None if baseline == 0 else (1 - candidate / baseline) * 100,
        "laya_compute_and_total_cost": "not_estimated",
        "external_api_tokens": "not_measured_this_calculator_makes_no_api_calls",
    }


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def self_test():
    sample = dict(requests=1000, rule_resolved=250,
        cache_hit_rate_after_rules=.4, laya_resolved_rate_after_cache=.8,
        baseline_input_tokens=1200, baseline_output_tokens=120,
        candidate_input_tokens=350, candidate_output_tokens=80)
    result = calculate(sample)
    assert result["cache_hits"] == 300
    assert result["laya_calls"] == 450
    assert result["large_model_calls"] == 90
    assert result["candidate_large_model_tokens"] == 38700
    assert math.isclose(result["large_model_token_reduction_percent"], 97.06818181818181)
    assert calculate({**sample, "requests": 0, "rule_resolved": 0})["large_model_token_reduction_percent"] is None
    assert calculate({**sample, "cache_hit_rate_after_rules": 1})["laya_calls"] == 0
    assert calculate({**sample, "rule_resolved": 1000})["large_model_calls"] == 0
    no_savings = {**sample, "rule_resolved": 0, "cache_hit_rate_after_rules": 0,
        "laya_resolved_rate_after_cache": 0, "candidate_input_tokens": 1200,
        "candidate_output_tokens": 120}
    assert calculate(no_savings)["large_model_token_reduction_percent"] == 0
    assert calculate({**no_savings, "candidate_input_tokens": 2400})["large_model_token_reduction_percent"] < 0
    for bad in ({"rule_resolved": 1001}, {"requests": True}, {"requests": 1.5},
                {"cache_hit_rate_after_rules": 1.1}, {"baseline_input_tokens": -1},
                {"candidate_input_tokens": float("nan")}, {"candidate_output_tokens": float("inf")},
                {"private_text": "not accepted"}):
        try:
            calculate({**sample, **bad})
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid input accepted")
    try:
        json.loads('{"requests":1,"requests":2}', object_pairs_hook=unique_object)
    except ValueError:
        pass
    else:
        raise AssertionError("Duplicate key accepted")
    print("PASS: stage arithmetic, zero denominators, negative savings and invalid input boundaries")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 2:
        print("Usage: python -B tools/token_budget.py scenario.json | --self-test", file=sys.stderr)
        return 2
    try:
        with Path(sys.argv[1]).open("rb") as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            raise ValueError("Scenario exceeds 64 KiB")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        print(json.dumps(calculate(data), indent=2, ensure_ascii=True, allow_nan=False))
        return 0
    except (ValueError, OSError, OverflowError):
        print("Invalid numeric scenario. Check fields, ranges and UTF-8 JSON.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
