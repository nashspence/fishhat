"""Executed line accounting includes dependencies, returns and exception paths."""

from __future__ import annotations

import json
import sys

import pytest
from fishhat_contracts import canonical

from tests import linear_support

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["tests/linear_support.py"],
    "scope": "independent live trace-event accounting and restoration of interpreter hooks",
    "relationship": "no-product-claim",
    "reason": "A separate event observer checks all measured Python lines and auxiliary work counters without qualifying a product operation.",
    "claims": [],
}


@pytest.mark.parametrize("raises", [False, True], ids=["return", "exception"])
def test_complete_line_accounting_matches_independent_live_events(monkeypatch, raises):
    previous_trace, previous_profile = sys.gettrace(), sys.getprofile()
    install = sys.settrace
    expected = 0
    files, events = set(), set()

    def observe(callback):
        if callback is previous_trace:
            install(callback)
            return

        def calls(frame, event, arg):
            local = callback(frame, event, arg)

            def lines(frame, event, arg):
                nonlocal local, expected
                events.add(event)
                if event == "line" and frame.f_code.co_filename != linear_support.__file__:
                    expected += 1
                    files.add(frame.f_code.co_filename)
                local = local(frame, event, arg)
                return lines if local is not None else None

            return lines if local is not None else None

        install(calls)

    def nested(value):
        if raises:
            raise ValueError(value)
        return value

    def exercise():
        total = 0
        for value in range(3):
            payload = {"value": value, "items": [value, value + 1]}
            assert json.loads(json.dumps(payload)) == payload
            assert canonical(payload)
            assert payload.copy() == payload
            try:
                total += nested(value)
            except ValueError as error:
                total += error.args[0]
        return total

    monkeypatch.setattr(sys, "settrace", observe)
    result, work = linear_support.measure(exercise)
    assert result == 3
    assert work["python"] == expected > 0
    assert work["serialized_bytes"] > 0 and work["parsed_bytes"] > 0
    assert work["copied_items"] > 0
    assert {"line", "return"} <= events
    assert ("exception" in events) is raises
    assert __file__ in files
    assert any("json/encoder.py" in name.replace("\\", "/") for name in files)
    assert any("fishhat_contracts" in name for name in files)
    assert sys.gettrace() is previous_trace
    assert sys.getprofile() is previous_profile
