"""Count executed work rather than elapsed time; setup is outside the measured call."""

from __future__ import annotations

import base64
import json
import sys
from collections import Counter
from unittest.mock import patch


def measure(call, *, database=None):
    work = Counter(python=0, serialized_bytes=0, parsed_bytes=0, encoded_bytes=0, sqlite=0)
    original_dumps, original_loads = json.dumps, json.loads
    original_base64 = base64.b64encode
    previous = sys.gettrace()

    def trace(frame, event, arg):
        if event == "line" and frame.f_code.co_filename != __file__:
            work["python"] += 1
        return trace

    def dumps(*args, **kwargs):
        result = original_dumps(*args, **kwargs)
        work["serialized_bytes"] += len(result.encode("utf-8"))
        return result

    def loads(data, *args, **kwargs):
        work["parsed_bytes"] += len(data.encode("utf-8") if isinstance(data, str) else data)
        return original_loads(data, *args, **kwargs)

    def encode(data, *args, **kwargs):
        work["encoded_bytes"] += len(data)
        return original_base64(data, *args, **kwargs)

    def progress():
        work["sqlite"] += 1
        return 0

    if database is not None:
        database.set_progress_handler(progress, 1)
    try:
        with (
            patch.object(json, "dumps", dumps),
            patch.object(json, "loads", loads),
            patch.object(base64, "b64encode", encode),
        ):
            sys.settrace(trace)
            result = call()
    finally:
        sys.settrace(previous)
        if database is not None:
            database.set_progress_handler(None, 0)
    return result, work


def assert_linear(samples):
    """Require a constant work-per-input envelope over every measured scale.

    A 25% allowance covers fixed-size fixture encodings and interpreter changes;
    scales span at least sixteenfold so quadratic work cannot fit that envelope.
    These are deterministic work counts, never machine-dependent timing limits.
    """
    assert len(samples) >= 3 and samples[-1][0] >= 16 * samples[0][0]
    first_extent, first = samples[0]
    for extent, counts in samples[1:]:
        for metric in first.keys() | counts.keys():
            assert counts[metric] * first_extent <= 1.25 * first[metric] * extent, (metric, samples)
