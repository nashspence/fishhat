"""Count executed work rather than elapsed time; setup is outside the measured call."""

from __future__ import annotations

import base64
import builtins
import json
import sys
from collections import Counter
from collections.abc import Mapping
from unittest.mock import patch


def _container_observer(work):
    absent = object()
    changes = []
    watched = set()

    def counted(source):
        for item in source:
            work["container_items"] += 1
            yield item

    def constructor(original):
        class Constructor(type):
            def __call__(cls, *args, **kwargs):
                if args:
                    source, *tail = args
                    if original is dict and isinstance(source, Mapping):
                        work["container_items"] += len(source)
                    else:
                        source = counted(source)
                    args = (source, *tail)
                work["container_items"] += len(kwargs)
                return original(*args, **kwargs)

            def __instancecheck__(cls, value):
                return isinstance(value, original)

            def __subclasscheck__(cls, value):
                return issubclass(value, original)

            def __getattr__(cls, name):
                return getattr(original, name)

        return Constructor(original.__name__, (), {})

    class Comparison:
        def __init__(self, value):
            self.value = value

        def __lt__(self, other):
            work["sort_comparisons"] += 1
            return self.value < other.value

    def ordered(source, *, key=None, reverse=False):
        values = list(counted(source))
        return builtins.sorted(
            values, key=lambda item: Comparison(item if key is None else key(item)), reverse=reverse
        )

    proxies = {
        name: constructor(getattr(builtins, name))
        for name in ("set", "frozenset", "list", "dict", "tuple")
    }
    proxies["sorted"] = ordered

    def observe(namespace, explicit=False):
        if id(namespace) in watched:
            return
        watched.add(id(namespace))
        names = proxies if explicit else ("set", "frozenset")
        for name in names:
            original = namespace.get(name, absent)
            if original is absent or original is getattr(builtins, name):
                changes.append((namespace, name, original))
                namespace[name] = proxies[name]

    def restore():
        for namespace, name, original in reversed(changes):
            if original is absent:
                del namespace[name]
            else:
                namespace[name] = original

    return observe, restore


def measure(call, *, database=None, modules=()):
    """Measure executed work, including native container loops hidden from line tracing.

    Set construction in visited project modules and sized C ``copy`` methods are
    always observed. Explicit owner modules additionally observe list/dict/tuple
    constructors and comparison sorting. Proxies return the original built-in
    types and preserve isinstance; callers select modules that do not use exact
    type identity against those constructor names. Deep-copy recursion remains
    visible to the Python work counter. Setup is outside the measured operation.
    """
    work = Counter(
        python=0,
        container_items=0,
        copied_items=0,
        sort_comparisons=0,
        serialized_bytes=0,
        parsed_bytes=0,
        encoded_bytes=0,
        sqlite=0,
    )
    original_dumps, original_loads = json.dumps, json.loads
    original_base64 = base64.b64encode
    previous, previous_profile = sys.gettrace(), sys.getprofile()
    observe, restore = _container_observer(work)

    python_lines = 0

    def count_lines(frame, event, arg):
        nonlocal python_lines
        if event == "line":
            python_lines += 1
        return count_lines

    def trace(frame, event, arg):
        if event == "call" and frame.f_globals.get("__name__", "").startswith(
            ("fishhat_", "a_fishhat_")
        ):
            observe(frame.f_globals)
        # Select the same counted files once per call; count every line inside them.
        if frame.f_code.co_filename != __file__:
            return count_lines
        return None

    def profile(frame, event, arg):
        if event == "c_call" and getattr(arg, "__name__", None) == "copy":
            source = getattr(arg, "__self__", None)
            if isinstance(source, (dict, list, set, frozenset)):
                work["copied_items"] += len(source)

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
        for module in modules:
            observe(vars(module), explicit=True)
        with (
            patch.object(json, "dumps", dumps),
            patch.object(json, "loads", loads),
            patch.object(base64, "b64encode", encode),
        ):
            sys.settrace(trace)
            sys.setprofile(profile)
            result = call()
    finally:
        sys.settrace(previous)
        sys.setprofile(previous_profile)
        work["python"] = python_lines
        restore()
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
