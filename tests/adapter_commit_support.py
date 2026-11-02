"""Independent synthetic delta receiver; no native atomicity or durability claim."""

import copy

from fishhat_contracts.validation import canonical, digest, strict_json


class CommitStore:
    """Retain serialized append records and reconstruct indexed state incrementally.

    All semantic/precondition assertions run before changing the visible state.
    This test receiver models an atomic transaction; native storage must provide
    its own crash, concurrency and durable-acknowledgment qualification.
    """

    def __init__(self, owner):
        self.state = {
            "owner": copy.deepcopy(owner),
            "revision": 0,
            "bindings": {},
            "admission": {},
            "attempts": {},
            "requests": {},
            "results": {},
            "quiescent": {},
        }
        self.records = []
        self.written_bytes = 0
        self.written_rows = 0

    def __call__(self, envelope):
        encoded = canonical(envelope)
        value = strict_json(encoded, max_bytes=len(encoded))
        assert value["format"] == "fishhat.adapter-commit/v1"
        assert value["kind"] in {"delta", "checkpoint"}
        payload = "updates" if value["kind"] == "delta" else "checkpoint"
        assert set(value) == {
            "format",
            "kind",
            "owner",
            "expected_revision",
            "revision",
            payload,
        }
        assert value["owner"] == self.state["owner"]
        assert value["expected_revision"] == self.state["revision"]
        assert value["revision"] == self.state["revision"] + 1
        if payload == "checkpoint":
            assert value[payload]["owner"] == value["owner"]
            assert value[payload]["revision"] == value["revision"]
            self.state = value[payload]
        else:
            self._check_updates(value[payload])
            self._apply_updates(value[payload])
            self.state["revision"] = value["revision"]
        self.records.append(encoded)
        self.written_bytes += len(encoded)

    def _check_updates(self, updates):
        assert updates and set(updates) <= {
            "bindings",
            "admission",
            "attempts",
            "requests",
            "results",
            "quiescent",
        }
        for attempt_id, request in updates.get("requests", {}).items():
            previous = self.state["requests"].get(attempt_id)
            assert previous is None or previous == request
        for attempt_id, evidence in updates.get("results", {}).items():
            assert set(evidence) == {"latest", "records", "knowledge"}
            previous = self.state["results"].get(attempt_id, {"records": {}})
            assert evidence["latest"] in evidence["records"]
            for identity, record in evidence["records"].items():
                assert digest(record) == identity
                assert (
                    identity not in previous["records"] or previous["records"][identity] == record
                )

    def _apply_updates(self, updates):
        for table, rows in updates.items():
            self.written_rows += len(rows)
            if table != "results":
                self.state[table].update(rows)
                continue
            for attempt_id, evidence in rows.items():
                previous = self.state["results"].setdefault(attempt_id, {"records": {}})
                previous["records"].update(evidence["records"])
                previous["latest"] = evidence["latest"]
                previous["knowledge"] = evidence["knowledge"]

    def snapshot(self):
        return copy.deepcopy(self.state)
