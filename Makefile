SHELL := bash
.DEFAULT_GOAL := help

MISE_BIN ?= mise
FILES ?= .
TESTS ?= tests
UNIT_WORKERS ?= 4
UNIT_REPORT_ARGS ?= --durations=30 --durations-min=0.25
PYTHON_PATHS ?= packages fishhat some-implementations scripts tests
BUNDLE_OUTPUT ?= artifacts/scaffold-bundle
WATCHDOG_UV = UV_HTTP_TIMEOUT="$$("$(MISE_BIN)" x -- python -m scripts.validation_timeouts uv-http)"
UV_RUN = $(WATCHDOG_UV) "$(MISE_BIN)" x -- uv run --locked --all-packages --group dev
VALIDATE = $(UV_RUN) python -m scripts.validation run --target $@ --
args ?=

.PHONY: help setup check test unit ruff ruff-fix format format-check fix mypy lint compile contracts dist package audit policy license governance bundle dist-smoke operation-qualification engineering database-qualification profile evidence

# check-purpose: repository-policy
help:
	@printf '%s\n' \
		'Targets:' \
		'  make setup         Install locked tools/dependencies and the local commit hook.' \
		'  make unit          Run the local unit suite.' \
		'  make ruff          Check Python lint.' \
		'  make ruff-fix      Apply safe Ruff fixes.' \
		'  make format        Format Python files.' \
		'  make format-check  Check Python formatting.' \
		'  make fix           Run ruff-fix, then format.' \
		'  make mypy          Run strict type checks.' \
		'  make license       Verify Apache-2.0 REUSE provenance.' \
		'  make lint          Run formatting, lint, types and licensing checks.' \
		'  make compile       Byte-compile repository Python files.' \
		'  make test          Run lint and units.' \
		'  make contracts     Validate schemas and synthetic fixtures.' \
		'  make policy        Check component, interface and state contracts.' \
		'  make engineering   Check operation-owned growth/extent and migration coverage.' \
		'  make database-qualification  Exercise reference-state migrations, crash rollback and retry.' \
		'  make profile       Run an optional cProfile workload; all measurements are report only.' \
		'  make evidence      Reconcile reviewed check purposes; args=--evidence-generate after review.' \
		'  make check         Run lint, contracts, policy, operation coverage and units; check public content.' \
		'  make audit         Audit all locked runtime, build and development dependencies.' \
		'  make dist          Rebuild and inspect every component wheel.' \
		'  make package       Alias for dist.' \
		'  make dist-smoke    Rebuild wheels; prepare and exercise a temporary offline bundle.' \
		'  make bundle        Build a persistent offline scaffold bundle in a new output directory.' \
		'  make governance    Audit live GitHub controls without changing them.' \
		'  make operation-qualification  Check the source-derived operation coverage map.' \
		'' \
		'Variables:' \
		"  args='...'         Forward tool flags to unit, ruff, ruff-fix, format, format-check or mypy." \
		"                     For operation-qualification/engineering: check (default), generate or report [--require-current-proofs]." \
		"  UNIT_WORKERS=...  Unit workers; default: 4. Use 0 for serial debugging." \
		"  TESTS='...'        Select unit test paths or node IDs; default: tests." \
		"  FILES='...'        Select Ruff/format paths; default: ." \
		"  PYTHON_PATHS='...' Select compile paths; default: packages fishhat some-implementations scripts tests." \
		"  UNIT_REPORT_ARGS='...' Pytest reporting flags; default: --durations=30 --durations-min=0.25." \
		"  profile args='--workload canonical|unit|database-qualification|engineering-tests'" \
		'  BUNDLE_OUTPUT=...  Persistent bundle destination; it must not already exist.' \
		'  MISE_BIN=...       Use a particular mise executable.' \
		'' \
		'FISHHAT_VALIDATION_TIMEOUT_SCALE: finite positive validation watchdog factor; default 1.' \
		'It changes observation budgets, preserves runtime deadlines and records actual time unchanged.' \
		'CI resolves the repository variable before jobs start; factors beyond platform ceilings fail.' \
		'Receipts: artifacts/validation; mandatory test stats/targets: artifacts/test-stats; profiles: artifacts/profiles.' \
		'Use TESTS for unit paths and args for pytest flags; test/check also invoke other tools.'

# check-purpose: repository-policy
setup:
	"$(MISE_BIN)" install --locked
	$(WATCHDOG_UV) "$(MISE_BIN)" x -- uv sync --locked --all-packages --group dev
	git config --local core.hooksPath .githooks

# check-purpose: validation-tooling
ruff:
	$(VALIDATE) python -m ruff check $(FILES) $(args)

# check-purpose: validation-tooling
ruff-fix:
	$(VALIDATE) python -m ruff check --fix $(FILES) $(args)

# check-purpose: validation-tooling
format:
	$(VALIDATE) python -m ruff format $(FILES) $(args)

# check-purpose: validation-tooling
format-check:
	$(VALIDATE) python -m ruff format --check $(FILES) $(args)

# check-purpose: validation-tooling
fix: ruff-fix format

# check-purpose: validation-tooling
mypy:
	$(VALIDATE) python -m mypy $(args)

# check-purpose: validation-tooling
lint: format-check ruff mypy license

# check-purpose: validation-tooling
compile:
	$(VALIDATE) python -m compileall -q $(PYTHON_PATHS)

# check-purpose: validation-tooling
unit:
	$(VALIDATE) python -m pytest -q $(TESTS) -n $(UNIT_WORKERS) --dist=worksteal --max-worker-restart=0 $(UNIT_REPORT_ARGS) $(args)

# check-purpose: validation-tooling
test: lint unit

# check-purpose: validation-tooling
contracts:
	$(VALIDATE) python -m scripts.check_contracts

# check-purpose: validation-tooling
check: lint contracts policy operation-qualification engineering evidence unit
	$(UV_RUN) python scripts/check_public.py

# check-purpose: implementation
package: dist

# check-purpose: implementation
dist:
	$(VALIDATE) python -m scripts.distributions build

# check-purpose: validation-tooling
audit:
	$(WATCHDOG_UV) "$(MISE_BIN)" x -- uv export --quiet --locked --all-packages --all-groups --no-emit-workspace --no-hashes --format requirements-txt --output-file .venv/audit-requirements.txt
	$(VALIDATE) python -m pip_audit --timeout $$($(UV_RUN) python -m scripts.validation_timeouts audit-http) --strict --no-deps --disable-pip -r .venv/audit-requirements.txt

# check-purpose: repository-policy
policy:
	$(VALIDATE) python -m scripts.project_policy --history

# check-purpose: repository-policy
license:
	$(VALIDATE) python -m reuse lint

# check-purpose: repository-policy
governance:
	$(VALIDATE) python -m scripts.check_repository --scope full

# check-purpose: implementation
bundle: dist
	$(VALIDATE) python -m scripts.distributions prepare --bundle "$(BUNDLE_OUTPUT)"

# check-purpose: implementation
dist-smoke: dist
	$(VALIDATE) python -m scripts.distributions smoke-fresh

# check-purpose: validation-tooling
operation-qualification:
	$(VALIDATE) python -m scripts.operation_qualification $(if $(strip $(args)),$(args),check)

# check-purpose: validation-tooling
engineering:
	$(VALIDATE) python -m scripts.engineering $(if $(strip $(args)),$(args),check)

# check-purpose: validation-tooling
database-qualification:
	$(VALIDATE) python -m pytest -q tests/test_migrations.py $(UNIT_REPORT_ARGS) $(args)

# check-purpose: validation-tooling
profile:
	$(VALIDATE) python -m scripts.profile $(args)

# check-purpose: validation-tooling
evidence:
	$(UV_RUN) python -m pytest --collect-only -q tests $(args)
