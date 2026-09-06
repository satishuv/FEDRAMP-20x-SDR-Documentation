# Thin wrapper over sdr.py. The Python entry point is the real one; this file
# exists because `make` is muscle memory for a lot of people.
#
# Override the interpreter if you need to: make all PYTHON=python3.12

PYTHON ?= python

.DEFAULT_GOAL := help
.PHONY: help install all build validate scan clean reproducible catalog

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

install: ## Install the three runtime dependencies
	$(PYTHON) -m pip install jsonschema referencing python-docx

all: ## Build, validate, scan, then print a readiness summary
	$(PYTHON) sdr.py all

build: ## Regenerate every deliverable from the record store
	$(PYTHON) sdr.py build

validate: ## Run the build gate; 0 hard failures required to ship
	$(PYTHON) sdr.py validate

scan: ## Run the readiness scanner (reports, does not gate)
	$(PYTHON) sdr.py scan

clean: ## Remove caches and scanner reports
	$(PYTHON) sdr.py clean

catalog: ## Regenerate the scanner check catalog after editing checks.py
	$(PYTHON) automation/sdrscan/sdrscan.py --write-catalog

reproducible: ## Prove the deliverables match their inputs (the CI gate, locally)
	$(PYTHON) sdr.py build
	@git diff --exit-code -- . ':(exclude)*.docx' \
		&& echo "OK. Every generated file matches what the pipeline produces." \
		|| { echo "FAIL. A generated file was hand-edited. Edit the record store instead."; exit 1; }
