# DudeFS developer toolchain — Astral uv + ruff (lint/format) + ty (typecheck).
#
# FULLY SELF-CONTAINED: uv installs into ./.uv (not ~/.local/bin), its cache is
# ./.uv/cache, and the venv is ./.venv — nothing touches the system. The RUNTIME
# is stdlib + ONE crypto dependency: PyNaCl (libsodium) is the L0 backend
# (CRYPTO.md / NOTES 46); everything else here is dev-only. The venv is
# VSCode-compatible (.vscode/settings.json points at .venv/bin/python).
#
#   make install     install a project-local uv + create .venv + install tools
#   make lint        ruff check
#   make format      ruff format (writes)
#   make check       lint + format-check + typecheck + test  (CI-style, no writes)
#   make clean       remove .venv + caches   |   make distclean   also removes .uv

TOOLS := $(CURDIR)/.uv
UV    := $(TOOLS)/uv
VENV  := $(CURDIR)/.venv
PY    := $(VENV)/bin/python
RUFF  := $(VENV)/bin/ruff
TY    := $(VENV)/bin/ty

# Keep uv's cache inside the project too, so `make` creates nothing under $HOME.
export UV_CACHE_DIR := $(TOOLS)/cache

.PHONY: help install uv-bootstrap lint format format-check typecheck test check clean distclean

help:
	@echo "targets: install | lint | format | format-check | typecheck | test | check | clean | distclean"

# Install uv as a standalone binary INTO THE PROJECT (./.uv), never touching
# ~/.local/bin or shell profiles (UV_NO_MODIFY_PATH=1). No-op if already present.
uv-bootstrap:
	@test -x "$(UV)" || { \
	  echo ">> installing project-local uv into $(TOOLS)"; \
	  mkdir -p "$(TOOLS)"; \
	  curl -LsSf https://astral.sh/uv/install.sh \
	    | env UV_UNMANAGED_INSTALL="$(TOOLS)" UV_NO_MODIFY_PATH=1 sh; }

# Create the venv (Python 3.12) and install the dev tools into it.
install: uv-bootstrap
	"$(UV)" venv "$(VENV)" --python 3.12 --clear
	"$(UV)" pip install --python "$(PY)" ruff ty pynacl
	@echo ">> toolchain ready (project-local); 'make check' to run everything"

lint:
	"$(RUFF)" check dudefs tests

format:
	"$(RUFF)" format dudefs tests

format-check:
	"$(RUFF)" format --check dudefs tests

typecheck:
	"$(TY)" check dudefs tests

test:
	"$(PY)" -m unittest discover -s tests

# CI-style gate: no writes, fails on any issue.
check: lint format-check typecheck test

clean:
	rm -rf "$(VENV)" "$(TOOLS)/cache" .ruff_cache

distclean: clean
	rm -rf "$(TOOLS)"
