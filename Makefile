.PHONY: setup contracts test suite demo diagram
setup: ; pip install -r requirements.txt
contracts: ; cd scripts && npm install --prefix ../.solc solc@0.8.19 && SOLC=../.solc/node_modules/solc node compile.js   # build/contracts.json is committed; only needed to rebuild
test: ; python -m pytest -q tests
suite: ; python scripts/run_suite.py
demo: ; python -m aegis.cli demo
diagram: ; python scripts/make_diagram.py
