test:
	uv run pytest tests

clean:
	rm -rf ./dist || true
	rm -r ./pqcrypto/* || true

compile:
	uv run python3 compile.py

format:
	uvx ruff format

build:
	make clean
	cibuildwheel --output-dir dist

update:
	git submodule update --init --recursive
	uv run python document.py
