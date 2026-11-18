LINT = cargo clippy --all-targets -- -D warnings

.PHONY: test lint test-ci coverage

test:
	cargo test

lint:
	$(LINT)

test-ci:
	docker run --rm doas-dev sh -lc '$(LINT) && cargo test'

coverage:
	mkdir -p .work/tmp .work/coverage
	TMPDIR="$(CURDIR)/.work/tmp" cargo llvm-cov --locked --branch --json --output-path .work/coverage/report.json
	cargo llvm-cov report --branch --summary-only
