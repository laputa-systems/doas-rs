LINT = cargo clippy --all-targets -- -D warnings

.PHONY: test lint test-ci

test:
	cargo test

lint:
	$(LINT)

test-ci:
	docker run --rm doas-dev sh -lc '$(LINT) && cargo test'
