.PHONY: test test-ci

test:
	cargo test

test-ci:
	docker run --rm doas-dev sh -lc 'cargo clippy --all-targets -- -D warnings && cargo test'
