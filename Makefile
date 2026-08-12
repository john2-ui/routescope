.PHONY: run check test fmt clippy benchmark seed smoke namespace-up namespace-down namespace-status namespace-test namespace-collector-test namespace-dns-test

run:
	set -a && [ -f .env ] && . ./.env; set +a; cargo run

check:
	cargo check

test:
	cargo test

clippy:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

benchmark:
	cargo run --quiet --release -- benchmark-storage $${ROUTESCOPE_BENCHMARK_FLOWS:-10000}

seed:
	set -a && [ -f .env ] && . ./.env; set +a; python3 scripts/seed_dev_data.py

smoke:
	bash scripts/smoke_api.sh

namespace-up:
	scripts/namespace_lab.sh up

namespace-down:
	scripts/namespace_lab.sh down

namespace-status:
	scripts/namespace_lab.sh status

namespace-test:
	scripts/namespace_lab.sh test

namespace-collector-test:
	cargo build
	sudo scripts/namespace_lab.sh collector-test

namespace-dns-test:
	cargo build
	cargo test --test namespace_dns -- --ignored --nocapture
