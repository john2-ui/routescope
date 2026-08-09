.PHONY: run check test fmt seed smoke namespace-up namespace-down namespace-status namespace-test namespace-collector-test

run:
	set -a && [ -f .env ] && . ./.env; set +a; cargo run

check:
	cargo check

test:
	cargo test

fmt:
	cargo fmt

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
