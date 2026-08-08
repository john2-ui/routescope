.PHONY: run check test fmt seed smoke

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
