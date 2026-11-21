.PHONY: all check test clippy fmt ffi bench clean

all: check test

check:
	cargo check --workspace
	cargo check -p silentwire --no-default-features --offline --locked

clippy:
	cargo clippy --workspace --all-targets --offline --locked -- -D warnings

test:
	cargo test --workspace --release --offline --locked

fmt:
	cargo fmt --all --check

ffi:
	cargo build -p silentwire-ffi --release --offline --locked
	mkdir -p target/ffi
	cc -std=c11 -Wall -Wextra -Werror -I tests -I bindings/include tests/ffi.c -L target/release -lsilentwire_ffi -Wl,-rpath,target/release -o target/ffi/test_ffi
	./target/ffi/test_ffi

bench:
	cargo run -p silentwire-cli --release -- compare --txs 100

clean:
	cargo clean
	rm -rf target/ffi
