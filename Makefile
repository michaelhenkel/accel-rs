.PHONY: cli_server cli_client accel
ARCH?=x86_64
all: cli_server cli_client accel

cli_server:
	(cd cli_server; cargo build --release --target=${ARCH}-unknown-linux-gnu)

cli_client:
	(cd cli_client; cargo build --release --target=${ARCH}-unknown-linux-gnu)

accel: ebpf
	(cd accel; cargo build --release --target=${ARCH}-unknown-linux-gnu)
ebpf:
	(cd accel; cargo xtask build-ebpf --release)
