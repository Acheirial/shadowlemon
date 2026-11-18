# Copyright (C) 2022  mieru authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

SHORT_SHA=$(shell git rev-parse --short HEAD)
TEST_BINARY_PREREQ = test-binary
# Tag of the container image used by the integration tests. It can be overridden
# from the environment, e.g. by CI when the image is built by another tool.
TEST_CONTAINER_IMAGE ?= shadowlemon_basic:${SHORT_SHA}
FUZZ_TIME ?= 10s

# PROTOCOL_VERSION: ShadowLemon V0.2 wire protocol version byte is 4 (V0.1 was
# 3). V0.2 is wire-incompatible with every older release; both peers must run
# the same version.

# With .ONESHELL, each recipe is executed in a single shell instance.
# This allows `cd` to affect subsequent commands in the same recipe.
# .ONESHELL is supported in GNU Make version 3.82 and later.
.ONESHELL:

# Cargo installs its binaries into ~/.cargo/bin, which is not always on PATH
# (notably in minimal CI images). Every recipe prepends that directory so the
# targets work without requiring the caller to configure the shell first.

# Build the release binary into bin/. The single binary serves both the client
# (shadowlemon client <command>) and the server (shadowlemon server <command>).
.PHONY: build
build: bin

# Build binaries.
.PHONY: bin
bin:
	mkdir -p bin
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo build --release --bin shadowlemon
	cp target/release/shadowlemon ../bin/shadowlemon

# Run all unit / integration tests in the Rust workspace.
.PHONY: test
test:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo test --workspace

# Compile all workspace crates without running the tests.
.PHONY: compile
compile:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo build --workspace

# Format source code.
.PHONY: fmt
fmt:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo fmt --all

# Verify that the source code is formatted without rewriting it (CI gate).
.PHONY: fmt-check
fmt-check:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo fmt --all -- --check

# Alias kept for compatibility: the Rust equivalent of "vet" is clippy.
.PHONY: vet
vet: clippy

# Lint all Rust targets with warnings treated as errors (CI gate).
.PHONY: clippy
clippy:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: lint
lint: clippy

# Run benchmarks.
.PHONY: bench
bench:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo bench --workspace

# Run every cargo-fuzz target for FUZZ_TIME (default 10s).
# Requires nightly and cargo-fuzz.
.PHONY: fuzz
fuzz:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && for target in $$(cargo fuzz list); do cargo fuzz run "$$target" -- -max_total_time=${FUZZ_TIME}; done

# List the cargo-fuzz targets. Requires nightly and cargo-fuzz.
.PHONY: fuzz-list
fuzz-list:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo fuzz list

# Size-optimized embedded build: uses the `embedded` profile and feature.
# Add --target <triple> for cross compilation (see rust/docs/platform-notes.md).
.PHONY: rust-embedded
rust-embedded:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo build --profile embedded --no-default-features --features embedded

# Build binaries used in integration tests: the main binary plus the four
# helpers (httpserver, udpserver, sockshttpclient, socksudpclient) provided by
# the rust/test-utils crate. All five are placed in bin/.
.PHONY: test-binary
test-binary: bin
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo build --release --manifest-path test-utils/Cargo.toml --bins --target-dir target
	cp target/release/httpserver target/release/udpserver target/release/sockshttpclient target/release/socksudpclient ../bin/

# Build docker images to run integration tests.
.PHONY: test-container-image
test-container-image: test-container-image-basic

.PHONY: test-container-image-basic
test-container-image-basic: $(TEST_BINARY_PREREQ)
	docker build -t $(TEST_CONTAINER_IMAGE) -f test/deploy/basic/Dockerfile .

# Run docker integration tests.
.PHONY: run-container-test
run-container-test: run-container-test-basic

.PHONY: run-container-test-prebuilt
run-container-test-prebuilt:
	$(MAKE) TEST_BINARY_PREREQ= run-container-test

.PHONY: run-container-test-basic
run-container-test-basic: test-container-image-basic
	docker run --rm $(TEST_CONTAINER_IMAGE)

# Compatibility aliases for the earlier Rust helper target names.
.PHONY: rust-build rust-test rust-fmt-check rust-clippy rust-fuzz rust-fuzz-list
rust-build: build
rust-test: test
rust-fmt-check: fmt-check
rust-clippy: clippy
rust-fuzz: fuzz
rust-fuzz-list: fuzz-list

# Offline OpenGFW FET evaluator / evasion-prefix search (research tool).
# Set PCAP=<file> for the check/scan targets; see tools/gfw-search.md.
GSEARCH ?= /tmp/opencode/gfw-search
PCAP ?=
.PHONY: gfw-search gfw-search-check gfw-search-scan
gfw-search:
	export PATH="$$HOME/.cargo/bin:$$PATH" && rustc -O tools/gfw-search.rs -o $(GSEARCH)
gfw-search-check: gfw-search
	$(GSEARCH) check $(PCAP)
gfw-search-scan: gfw-search
	$(GSEARCH) search $(PCAP) 20 128

# Remove build outputs.
.PHONY: clean
clean:
	rm -rf bin rust/target rust/fuzz/target
	rm -f coverage.out coverage.html

# Clean the Cargo build cache.
.PHONY: clean-cache
clean-cache:
	cd rust && export PATH="$$HOME/.cargo/bin:$$PATH" && cargo clean
