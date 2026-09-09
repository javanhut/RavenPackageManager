PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
BINARY = rvn
TARGET = target/release/$(BINARY)

.PHONY: build test check install uninstall clean help

## Build release binary
build:
	cargo build --locked --release

## Run all tests
test:
	cargo test --locked --all-targets

## Run the local quality gates
check:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked --all-targets

## Install rvn to $(PREFIX)/bin (default: /usr/local/bin)
install: build
	@echo "Installing $(BINARY) to $(BINDIR)..."
	@install -d $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/$(BINARY)
	@install -m 755 target/release/rvnd $(BINDIR)/rvnd
	@echo "Installed $(BINARY) and rvnd to $(BINDIR)"
	@echo "Run 'rvn --version' to verify."

## Uninstall rvn from $(PREFIX)/bin
uninstall:
	@echo "Removing $(BINDIR)/$(BINARY)..."
	@rm -f $(BINDIR)/$(BINARY)
	@echo "Uninstalled $(BINARY)"

## Clean build artifacts
clean:
	cargo clean

## Show help
help:
	@echo "Raven Package Manager — Makefile targets:"
	@echo ""
	@echo "  make build      Build release binary"
	@echo "  make test       Run all tests"
	@echo "  make check      Run formatting, Clippy, and the full locked test suite"
	@echo "  make install    Install to $(BINDIR) (may need sudo)"
	@echo "  make uninstall  Remove from $(BINDIR) (may need sudo)"
	@echo "  make clean      Clean build artifacts"
	@echo ""
	@echo "Override install location:"
	@echo "  make install PREFIX=~/.local"
