PREFIX ?= /usr/local
DESTDIR ?=
BINDIR = $(DESTDIR)$(PREFIX)/bin
BINARY = rvn
TARGET = target/release/$(BINARY)

# The configuration files are read from paths compiled into the binaries --
# `policy::DEFAULT_PATH` is /etc/raven/rvnd.toml and `sign::CONFIG` is
# etc/rvn/build.toml under the install root -- so they go to /etc whatever
# PREFIX says. A copy under ~/.local/etc would be a file nothing ever reads.
# SYSCONFDIR is here for a packaging run that stages a root somewhere else;
# DESTDIR is the usual way to do that and works on both.
SYSCONFDIR ?= /etc
CONFDIR = $(DESTDIR)$(SYSCONFDIR)

# Reference configuration, named relative to both etc/ here and $(CONFDIR)
# there. Every value in these files is a default and the whole of each file is
# optional, so they are documentation that happens to be machine-readable
# rather than something a machine needs -- but documentation that never leaves
# the source tree is documentation nobody reads. install-config is how they
# reach the machine.
CONFIGS = raven/rvnd.toml rvn/build.toml

.PHONY: build test check install install-bin install-config uninstall clean help

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

## Install the binaries and the reference configuration
install: build install-bin install-config

## Install rvn and rvnd to $(PREFIX)/bin (default: /usr/local/bin)
install-bin:
	@echo "Installing $(BINARY) to $(BINDIR)..."
	@install -d $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/$(BINARY)
	@install -m 755 target/release/rvnd $(BINDIR)/rvnd
	@echo "Installed $(BINARY) and rvnd to $(BINDIR)"
	@echo "Run 'rvn --version' to verify."

## Install the reference configuration, never over a file somebody has edited
#
# A file that is already there is left exactly as it is and the new version is
# written beside it as `.pacnew`. That is not a convention invented for this
# target: it is the one rvn itself applies to every `backup` file in every
# package it installs, and `rvn config list` walks /etc for precisely those
# suffixes -- so a .pacnew this target leaves behind turns up in the same
# review desk as one an upgrade left, and `rvn config diff`, `merge`, `accept`
# and `keep` settle it the same way.
#
# Refusing to overwrite matters more here than for an ordinary file. The two
# files are policy: rvnd.toml says which operations need a human to agree to
# them, and an administrator who has set `on_auth_unavailable = "deny"` would
# be put back to failing open by a `make install` that clobbered it -- silently,
# and at exactly the moment they thought they were tightening the machine up.
install-config:
	@for config in $(CONFIGS); do \
		src="etc/$$config"; \
		dest="$(CONFDIR)/$$config"; \
		install -d "$${dest%/*}" || exit 1; \
		if [ ! -e "$$dest" ]; then \
			install -m 644 "$$src" "$$dest" || exit 1; \
			echo "Installed $$dest"; \
		elif cmp -s "$$src" "$$dest"; then \
			echo "Unchanged $$dest"; \
		else \
			install -m 644 "$$src" "$$dest.pacnew" || exit 1; \
			echo "Kept $$dest (yours); shipped version is $$dest.pacnew"; \
			echo "  review it with: rvn config diff $(SYSCONFDIR)/$$config"; \
		fi; \
	done

## Uninstall rvn from $(PREFIX)/bin
#
# The configuration is deliberately left behind. An administrator's policy
# outliving the binary it configures is the harmless direction to be wrong in;
# deleting a rvnd.toml somebody wrote because a binary was reinstalled the long
# way round is not. `make uninstall` says where they are rather than guessing.
uninstall:
	@echo "Removing $(BINDIR)/$(BINARY) and $(BINDIR)/rvnd..."
	@rm -f $(BINDIR)/$(BINARY) $(BINDIR)/rvnd
	@echo "Uninstalled $(BINARY)"
	@for config in $(CONFIGS); do \
		if [ -e "$(CONFDIR)/$$config" ]; then \
			echo "Left in place: $(CONFDIR)/$$config"; \
		fi; \
	done

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
	@echo "  make install    Install to $(BINDIR) and $(CONFDIR) (may need sudo)"
	@echo "  make uninstall  Remove from $(BINDIR) (may need sudo)"
	@echo "  make clean      Clean build artifacts"
	@echo ""
	@echo "Override install location:"
	@echo "  make install PREFIX=~/.local"
	@echo "  make install DESTDIR=/path/to/staged/root   (packaging)"
	@echo ""
	@echo "Configuration goes to $(CONFDIR) whatever PREFIX says, because the"
	@echo "binaries read it from there. An existing file is never overwritten:"
	@echo "the shipped version lands beside it as .pacnew."
