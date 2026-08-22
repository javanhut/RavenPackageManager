# Raven Package Manager

Raven Package Manager or rvn is a package manager built in Rust as the default package manager for Raven Linux.

## Architecture

Since Raven Linux is built on top of Arch Linux, `rvn` is compatible with the Arch
package ecosystem for x86_64 and arm, with x86_64 as the default target.

Rather than wrapping `pacman` and `yay`, rvn implements the package manager natively:
official repositories and the AUR are both handled by a single binary, so neither
`pacman` nor `yay` needs to be installed separately.

| Layer | What rvn does itself |
| --- | --- |
| Configuration | Parses `/etc/pacman.conf` and mirrorlists, including `$repo`/`$arch` expansion |
| Sync databases | Downloads and parses `$repo.db` tarballs from mirrors |
| Local database | Reads and writes `/var/lib/pacman/local` in pacman's own format |
| Version comparison | Full `alpm_pkg_vercmp` port, including epochs and release ordering |
| Dependency resolution | Transitive resolution with provides, versioned constraints, conflicts and cycle handling |
| Download | Streaming fetch with mirror failover and resumable `.part` files |
| Verification | SHA-256 from the sync database, plus detached PGP signatures checked against the pacman keyring |
| Extraction | zstd + tar unpacking with path-traversal rejection and file-conflict detection |
| AUR | RPC v5 search/info, git checkout, `.SRCINFO` parsing, and building |

Because a PKGBUILD *is* a bash script, building AUR packages requires `bash`, and
currently uses `makepkg` when it is present. Everything else is rvn's own code.

### Status

`install`, `uninstall`, `update`, `find` and `sync` are implemented end to end.

# Required Installations

- Rust
- Make or [ImLazy](https://github.com/javanhut/ImLazy.git)
- Optional for ImLazy - Go

# Getting Started

## ImLazy Installation (Default)

### Git

```bash
git clone https://github.com/javanhut/RavenPackageManager.git
cd RavenPackageManager
imlazy install
```

### Ivaldi

```bash
ivaldi download javanhut/RavenPackageManager
cd RavenPackageManager
imlazy install
```

## Make Installation

### Git

```bash
git clone https://github.com/javanhut/RavenPackageManager.git
cd RavenPackageManager
make install
```

### Ivaldi

```bash
ivaldi download javanhut/RavenPackageManager
cd RavenPackageManager
make install
```

# Quick Start

### Version Command

```bash
rvn --version
```

### Help

```bash
rvn --help
```

### Install Package(s)

```bash
rvn install go
```

#### Multiple Package Install

```bash
rvn install go rust treesitter-cli
```

### Uninstall Package

```bash
rvn uninstall go
```

rvn refuses a removal that would break something else, and says what:

```
  ✖  removal would break installed packages:
     ├─ ncurses is required by readline (needs libncursesw.so=6-64)
     └─ ncurses is required by bash (needs ncurses)
  •  use --cascade to remove the dependents too, or --nodeps to force
```

| Option | Effect |
| --- | --- |
| `--cascade` | Also remove packages that depend on the targets |
| `-r`, `--recursive` | Also remove dependencies that become orphaned |
| `--nodeps` | Remove even if it breaks other packages |
| `--dry-run` | Show what would be removed without changing anything |

Files shared with another installed package are left alone, empty directories are
pruned, and a configuration file you edited is kept as `<name>.pacsave` rather than
deleted — matched against the checksum recorded when it was installed, so untouched
config is simply removed.

### Update Package

```bash
rvn update go
```

### Update Package(s)

```bash
rvn update go rust
```

### Update Everything

With no arguments, `update` refreshes the databases and upgrades the whole system.

```bash
rvn update
```

```
  ✔  1 update available (3ms)

  ▸  updates to apply (1)
     └─ extra/ripgrep 14.0.0-1 → 15.2.0-1

  •  download 1.4 MB
```

Renamed packages are handled through `%REPLACES%`, and the superseded package is
retired once its successor is installed. A package whose installed version is
*newer* than the repositories carry is reported and skipped rather than silently
rolled back.

| Option | Effect |
| --- | --- |
| `--no-refresh` | Use the cached databases instead of syncing first |
| `--dry-run` | Show available updates without applying them |

### Update Package Manager

```bash
rvn-update
```

### Search for a Package

Searches official repositories and the AUR together, tagging each result with its
source and marking anything already installed.

```bash
rvn find ripgrep
```

```
extra/ripgrep 15.2.0-1
    A search tool that combines the usability of ag with the raw speed of grep
aur/ripgrep-git 15.1.0.r4.57c190d5-1 (0.0)
    A search tool that combines the usability of The Silver Searcher with the raw speed of grep.
```

### Refresh Repository Databases

```bash
rvn sync
```

## Global Options

| Option | Effect |
| --- | --- |
| `--config <PATH>` | Use an alternative `pacman.conf` (default `/etc/pacman.conf`) |
| `--repo-only` | Skip the AUR and use official repositories only |
| `-y`, `--noconfirm` | Answer every prompt affirmatively |
| `--dry-run` | Resolve and show the plan without changing anything |

### Previewing a Transaction

```bash
rvn install ripgrep --dry-run
```

```
  ✔  resolved 14 packages, 13 dependencies (1ms)

  ▸  packages requested
     └─ extra/ripgrep 15.2.0-1
  ▸  dependencies (13)
     ├─ core/linux-api-headers 7.2-1
     ├─ core/glibc 2.44+r24+g16be1518495f-1
     └─ core/pcre2 10.47-1

  •  download 20.1 MB   installed size 93.1 MB
```

# Development

```bash
cargo build            # debug binary at target/debug/rvn
cargo test             # unit tests
cargo build --release  # optimised binary at target/release/rvn
```

Operations can be exercised against a sandbox root without touching the system by
pointing `--config` at a `pacman.conf` whose `RootDir`, `DBPath` and `CacheDir` are
set to a scratch directory.
