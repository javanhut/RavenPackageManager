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
| Verification | SHA-256 from the sync database, plus detached PGP signatures on both packages and repository databases, checked against the pacman keyring |
| Extraction | zstd, xz, gzip and bzip2 tar unpacking with path-traversal rejection and file-conflict detection |
| AUR | RPC v5 search/info, git checkout, `.SRCINFO` parsing, and building |
| Scriptlets | `.INSTALL` hooks run around install, upgrade and removal |

Because a PKGBUILD *is* a bash script, building AUR packages requires `bash` and
`makepkg`. Everything else is rvn's own code.

### Building From The AUR

`rvn install <aur-package>` clones the build files, reads `.SRCINFO`, installs any
repository dependencies **first**, then builds — so a PKGBUILD's `makedepends` are
present before makepkg runs. AUR packages that depend on other AUR packages are
built and installed one at a time, in dependency order.

makepkg refuses to run as root, but rvn needs root to install. rvn resolves this by
dropping privileges for the build: it uses `$SUDO_USER` when invoked through sudo,
and otherwise falls back to an unprivileged account, handing the build tree over
first so git and makepkg both run as the same user.

The version recorded is the one the built package reports, not the one the AUR RPC
advertised — a `-git` package's `pkgver()` is only evaluated at build time, so the
two routinely differ.

Before building, rvn offers to show you the PKGBUILD and any install scriptlet,
since both are arbitrary code from a stranger. `-y` skips the prompt.

#### Devel Packages

A `-git` package's version is computed at build time, so it never changes on its
own — comparing versions will never report an update no matter how far upstream
moves. rvn records the upstream commit it built and asks the remote whether that
commit is still current:

```
  ▸  updates to apply (1)
     └─ aur/ttf-material-design-icons-git v7.4.47.r0.g57b567a-1 (upstream moved — rebuild)
```

A remote that cannot be reached is left alone rather than reported as outdated, so
an offline update does not propose rebuilding everything.

If a package's sources are signed by a key you do not have, rvn says which key:

```
  ✖  neofetch: the source is signed by a key that is not trusted locally.
     Import it with `gpg --recv-keys 46D62DD9F1DE636E` and try again
```

### Status

`install`, `uninstall`, `update`, `find` and `sync` are implemented end to end.

### Pacman Interoperability

rvn writes `/var/lib/pacman/local` in pacman's own format, so the two agree about
what is installed. Verified against a real Arch Linux ARM system:

```
$ rvn install neovim -y            # 16 packages, 2311 files
$ pacman -Qi neovim
Depends On      : glibc  libgcc  libluv  libtree-sitter.so=0.26-64  …
Installed Size  : 4.13 MiB
Install Reason  : Explicitly installed
Validated By    : Signature
$ pacman -Qkk neovim
neovim: 2311 total files, 0 altered files
```

`pacman -Qkk` passing means every file's checksum, permissions and timestamp match
the package's `.MTREE`. Packages installed by rvn can be removed by pacman and
vice versa. The same holds for packages rvn builds from the AUR, whose metadata is
taken from the built archive's `.PKGINFO`:

```
$ rvn install bash-pipes -y     # pulls pipes.sh from the AUR first
$ pacman -Qi bash-pipes | grep Depends
Depends On      : pipes.sh=1.3.0
$ pacman -Qi pipes.sh  | grep Reason
Install Reason  : Installed as a dependency for another package
```

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

Dependencies that nothing else needs are removed along with the target, so
uninstalling does not silently leave a system full of orphans.

| Option | Effect |
| --- | --- |
| `--cascade` | Also remove packages that depend on the targets |
| `--keep-orphans` | Leave behind dependencies nothing needs any more |
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

### Install From Search Results

Running `rvn find` on a terminal numbers the results and offers to install them,
so a search does not have to be followed by retyping a package name.

```
$ rvn find ripgrep
 1 extra/ripgrep 15.2.0-1
 2 aur/ripgrep-git 15.1.0.r4.57c190d5-1
  ▸  install which? (e.g. 1 3, 2-4, ^2, blank to skip)
```

Selections accept single numbers, ranges (`2-4`), and exclusions (`^3`, or `^2-4`).
Use `--no-select` to print results without the prompt.

### Inspecting The System

| Command | Purpose |
| --- | --- |
| `rvn info <pkg>` | Everything known about a package, installed or not |
| `rvn list` | Installed packages (`--explicit`, `--foreign`, `--orphans`) |
| `rvn owns <path>` | Which package owns a file |
| `rvn files <pkg>` | The files an installed package owns |

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

### Install Scriptlets

Packages may ship an `.INSTALL` scriptlet defining `pre_install`, `post_install`,
`pre_upgrade`, `post_upgrade`, `pre_remove` and `post_remove`. rvn runs the
appropriate hook around each transaction and stores the scriptlet alongside the
package record, so removal hooks still work long after installation. When the
install root is not `/`, hooks run inside it via `chroot`.

A failing hook is reported as a warning rather than aborting the transaction —
the files are already on disk, and unwinding would leave a worse state behind.

### Refresh Repository Databases

```bash
rvn sync
```

Databases are verified against their detached signature before being used:

```
  ✔  core synced (249 KB) · signature verified
```

`SigLevel` is honoured separately for packages and databases, as pacman does, so
`SigLevel = Required DatabaseOptional` means a package signature is mandatory while
a database signature is checked only when the repository publishes one. A database
signature that is present but does not match is always fatal — that is a tampered
database, not a missing convenience — and the file is discarded rather than left
for the next command to read.

| Token | Effect |
| --- | --- |
| `Never` / `Optional` / `Required` | Sets both packages and databases |
| `PackageNever` / `PackageOptional` / `PackageRequired` | Packages only |
| `DatabaseNever` / `DatabaseOptional` / `DatabaseRequired` | Databases only |

Neither Arch nor Arch Linux ARM currently publishes `.db.sig` files, which is why
the shipped configuration uses `DatabaseOptional`.

## Global Options

rvn looks after its own housekeeping, so a normal install needs no flags at all:
repository databases are refreshed when they are missing or stale, downloaded
archives are cleared once they have been installed, and removing a package also
removes the dependencies nothing else needs.

| Option | Effect |
| --- | --- |
| `--config <PATH>` | Use an alternative `pacman.conf` (default `/etc/pacman.conf`) |
| `--repo-only` | Skip the AUR and use official repositories only |
| `-y`, `--yes` | Assume yes for every prompt |
| `--dry-run` | Resolve and show the plan without changing anything |
| `--keep-cache` | Keep downloaded packages instead of clearing them afterwards |
| `--no-sync` | Never refresh repository databases automatically |

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

To test against a real Arch system from a non-Arch machine:

```bash
docker run -d --name rvn-arch -v "$PWD":/src:ro \
  menci/archlinuxarm:base-devel sleep infinity
docker exec rvn-arch sh -c \
  "sed -i '0,/^\[options\]/s//[options]\nDisableSandbox/' /etc/pacman.conf &&
   pacman -Sy --noconfirm rust &&
   cp -r /src/src /src/Cargo.toml /src/Cargo.lock /work/ &&
   cd /work && cargo build --release"
```

`DisableSandbox` is only needed to let pacman bootstrap Rust inside a container;
rvn itself does not use pacman.
