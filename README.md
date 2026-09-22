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

### Installing without sudo: rvnd

Installing needs root; typing a password for every install does not. `rvnd`
is a small daemon that raven-init starts as root. It listens on
`/run/rvn/ctl`, a socket only members of the `wheel` group can open, and runs
the ordinary `rvn --json --yes ...` on their behalf with the connection as its
stdout. An unprivileged `rvn install`, `uninstall`, `update` or `sync` sends
one request line over that socket and replays the event stream through the
same terminal interface, so it looks exactly like a run as root:

```
rvn install seatd libinput      # as yourself; no sudo, no password
```

In the terminal it is two phases. The daemon runs the operation with
`--dry-run` and the plan is shown; once you say yes, it runs for real. Nothing
on the wire is interactive, so the question is asked by the client. `--yes`
skips the plan, `--dry-run` skips the apply, and `--json` relays the events
verbatim in a single phase, which is what Raven Store reads.

What crosses the socket is small and checked before anything runs: an
operation name, a package list validated to package-name characters, and a
handful of named flags. The configuration file is never the client's to
choose; the daemon runs with the system's. AUR packages are built by the
dedicated unprivileged `raven-build` account, never as root and never as you.
One transaction runs at a time; a second is told so rather than queued.

The read-only commands (`find`, `info`, `list`, `owns`, `files`) never touch
the daemon; they read databases anyone can read.

### What rvnd asks before it installs

Installing a package is root in the full sense: a package's scriptlets run as
root by design, and a package from the AUR is built from a shell script
somebody else wrote. So the socket's mode is not the whole of the access
control, and for a while it was — which meant that on a desktop where the one
human is in `wheel`, any process running as that human, including the web
browser, could install an arbitrary AUR package and get root with no prompt
and no record.

Three things now stand in front of a request:

1. The socket's mode, as before: the kernel refuses the connect.
2. An explicit check that the peer's account is in the group the socket
   belongs to, read from `/etc/group`. It can only refuse somebody the kernel
   already let through, and it is there so the rule is written in the code.
3. `/etc/raven/rvnd.toml`, which says which classes of operation need the
   human who owns the requesting session to agree to them first.

The policy file classifies every request as `query` (a `sync`, or any
`--dry-run` phase: it writes nothing that is executed), `repo` (packages the
distribution signed) or `aur` (anything that may build a PKGBUILD), and gives
each of them `allow`, `auth` or `deny`. The shipped defaults are `query =
"allow"`, `repo = "auth"`, `aur = "auth"`, and an answered prompt counts for
five minutes in the session that answered it, the way sudo's timestamp does.
The interesting policy the split is for is `repo = "allow"` with
`aur = "auth"`: take the distribution's signed packages without ceremony and
put a human in front of anything that runs a build script.

The prompt is raised by `ravend`, RavenLinux's login daemon, which owns the
session and already holds the account's password and fingerprint policy. On a
machine where nothing answers, `on_auth_unavailable` decides, and it ships as
`"allow"` — deliberately, because a security control whose failure mode is a
bricked package manager gets switched off and then it is not a control. Every
such request is a warning in rvnd's log, is relayed to the client, and is
recorded as `auth=unavailable`; turn the setting to `"deny"` once prompts
demonstrably work. A prompt that was raised and ignored until it timed out is
a refusal, not an absence.

Every privileged request is appended to `/var/log/raven/rvnd-audit.log`, refused
ones included — the time, the uid and account, the pid, the path that pid was
executing according to `/proc/<pid>/exe`, the operation, the classification,
the decision and the packages. `/var/log/pacman.log` records what was
installed; this records what asked for it.

```
$ sudo tail -2 /var/log/raven/rvnd-audit.log
[2026-09-21T13:04:11+0000] [RVND] allowed op=install class=aur rule=auth auth=prompt \
  uid=1000 user=javanstorm gid=1000 pid=4242 session=1200 exe="/usr/bin/rvn" packages=brave-bin
[2026-09-21T13:07:52+0000] [RVND] refused op=install class=aur rule=auth auth=denied \
  uid=1000 user=javanstorm gid=1000 pid=9130 session=1200 exe="/usr/lib/brave/brave" \
  packages=some-aur-package reason="not authorized: the prompt was dismissed"
```

The whole file is optional and every field in it has a default, but a file
that is present and does not parse stops rvnd from starting rather than
falling back — the one failure a policy file must never have is being quietly
ignored. `rvnd --print-policy` writes the shipped file, comments and all, from
inside the binary:

```
rvnd --print-policy | sudo tee /etc/raven/rvnd.toml
```

Without a daemon `rvn` says so and behaves as it always has; with a daemon you
are not allowed to use, it says which group to join. `RVN_SOCKET` points a
client at another socket, for development. Rules for the daemon itself:

```
rvnd [--socket PATH] [--group NAME|none] [--rvn PATH] [--policy PATH]
rvnd --print-policy
```

### Your own prefix: `rvn --user`

`rvn --user install foo` installs into a prefix you own, with no root and no
daemon: packages unpack under `~/.local/share/rvn/root`, the record of what is
installed lives in `~/.local/share/rvn/db`, downloads in `~/.cache/rvn/pkg`.
Repositories, mirrors and the keyring are the system's; the repository
databases are the per-user copy rvn keeps for unprivileged refreshes, seeded
from the system's the first time, so a fresh prefix resolves offline at once
and `rvn --user sync` refreshes it without asking anyone.

```
rvn --user install ripgrep
raven-add path ~/.local/share/rvn/root/usr/bin     # once
rvn --user list
```

What it is honest about: a package's scriptlets and hooks do not run (they
need a chroot and root), and a program that hard-codes `/usr` for its
libraries, data or D-Bus services will not find them under the prefix.
Self-contained tools work; a desktop application generally does not, and
needs a system install through rvnd.

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

While makepkg runs, its output is streamed straight through rather than held
until the build ends — a compile that takes minutes should not be
indistinguishable from a hang. The stage spinner steps aside for the duration
and resumes once the build is done.

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

`install`, `uninstall`, `update`, `find` and `sync` are implemented end to end,
and so is the rest of what a machine needs between them:

| Command | What it does | Where it is written up |
| --- | --- | --- |
| `rvn config` | Settles the `.pacnew` files an upgrade left unmerged | Reviewing Configuration Files |
| `rvn cache` | What the package cache holds, and what may go | The Package Cache |
| `rvn rollback` | Puts one package back to the previous version in that cache | Going Back A Version |
| `rvn build` | Turns a `package.toml` manifest into a package | Building Packages |
| `rvn repo-add` | Turns a directory of packages into a repository | Building Packages |

Transaction hooks run around every transaction from `/etc/rvn/hooks.d`, and
`rvnd` authorizes and audits every privileged request it carries out. Both have
sections of their own — Transaction Hooks below, and "What rvnd asks before it
installs" above.

A repository rvn builds can be served straight off a disk with
`Server = file:///srv/repos/raven`, which is what makes `build` and `repo-add`
a complete loop rather than half of one.

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

## Uninstalling rvn

Removes the `rvn` and `rvnd` binaries. Packages installed with rvn are left in
place — use `rvn uninstall <pkg>` for those — and so is the configuration in
`/etc`, which both runners name rather than delete. An administrator's policy
outliving the binary it configures is the harmless direction to be wrong in.

### ImLazy

```bash
imlazy uninstall
```

### Make

```bash
make uninstall
```

## Install Location

Both runners install to `/usr/local/bin`, so writing there may need `sudo`.
Point them somewhere else with a prefix:

```bash
imlazy install prefix=$HOME/.local   # installs to $HOME/.local/bin/rvn
make install PREFIX=$HOME/.local
```

Uninstalling takes the same prefix, and must match the one used to install:

```bash
imlazy uninstall prefix=$HOME/.local
make uninstall PREFIX=$HOME/.local
```

### The Configuration That Comes With It

Installing also puts two reference files in `/etc`:

| File | What it configures |
| --- | --- |
| `/etc/raven/rvnd.toml` | Which operations rvnd asks a human about, where it asks, and what it records |
| `/etc/rvn/build.toml` | The key `rvn build` and `rvn repo-add` sign with |

Both are heavily commented, every value in them is a default, and a machine
needs neither: they are the reference for the values that exist, installed
where the binaries look for them so that reading one answers a question rather
than requiring a trip to the source tree.

They go to `/etc` whatever prefix is given, because the binaries read them from
paths compiled in — a copy under `~/.local/etc` would be a file nothing ever
opens. A file that is already there is never overwritten: the shipped version
lands beside it as `.pacnew`, which is the same convention rvn applies to every
`backup` file in every package it installs, so `rvn config list` finds it and
`rvn config diff|merge|accept|keep` settle it like any other. Refusing to
overwrite matters most for `rvnd.toml`: an administrator who has set
`on_auth_unavailable = "deny"` should not be put back to failing open by a
reinstall, silently, at the moment they thought they were tightening the machine
up.

Packaging into a staged root takes `DESTDIR`, which applies to both halves:

```bash
make install DESTDIR=/path/to/staged/root
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

Dependencies of the target that nothing else needs are removed along with it, so
uninstalling does not silently leave a system full of orphans. Only the target's own
dependency chain is considered: a package that was already unneeded before the
removal is left alone. Every removal is recorded in `LogFile` (`/var/log/pacman.log`
by default).

With `--yes` (and so through `rvnd`) nobody reviews the plan, so an uninstall that
would also take orphans is refused unless `--remove-orphans` or `--keep-orphans` says
which. Held packages are never removed as orphans or dependents: rvn always holds
`filesystem glibc bash coreutils util-linux shadow pam sudo pacman tar`, plus anything
in `HoldPkg` (`pacman glibc` when unset). Naming a held package outright asks for
confirmation at a terminal and is refused under `--yes`. The makepkg toolchain an AUR
build pulls in (`base-devel`, `git`) is recorded as explicitly installed, so it never
becomes an orphan.

| Option | Effect |
| --- | --- |
| `--cascade` | Also remove packages that depend on the targets |
| `--keep-orphans` | Leave behind dependencies nothing needs any more |
| `--remove-orphans` | Remove orphaned dependencies without asking (needed with `--yes`) |
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

A dry run never needs root: when `/var/lib/pacman/sync` is not writable, the
databases are refreshed into `~/.cache/rvn/sync` instead (the same idea as
pacman's `checkupdates`), so update checks — Raven Settings' and Raven Store's
included — run unprivileged. A dry run with `--no-refresh` reads whichever
copy was synced most recently, the system one or the per-user one, so a
check made in one place is what every other check sees; a per-user copy is
only preferred when it is complete and no older for any repository. Applying
updates still syncs the system databases and needs `sudo`.

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

Parsing `extra.db` takes a few hundred milliseconds, so rvn keeps a parsed copy of
each database under `~/.cache/rvn/index` (`$XDG_CACHE_HOME` is honoured), keyed by
the database's size and modification time. The copy is rebuilt on its own whenever
the database changes or rvn is rebuilt, and deleting the directory is always safe.

### Reviewing Configuration Files

When a package ships a new version of a file it declared as `backup` and the
copy on disk has been edited, the install keeps yours and writes the package's
version beside it with a `.pacnew` suffix. `rvn config` is where those are
settled.

```bash
rvn config                       # the same as `rvn config list`
rvn config diff /etc/sudoers
rvn config merge /etc/sudoers    # $EDITOR, or vimdiff
rvn config accept /etc/pacman.conf
rvn config keep /etc/fstab
```

| Verb | Effect |
| --- | --- |
| `list` | Everything waiting, and how long it has waited |
| `diff` | What the package's version would change |
| `merge` | Opens both in `$EDITOR`, falling back to `vimdiff` |
| `accept` | Takes the package's version, saving yours as `.pacorig` |
| `keep` | Discards the package's version and keeps yours |

`diff`, `merge`, `accept` and `keep` take any number of paths and act on every
file waiting when given none. The three that write ask first and keep a backup
of whatever they overwrite — `.pacorig`, which is pacman's name for the same
thing, because an administrator who has met one before already knows what it is.

`accept` refuses outright on the files that carry live account state.
`/etc/passwd`, `/etc/group`, `/etc/shadow` and their neighbours cannot be
replaced by a package's copy, which knows nothing about the accounts on this
machine; taking one locks everybody out. The same list is refused during an
install, for the same reason.

The machine this was written on had thirty-nine `.pacnew` files waiting in
`/etc`, some of them years old, and its owner had never seen one. `list` reads
databases anybody may read; the verbs that write say so and name `sudo` when
they need it, rather than going through rvnd — an administrator deciding what
to do with their own `/etc` is not a package operation.

### The Package Cache

```bash
rvn cache                        # the same as `rvn cache status`
rvn cache clean                  # keep the two most recent versions of each
rvn cache clean --keep 0         # and even then the installed version stays
rvn cache clean --builds --dry-run
```

| Flag | Effect |
| --- | --- |
| `--keep <N>` | Versions of each package to keep (default 2) |
| `--builds` | Also delete AUR build trees: checkouts, edits, downloaded sources |
| `--dry-run` | Say what would go, delete nothing |

`status` is the default verb on purpose: the question that makes somebody type
`rvn cache` is "what is in there and why is it that big", and answering it
deletes nothing. `clean` is the verb that removes things and it is never
guessed at.

Two versions, not one, because one means the cache holds exactly what is
installed — enough to reinstall, nothing to go back to. The second is the
version that was running before the last upgrade, which is the one anybody asks
for after an upgrade breaks something, and it is the one `rvn rollback` reads.
The version that is currently installed is never deleted, whatever `--keep`
says.

Under `rvn --user` both verbs report on the prefix's own cache at
`$XDG_CACHE_HOME/rvn/pkg` rather than the system's. It fills up the same way and
the person who owns it can empty it without asking anyone.

### Going Back A Version

```bash
rvn rollback                     # what could be rolled back, and nothing else
rvn rollback mesa
rvn rollback mesa --dry-run
```

Bare, it reports. Named, it reinstalls the previous version of that one package
from the cache.

It is a downgrade, not an undo, and it says so before it does anything. rvn
keeps no copy of the bytes an upgrade overwrote — a file the payload replaced is
gone the moment it is written — so what a rollback can do is install an older
archive over the top. A package whose upgrade migrated a database or a
configuration format will not be un-migrated by this.

The archive it installed from is deliberately not swept afterwards, unlike an
ordinary transaction's downloads: it is the only copy of that version on the
machine, and deleting it would take the way back with it. Nothing is added to
the cache either, so `rvn cache`'s retention rules still decide when it goes.

`rvn rollback <pkg>` writes to the install root, so it goes through rvnd and is
audited like any other privileged operation, classified `repo` — the archive is
already on this machine and was signature-checked when it was downloaded, and it
can never come from the AUR. Bare `rvn rollback` does not: it reads two
world-readable databases, and putting an authorization prompt in front of a
question, holding the transaction lock to answer it, would be a worse
interface than the one it replaces.

### Transaction Hooks

The other kind of hook. A package's `.INSTALL` scriptlet is what a *package*
asks the system to do, one package at a time; a transaction hook is what this
*machine* wants run once around the transaction as a whole, and it is what
pacman means by the word.

It exists because of rollback. rvn cannot undo an install, so the only honest
answer is a snapshot taken before the first file is written — and taking one is
not the package manager's business. It depends on whether the machine is on
btrfs, or zfs, or neither, and on where the snapshots should live. So rvn does
not take a snapshot. It provides the moment.

A hook is one TOML file in either of

```
/usr/share/rvn/hooks.d/   shipped by a component
/etc/rvn/hooks.d/         written by this machine's administrator
```

read in file-name order across both. A file in `/etc` replaces a shipped file of
the same name, so a component's hook can be changed without editing a file the
next upgrade overwrites; an empty file replaces a shipped hook with nothing,
which is how one is switched off.

```toml
# /etc/rvn/hooks.d/50-snapshot.toml

[trigger]
when = "pre-transaction"
operations = ["install", "update", "remove"]
paths = ["etc/**", "usr/**"]

[run]
description = "snapshotting the root subvolume"
exec = "/usr/lib/rvn/snapshot"
args = ["--label", "before-rvn"]
abort_on_fail = true
```

| Key | Meaning |
| --- | --- |
| `trigger.when` | `pre-transaction` or `post-transaction` |
| `trigger.operations` | Any of `install`, `update`, `remove`; omitted means all three |
| `trigger.packages` | Package-name globs |
| `trigger.paths` | Globs against the files the transaction touches |
| `run.exec`, `run.args` | What to run; `exec` is required |
| `run.description` | What to say while it runs |
| `run.abort_on_fail` | Whether a failure stops the transaction |

A hook with neither `packages` nor `paths` fires on every transaction of the
operations it asked for, which is what a snapshot hook wants. Given both,
either one matching is enough: they are two ways of describing the same
interest, not two conditions to satisfy at once. A transaction is usually more
than one operation at once — an upgrade that pulls in a new dependency installs
*and* updates — and a hook fires if it asked for any of them, so one that only
cares about upgrades is not silently skipped the one time an upgrade also
brought something new.

Failure is deliberately asymmetric. A pre-transaction hook that fails with
`abort_on_fail` stops the transaction before a single file has been written,
which is a promise worth making: a snapshot that did not happen is an excellent
reason not to upgrade. A post-transaction hook that fails is a warning and
nothing more — by then the packages are on disk and registered, and reporting
the transaction as failed would be a lie the next `rvn update`, which would find
everything already installed, immediately contradicts. `abort_on_fail` on a
post-transaction hook is refused when the file is read, rather than ignored
during the upgrade it was meant to protect: there is nothing left to abort.

Hooks run as whatever rvn is, which for any transaction that touches `/` is
root. The environment is cleared and rebuilt with the same three variables rvnd
hands rvn, so a hook behaves identically whether the install came from a
terminal, through `sudo`, or from the desktop's package store over rvnd's
socket. What it needs to know it is told outright:

| Variable | Value |
| --- | --- |
| `RVN_HOOK_WHEN` | `pre-transaction` or `post-transaction` |
| `RVN_HOOK_OPERATIONS` | The operations this transaction is, space separated |
| `RVN_HOOK_ROOT` | The install root |

A hook file that does not parse stops the transaction rather than being skipped:
rvn does not start a transaction whose hooks it cannot read. `rvn --user` runs
none of this — these files are system policy, written expecting root and the
system's root directory, and a snapshot hook pointed at a per-user prefix would
not be the hook anybody wrote.

## Building Packages

`rvn build` turns a `package.toml` manifest into a package, and `rvn repo-add`
turns a directory of packages into a repository. Neither needs root, and `build`
must not be given any: it reads a manifest, stages files into a directory of its
own and writes an archive. Nothing is written outside `--outdir`.

```bash
rvn build packages/raven/huginn/package.toml --outdir build/packages
rvn repo-add build/packages --name raven
```

### `rvn build`

| Flag | Effect |
| --- | --- |
| `--outdir <DIR>` | Where the finished packages go (default: the working directory) |
| `--no-build` | Package a tree that is already built, rather than running `[build]` |
| `--srcdir <DIR>` | The built source tree the manifest's `src` paths are relative to |
| `--repo <NAME>` | Also rebuild `NAME.db` in the output directory |
| `--no-files` | Skip `NAME.files`, the database `pacman -F` reads |
| `--sign` | Sign, failing if no key is configured |
| `--key <KEY>` | A gpg key id, or the path to a secret key file; implies `--sign` |
| `--no-sign` | Do not sign, even though a key is configured |

Takes one or more manifests, or the directories holding them.

The output directory is the working directory rather than the package cache,
deliberately: a built package is output, not a cached download. Putting it in
`/var/cache/pacman/pkg` would need root for a command that otherwise needs none,
and would hand it to `rvn cache clean`, which would eventually delete the only
copy of something no mirror has.

`--no-build` and `--srcdir` are the pair an image build wants. RavenLinux's
scripts already compile every component with their own toolchain, so rvn
re-running the build would at best duplicate it and at worst use different
flags; with `--no-build` rvn reads the same `[install] files` table the scripts
read, stages exactly those files and produces an archive. `--srcdir` is the
checkout those `src` paths are relative to, which for a manifest living in
`packages/raven/<component>/` is somewhere else entirely. Without it the
manifest's own directory is used, and when that is wrong the failure names the
exact path that was not there rather than producing an empty package.

Under `--json`, a `built` event per package carries its path, version and sizes,
and a `repo_db` event carries the database, so a build script can collect them
without parsing terminal output.

### `rvn repo-add`

| Flag | Effect |
| --- | --- |
| `--name <NAME>` | What to call the repository (default: the directory's name) |
| `--no-files` | Skip `NAME.files` |
| `--sign`, `--key <KEY>`, `--no-sign` | As for `rvn build` |

Named after the tool it replaces, because somebody who has run a repository
before will look for exactly this word. It writes `NAME.db` and, unless told not
to, `NAME.files` — the file-list database `pacman -F` reads — in the same format
`repo-add` writes them, so pacman can use a repository rvn built and the other
way round. `--no-files` also deletes a stale `NAME.files` if one is there: a file
database describing packages the repository no longer carries is worse than
none.

### Serving It

A repository is a directory with a `.db` in it, and it does not need a web
server. Point `pacman.conf` at the disk:

```ini
[raven]
SigLevel = Optional TrustAll
Server = file:///srv/repos/raven
```

rvn reads `file://` through the filesystem rather than through HTTP, and
everything above that layer — mirror failover, resumable downloads, the rule
that decides whether a repository publishes a `.db.sig` — works the same way, so
a local repository behaves exactly like a remote one and can be listed as one
mirror among several.

One restriction worth knowing before it surprises you: a `file://` path
containing `..` is refused, in either half of the URL. rvn cannot tell the
`Server =` you wrote from the filename the database supplied, and the filename
is the untrusted half, so the check sits on the whole path. Write the resolved
path instead of `file:///srv/repos/../raven`.

### Signing

`etc/rvn/build.toml` names the key `build` and `repo-add` sign with. There is
nothing secret in that file: the key is named, not stored, and rvn never reads
private key material or writes it anywhere.

```toml
[sign]
key = "8A1B2C3D4E5F60718293A4B5C6D7E8F901234567"
```

A key identifier gpg already knows — a fingerprint, a long key id or an email
address — signs through `gpg-agent` on this machine, with whatever pinentry it is
set up with. That is the right form for a maintainer's workstation: the key stays
where it is and unlocking it stays gpg's problem. A path to an exported secret
key file is the CI form, for a runner handed a key and no keyring around it; rvn
imports it into a throwaway `GNUPGHOME` of its own, uses it for that one
signature and removes it, so signing never touches the keyring the person running
the command uses for anything else. A passphrase-protected key file is refused
rather than prompted for, because rvn would have to hold the passphrase to pass
it on, and holding it is the thing this arrangement avoids.

Whichever form is set, `rvn build` signs without being asked again: writing a key
down is saying that packages from this machine are signed. `--no-sign` overrides
it for one run, `--key` uses a different one, and a file that is present but does
not parse stops the build rather than quietly falling back to "do not sign".

The other half is the machine that installs the packages, which needs the
matching *public* key in its pacman keyring — rvn verifies against
`/etc/pacman.d/gnupg/pubring.gpg` as pacman does. A signature nobody can check is
not better than no signature; it is the same, with more steps.

## Machine-Readable Output

`--json` turns every line of interface output into a JSON event on stdout, one
object per line, and suppresses the painted stderr interface. This is how
[Raven Store](https://github.com/javanhut/RavenStore) drives rvn; anything else
that wants structured data can read the same stream.

```bash
rvn --json find ripgrep --limit 5      # {"event":"results","query":"ripgrep","results":[…],"total":16}
rvn --json list --explicit             # {"event":"installed","packages":[…]}
rvn --json info ripgrep                # {"event":"packages","packages":[…],"missing":[]}
rvn --json update --dry-run            # …{"event":"updates","candidates":[…],"download_size":…}
sudo rvn --json -y install ripgrep     # a live stream: stage, progress, plan, ok/warn/err, done
```

| Event | Fields | When |
| --- | --- | --- |
| `banner` | `version` | An operation starts |
| `stage` / `stage_done` | `message`; `ok`, `ms` | A spinner would start / settle |
| `progress` / `progress_done` | `label`, `done`, `total`, `unit`, `detail` | A progress bar would repaint / finish |
| `ok` `warn` `err` `info` `step` `detail` | `message` | A status line |
| `tree` | `items` | An indented list |
| `plan` | `install[]`, `replacing[]`, `download_size`, `installed_size_delta`, `build_from_source` | Install resolved a transaction |
| `updates` | `candidates[]`, `downgrades[]`, `download_size` | Update worked out what is out of date |
| `removal_plan` | `remove[]`, `orphaned[]`, `cascaded[]` | Uninstall planned a removal |
| `results` / `installed` / `packages` | package objects | `find` / `list` / `info` |
| `pacnew` | `count`, `files[]` | `rvn config list` found unmerged files |
| `pacnew_diff` | `path`, `package`, `diff` | `rvn config diff` |
| `pacnew_resolved` / `pacnew_refused` | `path`, `package`, `action`, `saved` / `reason` | `merge`, `accept` or `keep` settled one, or would not |
| `cache` | `total`, `count`, `repository`, `built`, `sources`, `partial`, `other`, `directories[]` | `rvn cache status` |
| `cache_clean` | `freed`, `archives`, `kept`, `rescued`, `partials`, `builds`, `trees`, `keep`, `failures[]` | `rvn cache clean` |
| `rollback_available` | `count`, `packages[]` | Bare `rvn rollback` |
| `rollback_plan` / `rollback_done` | `package`, `installed`, `rollback_to`, `archive`, `size` / `package`, `version` | `rvn rollback <pkg>` planned / finished |
| `built` | `package`, `version`, `arch`, `path`, `csize`, `isize`, `signed` | `rvn build` wrote a package |
| `repo_db` | `repo`, `database`, `files_database`, `packages`, `signed` | `rvn build --repo` or `rvn repo-add` wrote a database |
| `transaction_hook` | `hook`, `when`, `exec`, `ok`, `message` | A transaction hook ran |
| `build_tree_handover` | `path`, `from`, `to` | An AUR build tree was handed to the build account |
| `done` / `failed` | – / `message` | The command finished |

JSON mode is never interactive: prompts take their defaults, so pair it with
`-y` for anything that would otherwise ask. Raw output from `makepkg` and
scriptlets still goes to stderr, where a front-end can show it as a log.

Every event this crate emits is in that table, and a test keeps it that way
from the other end: it reads `src/**/*.rs`, collects every name passed to
`emit(`, and fails if one has been added without a decision about what the
terminal client does with it when it comes back over rvnd's socket.

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
