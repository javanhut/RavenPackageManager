# Raven Package Manager

Raven Package Manager or rvn is a package manager built in Rust as the default package manager for Raven Linux.

## Architecture

Since Raven Linux is Built on top of Arch Linux the package manager will be a derivation of PacMan and Yay. A custom installaltion package it should be compatible with Arch Architecture for x86_64 and arm. With x86_64 being the default support.

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

### Update Package

```bash
rvn update go
```

### Update Package(s)

```bash
rvn update go rust
```

### Update Package Manager

```bash
rvn-update
```
