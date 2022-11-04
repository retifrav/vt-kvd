# vt-kvd

<!-- MarkdownTOC -->

- [About](#about)
- [Installing](#installing)
    - [From PyPI](#from-pypi)
    - [From sources](#from-sources)
- [Configuration](#configuration)
- [Running](#running)
- [Platforms](#platforms)
- [3rd-party](#3rd-party)
    - [Requirements](#requirements)
    - [Resources](#resources)

<!-- /MarkdownTOC -->

## About

A VirusTotal GUI client.

## Installing

### From PyPI

``` sh
$ pip install ?
```

### From sources

``` sh
$ cd /path/to/repository/
$ pip install ./
```

or:

``` sh
$ cd /path/to/repository/
$ python -m build
$ pip install ./dist/vt_kvd-0.1.0-py3-none-any.whl
```

## Configuration

Config file `~/.config/vt-kvd/config.toml`:

``` toml
[API]
key = "YOUR-VIRUSTOTAL-API-KEY"
```

If the main config file is missing, it will try to fallback to [vt-cli](https://github.com/VirusTotal/vt-cli)'s config at `~/.vt.toml`:

``` toml
apikey="YOUR-VIRUSTOTAL-API-KEY"
```

## Running

``` sh
$ vt-kvd --help
```

## Platforms

Tested on:

- Mac OS:
    + ?, Intel
    + ?, Apple silicon
- Windows:
    + ?
- GNU/Linux:
    + ?

## 3rd-party

### Requirements

- Python 3.8 or later
- [Dear PyGui](https://pypi.org/project/dearpygui/) - application window and UI controls
- [pandas](https://pypi.org/project/pandas/) - processing results
- [vt-py](https://github.com/VirusTotal/vt-py) - VirusTotal API library

### Resources

- [JetBrains Mono](https://www.jetbrains.com/lp/mono/) font
