# vt-kvd

<!-- MarkdownTOC -->

- [About](#about)
- [Installing](#installing)
    - [From PyPI](#from-pypi)
    - [From sources](#from-sources)
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
- [vt-py](https://github.com/VirusTotal/vt-py) - VirusTotal API library

### Resources

- [JetBrains Mono](https://www.jetbrains.com/lp/mono/) font
