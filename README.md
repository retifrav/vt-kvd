# vt-kvd

<!-- MarkdownTOC -->

- [About](#about)
- [Installing](#installing)
    - [vt-kvd itself](#vt-kvd-itself)
        - [From PyPI](#from-pypi)
        - [From sources](#from-sources)
    - [Dependencies](#dependencies)
        - [libmagic](#libmagic)
- [Configuration](#configuration)
- [Running](#running)
    - [Scanning directories](#scanning-directories)
- [Platforms](#platforms)
- [3rd-party](#3rd-party)
    - [Requirements](#requirements)
    - [Resources](#resources)

<!-- /MarkdownTOC -->

## About

A VirusTotal GUI client.

## Installing

### vt-kvd itself

#### From PyPI

``` sh
$ pip install ?
```

#### From sources

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

### Dependencies

#### libmagic

All the dependencies are automatically installed with `pip`. But `python-magic` Python module [expects](https://github.com/ahupp/python-magic#installation) `libmagic` to be present in the system. So if you will be [scanning directories](#scanning-directories) instead of individual files, then you will need to install this library using your system package manager:

- Mac OS (*Homebrew*): `brew install libmagic`
- GNU/Linux (*APT*): `sudo apt install libmagic1`
- Windows: well, the easiest probably would be to use [alternative package](https://pypi.org/project/python-magic-bin/) instead of `python-magic`, because that one bundles required `libmagic` binary. Or perhaps you could try to build it from [sources](https://github.com/julian-r/file-windows)

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

### Scanning directories

It is possible to check not a single file but a directory. In that case in order to skip the files that are of no interest the application will scan the directory for suitable files by guessing their types based on [magic numbers](https://en.wikipedia.org/wiki/List_of_file_signatures). This is not an absolutely reliable way, so it is recommended that you check the files of interest individually by explicitly providing their full paths one by one.

Another thing to consider is that VirusTotal API has a quota for [standard free public accounts](https://www.virustotal.com/gui/my-apikey), and you can quickly exceed that quota by scanning directories instead of individual files.

Scanning directories is disabled by default. If you would like to enable it, launch the application with `--enable-dir-scan`. That will also require you to have [libmagic](#libmagic) binary installed in the system.

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
- [python-magic](https://github.com/ahupp/python-magic) - finding executables and libraries
- [vt-py](https://github.com/VirusTotal/vt-py) - VirusTotal API library

### Resources

- [JetBrains Mono](https://www.jetbrains.com/lp/mono/) font
