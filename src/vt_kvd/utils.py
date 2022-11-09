# standard libraries
import sys
import traceback
import json
import hashlib
import pathlib
import configparser
from typing import Optional, List, Dict
# dependencies
try:  # from python-magic loader module, needed to modify lookup procedure
    from ctypes.util import find_library
    import ctypes
    # import site
    import sysconfig

    def magic_candidates():
        yield find_library("magic")
        if sys.platform == "win32":  # might need other platforms too
            # if user has python-magic-bin, then libmagic should be
            # in one of the site-packages
            sysPaths = sysconfig.get_paths()  # site.getsitepackages()
            sitePackages = [
                sysPaths["purelib"],
                sysPaths["platlib"]
            ]
            for p in sitePackages:
                dirCandidate = pathlib.Path(p) / "magic" / "libmagic"
                if dirCandidate.is_dir():
                    yield dirCandidate / "libmagic.dll"
            # excluded "msys-magic-1", because it can be picked up
            # from /path/to/git/usr/bin/msys-magic-1.dll and fail
            for i in ["libmagic", "magic1", "cygmagic-1", "libmagic-1"]:
                yield "./%s.dll" % (i,)
                yield find_library(i)

    foundMagic = False
    for lib in magic_candidates():
        if lib is None:
            continue
        # try:
        #     ctypes.CDLL(lib)
        #     foundMagic = True
        # except OSError:
        #     pass
        if pathlib.Path(lib).is_file():
            # print(f"Found the following libmagic binary: {lib}")
            foundMagic = True
            break
    if not foundMagic:
        raise ImportError("Failed to find libmagic")
    else:
        import magic
except Exception as ex:
    print(
        " ".join((
            "[WARNING] Could not import magic module, you probably",
            "don't have libmagic binary installed in your system. Trying",
            "to use directories scanning functionality will likely",
            f"result in error. {ex}"
        ))
    )
    # traceback.print_exc(file=sys.stderr)

mimeTypesToCheck: List[str] = [
    "application/x-archive",  # [ Windows | *.lib], [ Linux | *.a ]
    "application/x-dosexec",  # [ Windows | *.exe, *.dll ]
    "application/x-mach-binary",  # [ Mac OS | executables, *.a ]
    "application/x-sharedlib"  # [ Linux | executables, *.so ]
]


def getVirusTotalAPIkeyFromConfig() -> Optional[str]:
    vtAPIkey = None
    vtConfig = pathlib.Path.home() / ".config/vt-kvd/config.toml"
    # try to fallback to vt-cli config
    fromVTcliConfig = False
    if not vtConfig.is_file():
        vtConfig = pathlib.Path.home() / ".vt.toml"
        fromVTcliConfig = True
    # now we try to read whichever of the configs
    if vtConfig.is_file():
        config = configparser.ConfigParser()
        try:
            if fromVTcliConfig:
                vtConfigContent = None
                # configparser requires TOML files to have sections
                with open(vtConfig, "r") as f:
                    vtConfigContent = f"[default]\n{f.read()}"
                config.read_string(vtConfigContent)
                vtAPIkey = config["default"]["apikey"]
            else:
                config.read(vtConfig)
                vtAPIkey = config["API"]["key"]
        except Exception as ex:
            print(
                " ".join((
                    "[ERROR] Couldn't read VirusTotal API key",
                    f"from either of the known configs. {ex}"
                )),
                file=sys.stderr
            )
            traceback.print_exc(file=sys.stderr)
    # yeah, the awesome configparser doesn't know about quotes
    # for string values in TOML
    if vtAPIkey is not None:
        vtAPIkey = vtAPIkey.strip("\"")
    return vtAPIkey


def calculateSHAchecksum(
    pathToFile: pathlib.Path,
    shaType: str = "sha1"
) -> str:
    h = None
    if shaType == "sha1":
        h = hashlib.sha1()
    elif shaType == "sha256":
        h = hashlib.sha256()
    else:
        raise Exception(f"Unknown SHA type provided: {shaType}")
    b = bytearray(128*1024)
    mv = memoryview(b)
    with open(pathToFile, "rb", buffering=0) as f:
        # requires Python 3.8 or newer for := assignment in while loop
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def findFilesToCheck(
    pathToDirectory: pathlib.Path,
    printFilesListing: bool = False
) -> List[pathlib.Path]:
    filesToCheck: List[pathlib.Path] = []
    if printFilesListing:
        print(f"\n[DEBUG] All files in {pathToDirectory.as_posix()}:")
    for p in pathToDirectory.rglob("*"):
        if p.is_file() and not p.is_symlink():
            if printFilesListing:
                # print(p)
                print(
                    "-",
                    p.name,
                    "|",
                    magic.from_buffer(
                        open(p, "rb").read(2048),
                        mime=True
                    )
                )
            if magic.from_buffer(
                open(p, "rb").read(2048),
                mime=True
            ) in mimeTypesToCheck:
                filesToCheck.append(p)
    return filesToCheck


def estimateDangerLevel(analStats: Dict[str, int]) -> int:
    if analStats["malicious"] != 0:
        return 2
    elif analStats["suspicious"] != 0:
        return 1
    else:
        return 0
