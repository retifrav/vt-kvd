# dependencies
import magic
# standard libraries
import sys
import traceback
import json
import hashlib
import pathlib
import configparser
#
from typing import Optional, List

mimeTypesToCheck: List[str] = [
    # "application/x-archive",  # Windows | *.lib
    "application/x-dosexec",  # Windows | *.exe, *.dll
    "application/x-mach-binary"  # Mac OS | executables, *.a
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


def sha1sum(pathToFile: pathlib.Path) -> str:
    h = hashlib.sha1()
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


def parseAnalStats(analStats: str) -> str:
    stats = json.loads(analStats.replace("'", "\""))
    # print(json.dumps(stats, indent=4))
    return "/".join((
        str(stats["harmless"]),
        str(stats["type-unsupported"]),
        str(stats["suspicious"]),
        str(stats["failure"]),
        str(stats["malicious"]),
        str(stats["undetected"])
    ))
