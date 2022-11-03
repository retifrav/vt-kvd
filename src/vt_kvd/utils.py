import hashlib
import pathlib
import configparser
from typing import Optional


def sha1sum(pathToFile: pathlib.Path) -> str:
    h = hashlib.sha1()
    b = bytearray(128*1024)
    mv = memoryview(b)
    with open(pathToFile, "rb", buffering=0) as f:
        while n := f.readinto(mv):  # requires Python 3.8 or newer for :=
            h.update(mv[:n])
    return h.hexdigest()


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
