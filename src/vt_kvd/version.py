import platform
from typing import Tuple
from datetime import datetime

__version_info__: Tuple[int, int, int] = (0, 4, 0)
__version__: str = ".".join(map(str, __version_info__))
__platform__: str = platform.platform()

__copyright__: str = f"Copyright (C) 2022-{datetime.now().year} Declaration of VAR"
