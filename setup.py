# setup.py
from distutils.core import setup
import py2exe

includes = [
    "encodings",
    "encodings.*",
    "lxml._elementpath"
    ]

options = {
    "py2exe":
    {
    "compressed": 1,
    "optimize": 2,
    "includes": includes,
    }
    }

target = { "script" : "src/trelby.py",
           "icon_resources": [(1, "icon32.ico")],
           }

setup(options = options, zipfile="wxc2.pyd", windows=[target])
