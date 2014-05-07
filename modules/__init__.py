import inspect
import os
import os.path
import importlib

import sys

dirpath = os.path.dirname(
    os.path.abspath(
        inspect.getfile(
            inspect.currentframe()
        )
    )
)

sys.path.append(dirpath)

import utils
from algos import *

from model import Cracker

#Probably not the best way to do it, but works for now
dirname = os.path.basename(os.path.normpath(dirpath))

SUPPORTED_ALGORITHMS = set()

for mname in filter(lambda x: x.endswith(".py"), os.listdir(dirpath)):
    mname = ".%s" % (mname[:-3],)
    module = importlib.import_module(mname, dirname)

    for cls in inspect.getmembers(module, predicate=inspect.isclass):
        try:
            if issubclass(cls[1], Cracker) and hasattr(cls[1], "ALGORITHMS"):
                SUPPORTED_ALGORITHMS.update(set(cls[1].ALGORITHMS))
        except TypeError:
            pass
