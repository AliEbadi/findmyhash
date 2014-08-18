#!/usr/bin/env python

from distutils.core import setup
import os
import os.path

rdir = os.path.split(os.path.realpath(__file__))[0]

modules = []

for root, dirs, files in os.walk(rdir):
    if '/.' in root:
        continue
    files = [os.path.relpath(os.path.join(root, s[:len(s) - 3]), rdir) for s in files if s.endswith(".py")]
    modules = modules + files


print(modules)

setup(
    name="libfindmyhash",
    version="1.1.3",
    description="Online hash finder",
    url="https://github.com/Talanor/findmyhash",
    maintainer="Quentin POIRIER",
    maintainer_email="quentin.poirier@epitech.eu",
    py_modules=modules
)
