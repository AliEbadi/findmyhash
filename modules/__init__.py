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

from model import Cracker
import utils

# #Credits to : https://mail.python.org/pipermail/tutor/2006-August/048596.html
# def delete_module(modname, paranoid=None):
#     from sys import modules
#     try:
#         thismod = modules[modname]
#     except KeyError:
#         raise ValueError(modname)
#     these_symbols = dir(thismod)
#     if paranoid:
#         try:
#             paranoid[:]  # sequence support
#         except:
#             raise ValueError('must supply a finite list for paranoid')
#         else:
#             these_symbols = paranoid[:]
#     del modules[modname]
#     for mod in modules.values():
#         try:
#             delattr(mod, modname)
#         except AttributeError:
#             pass
#         if paranoid:
#             for symbol in these_symbols:
#                 if symbol[:2] == '__':  # ignore special symbols
#                     continue
#                 try:
#                     delattr(mod, symbol)
#                 except AttributeError:
#                     pass

#Probably not the best way to do it, but works for now
dirname = os.path.basename(os.path.normpath(dirpath))

for mname in filter(lambda x: x.endswith(".py"), os.listdir(dirpath)):
    mname = ".%s" % (mname[:-3],)
    module = importlib.import_module(mname, dirname)

    #has_child = False
    # for cls in inspect.getmembers(module, predicate=inspect.isclass):
    #     try:
    #         if cls[1].__base__ == Cracker:
    #             has_child = True
    #             break
    #     except TypeError:
    #         pass

    # if has_child is False:
    #     delete_module(module.__name__)
