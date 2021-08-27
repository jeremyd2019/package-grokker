import pefile
import subprocess
import sys
import os
import concurrent.futures
import io
import fileinput
import tempfile
from urllib.request import urlretrieve

PROBLEM_DLL=b"libharfbuzz-0.dll"
PROBLEM_SYMBOLS=set((b'_ZdaPv', b'_ZdlPv', b'_Znay', b'_Znwy', b'_Znaj', b'_Znwj'))

def process_package(pkgfile):
    with tempfile.TemporaryDirectory(dir="/c/_") as tmpdir:
        localfile = os.path.join(tmpdir, pkgfile)
        urlretrieve("https://mirror.msys2.org/mingw/mingw64/{}".format(pkgfile), localfile)
        subprocess.call(['bsdtar', '-C', tmpdir, '-xf', localfile], stderr=subprocess.DEVNULL)
        for root, dirs, files in os.walk(tmpdir):
            for name in files:
                p = os.path.normpath(os.path.join(root, name))
                if os.path.splitext(p)[-1] not in (".dll", ".exe", ".pyd"):
                    continue
                try:
                    pe = pefile.PE(p, fast_load=True)
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                except pefile.PEFormatError:
                    continue
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll.lower() == PROBLEM_DLL:
                        for imp in entry.imports:
                            if imp.name in PROBLEM_SYMBOLS:
                                return pkgfile
    return None



with concurrent.futures.ThreadPoolExecutor(20) as executor:
    futures = []
    for pkgfile in fileinput.input():
        pkgfile = pkgfile.rstrip()
        futures.append(executor.submit(process_package, pkgfile))

    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result is not None:
            print(result)
