import pefile
import subprocess
import sys
import os
import concurrent.futures
import tempfile
import pycman.config
import pyalpm
from urllib.request import urlretrieve

CHECK_REPO="mingw64"
PROBLEM_PACKAGE="mingw-w64-x86_64-harfbuzz"
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
    alpm_handle = pycman.config.init_with_config('/etc/pacman.conf')
    repo = [db for db in alpm_handle.get_syncdbs() if db.name == CHECK_REPO][0]

    done={}
    todo=[PROBLEM_PACKAGE]

    while todo:
        more=[]
        for pkgname in todo:
            pkg = mingw64.get_pkg(pkgname)
            more.extend(rdep for rdep in pkg.compute_requiredby() if rdep not in done)
            done[pkgname] = executor.submit(process_package, pkg.filename)
        todo = more

    for future in concurrent.futures.as_completed(done.values()):
        result = future.result()
        if result is not None:
            print(result)
