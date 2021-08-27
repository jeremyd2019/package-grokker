import argparse
import pefile
import subprocess
import sys
import os
import concurrent.futures
import tempfile
import pacdb
from urllib.request import urlretrieve

class ProblematicImportSearcher(object):
    def __init__(self, problem_dll, problem_symbols, temp_dir=None):
        super(ProblematicImportSearcher, self).__init__()
        self.problem_dll = problem_dll.encode('ascii').lower()
        self.problem_symbols = set(sym.encode('ascii') for sym in problem_symbols)
        self.temp_dir = temp_dir

    def __call__(self, pkg):
        with tempfile.TemporaryDirectory(dir=self.temp_dir) as tmpdir:
            localfile = os.path.join(tmpdir, pkg.filename)
            urlretrieve("https://mirror.msys2.org/mingw/{}/{}".format(pkg.db.name, pkg.filename), localfile)
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
                        if entry.dll.lower() == self.problem_dll:
                            if not self.problem_symbols:
                                return pkg
                            for imp in entry.imports:
                                if imp.name in self.problem_symbols:
                                    return pkg
        return None

parser = argparse.ArgumentParser(description='Search packages for problematic imports')
parser.add_argument('-e', '--repo', default='mingw64', help='pacman repo name to search')
parser.add_argument('-p', '--package', required=True, help='package from which to find dependents')
parser.add_argument('-d', '--dll', required=True, help='dll from which problematic symbols are imported')
parser.add_argument('-t', '--tempdir', help='directory for temporary files')
parser.add_argument('symbol', nargs='*', help='problematic symbol(s)')

options = parser.parse_args()

package_handler = ProblematicImportSearcher(options.dll, options.symbol, options.tempdir)

repo = pacdb.mingw_db_by_name(options.repo)

with concurrent.futures.ThreadPoolExecutor(20) as executor:

    done={}
    todo=[options.package]

    while todo:
        more=[]
        for pkgname in todo:
            pkg = repo.get_pkg(pkgname)
            more.extend(rdep for rdep in pkg.compute_requiredby() if rdep not in done)
            done[pkgname] = executor.submit(package_handler, pkg)
        todo = more

    for future in concurrent.futures.as_completed(done.values()):
        result = future.result()
        if result is not None:
            print(result.base)
