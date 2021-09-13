import argparse
import concurrent.futures
import os
import pefile
import tarfile
import threading
import zstandard

from contextlib import contextmanager
from urllib.request import urlopen

from pacdb import pacdb

_tls = threading.local()

PE_FILE_EXTENSIONS = frozenset((".dll", ".exe", ".pyd"))

@contextmanager
def open_zstd_supporting_tar(name, fileobj):
    # HACK: please, Python, support zst with :* in tarfile
    # could probably check for magic, but would have to have a stream wrapper
    # like tarfile already has to "put back" the magic bytes
    if name.endswith(".zst"):
        if not hasattr(_tls, 'zctx'):
            _tls.zctx = zstandard.ZstdDecompressor()
        with _tls.zctx.stream_reader(fileobj, closefd=False) as zstream:
            with tarfile.open(fileobj=zstream, mode="r|") as tar:
                yield tar
    else:
        with tarfile.open(fileobj=fileobj, mode="r|*") as tar:
            yield tar


class ProblematicImportSearcher(object):
    def __init__(self, problem_dlls, problem_symbols, local_mirror=None):
        super(ProblematicImportSearcher, self).__init__()
        self.problem_dlls = set(dll.encode('ascii').lower() for dll in problem_dlls)
        self.problem_symbols = set(sym.encode('ascii') for sym in problem_symbols)
        self.local_mirror = local_mirror

    def _open_package(self, pkg):
        if self.local_mirror:
            localfile = os.path.join(self.local_mirror, 'mingw', pkg.db.name, pkg.filename)
            return open(localfile, "rb")
        else:
            return urlopen("https://mirror.msys2.org/mingw/{}/{}".format(pkg.db.name, pkg.filename))

    def __call__(self, pkg):
        if not any(os.path.splitext(f)[-1] in PE_FILE_EXTENSIONS for f in pkg.files):
            return None
        with self._open_package(pkg) as pkgfile:
            with open_zstd_supporting_tar(pkg.filename, pkgfile) as tar:
                for entry in tar:
                    if not entry.isfile() or os.path.splitext(entry.name)[-1] not in PE_FILE_EXTENSIONS:
                        continue

                    with tar.extractfile(entry) as infofile:
                        data = infofile.read()

                    try:
                        pe = pefile.PE(data=data, fast_load=True)
                        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                    except pefile.PEFormatError:
                        continue
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        if entry.dll.lower() in self.problem_dlls:
                            if not self.problem_symbols:
                                return pkg
                            for imp in entry.imports:
                                if imp.name in self.problem_symbols:
                                    return pkg
        return None


parser = argparse.ArgumentParser(description='Search packages for problematic imports')
parser.add_argument('-e', '--repo', default='mingw64', help='pacman repo name to search')
parser.add_argument('-p', '--package', required=True, help='package from which to find dependents')
parser.add_argument('-d', '--dll', required=True, action='append', help='dll(s) from which problematic symbols are imported')
parser.add_argument('-l', '--local-mirror', help='root directory of local mirror')
parser.add_argument('symbol', nargs='*', help='problematic symbol(s)')

options = parser.parse_args()

package_handler = ProblematicImportSearcher(options.dll, options.symbol, options.local_mirror)

if options.local_mirror:
    repo = pacdb.Database(options.repo, filename=os.path.join(options.local_mirror, 'mingw', options.repo, '{}.files'.format(options.repo)))
else:
    repo = pacdb.mingw_db_by_name(options.repo, 'files')

with concurrent.futures.ThreadPoolExecutor(20) as executor:

    done={}
    todo=[options.package]

    # Check packages that immediately makedepend on the given package
    # https://github.com/jeremyd2019/package-grokker/issues/6
    for pkgname in repo.get_pkg(options.package).compute_rdepends('makedepends'):
        done[pkgname] = executor.submit(package_handler, repo.get_pkg(pkgname))

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
