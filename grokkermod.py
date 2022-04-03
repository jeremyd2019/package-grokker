import concurrent.futures
import os
import pefile
import tarfile
import threading
import zstandard

from contextlib import contextmanager, closing
from urllib.request import urlopen

_tls = threading.local()

PE_FILE_EXTENSIONS = frozenset((".dll", ".exe", ".pyd"))


@contextmanager
def open_zstd_supporting_tar(name, fileobj):
    # HACK: please, Python, support zst with |* in tarfile
    # could probably check for magic, but would have to have a stream wrapper
    # like tarfile already has to "put back" the magic bytes
    if name.endswith(".zst"):
        if not hasattr(_tls, 'zdctx'):
            _tls.zdctx = zstandard.ZstdDecompressor()
        with _tls.zdctx.stream_reader(fileobj, closefd=False) as zstream, \
             tarfile.open(fileobj=zstream, mode="r|") as tar:
            yield tar
    else:
        with tarfile.open(fileobj=fileobj, mode="r|*") as tar:
            yield tar


class ProblematicImportSearcher(object):
    def __init__(self, problem_dll_symbols, local_mirror=None, artifacts=None):
        super(ProblematicImportSearcher, self).__init__()
        self.problem_dlls = problem_dll_symbols
        self.local_mirror = local_mirror
        self.artifacts = artifacts

    def _open_package(self, pkg):
        if self.artifacts and pkg.name in self.artifacts:
            return open(self.artifacts[pkg.name], "rb")
        if self.local_mirror:
            localfile = os.path.join(self.local_mirror, pkg.filename)
            return open(localfile, "rb")
        else:
            return urlopen("{}/{}".format(pkg.db.url, pkg.filename))

    def __call__(self, pkg):
        if not any(os.path.splitext(f)[-1] in PE_FILE_EXTENSIONS for f in pkg.files):
            return None
        with self._open_package(pkg) as pkgfile, \
             open_zstd_supporting_tar(pkg.filename, pkgfile) as tar:
            for entry in tar:
                if not entry.isreg() or os.path.splitext(entry.name)[-1] not in PE_FILE_EXTENSIONS:
                    continue

                try:
                    with tar.extractfile(entry) as infofile, \
                         closing(pefile.PE(data=infofile.read(), fast_load=True)) as pe:
                        pe.parse_data_directories(directories=[
                            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
                        ])
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            problem_symbols = self.problem_dlls.get(entry.dll.lower(), None)
                            if problem_symbols is not None:
                                if not problem_symbols:
                                    return pkg
                                for imp in entry.imports:
                                    if imp.name in problem_symbols:
                                        return pkg
                except pefile.PEFormatError:
                    continue
        return None


def grok_dependency_tree(repo, package, package_handler):
    with concurrent.futures.ThreadPoolExecutor(20) as executor:
        makedepend={}
        done={}
        if isinstance(package, str):
            todo=set((package,))
        else:
            todo=set(package)

        # Check packages that immediately makedepend on the given package
        # https://github.com/jeremyd2019/package-grokker/issues/6
        for pkgname in todo:
            for rdep in repo.get_pkg(pkgname).compute_rdepends('makedepends'):
                if rdep not in makedepend:
                    makedepend[rdep] = executor.submit(package_handler, repo.get_pkg(rdep))

        while todo:
            more=set()
            for pkgname in todo:
                pkg = repo.get_pkg(pkgname)
                more.update(rdep for rdep in pkg.compute_requiredby() if rdep not in done and rdep not in todo)
                if pkgname in makedepend:
                    done[pkgname] = makedepend[pkgname]
                    del makedepend[pkgname]
                else:
                    done[pkgname] = executor.submit(package_handler, pkg)
            todo = more

        del repo

        futures = set(done.values())
        futures.update(makedepend.values())
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                yield result.base

def exports_for_package(name, fileobj):
    package_exports = {}
    with open_zstd_supporting_tar(name, fileobj) as tar:
        for entry in tar:
            if not entry.isreg() or os.path.splitext(entry.name)[-1] not in PE_FILE_EXTENSIONS:
                continue

            try:
                with tar.extractfile(entry) as infofile, \
                     closing(pefile.PE(data=infofile.read(), fast_load=True)) as pe:
                    pe.parse_data_directories(directories=[
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
                    ])

                    # assume we don't need to worry about ordinal-only exports
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        package_exports[entry.name] = set(exp.name for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols)
                    else:
                        package_exports[entry.name] = set()
            except pefile.PEFormatError:
                continue
    return package_exports

def diff_package_exports(url1, url2):
    with urlopen(url1) as fileobj:
        exports1 = exports_for_package(os.path.basename(url1), fileobj)

    with urlopen(url2) as fileobj:
        exports2 = exports_for_package(os.path.basename(url2), fileobj)

    problem_dll_symbols = {}
    for dll, exports in exports1.items():
        if dll not in exports2:
            problem_dll_symbols[os.path.basename(dll).encode('ascii').lower()] = set()
        else:
            removed = exports - exports2[dll]
            if removed:
                problem_dll_symbols[os.path.basename(dll).encode('ascii').lower()] = removed
    return problem_dll_symbols

