import argparse
import itertools
import os
import pprint
import sys

from contextlib import contextmanager
from pathlib import Path

import pacdb
import grokkermod

@contextmanager
def gha_group(title):
    print(f'\n::group::{title}')
    try:
        yield
    finally:
        print('::endgroup::')

# hack pprint
del pprint.PrettyPrinter._dispatch[bytes.__repr__]

parser = argparse.ArgumentParser(description='Search packages for problematic imports')
parser.add_argument('-e', '--repo', default='mingw64', help='pacman repo name to search')
parser.add_argument('-l', '--local-mirror', help='root directory of local mirror')
parser.add_argument('-v', '--verbose', action='count', help='output additional information')
subparser = parser.add_subparsers(title="subcommands", dest="cmd", required=True)
sub = subparser.add_parser("compare_urls", help="Compare two versions from 2 URLs")
sub.add_argument('-p', '--package', required=True, help='package from which to find dependents')
sub.add_argument('url', nargs=2, help='url to old and new packages')
sub = subparser.add_parser("artifact_dir", help="Check a directory full of updated packages against versions in the repo")
sub.add_argument('dir', type=Path, help='path to artifact directory')

options = parser.parse_args()

if options.cmd is None:
    parser.print_help()
    parser.exit()

local_mirror = None
if options.local_mirror:
    if options.repo == 'msys':
        local_mirror = os.path.join(os.path.abspath(options.local_mirror), options.repo, 'x86_64')
    else:
        local_mirror = os.path.join(os.path.abspath(options.local_mirror), 'mingw', options.repo)

    repo = pacdb.Database(options.repo, filename=os.path.join(local_mirror, '{}.files'.format(options.repo)))
elif options.repo == 'msys':
    repo = pacdb.msys_db_by_arch('x86_64', 'files')
else:
    repo = pacdb.mingw_db_by_name(options.repo, 'files')

artifacts = None
if options.cmd == "compare_urls":
    packages = [options.package]
    for (i, url) in zip(itertools.count(), options.url):
        if url == '@PKG@':
            pkg = repo.get_pkg(options.package)
            if pkg is None:
                print("WARNING: package does not exist in sync db: {}, skipping".format(options.package), file=sys.stderr)
                exit(0)

            if local_mirror:
                options.url[i] = Path(os.path.join(local_mirror, pkg.filename)).as_uri()
            else:
                options.url[i] = "{}/{}".format(pkg.db.url, pkg.filename)

    problem_dll_symbols = grokkermod.diff_package_exports(*options.url)
elif options.cmd == "artifact_dir":
    if not options.dir.is_dir():
        parser.error("dir does not exist or is not a directory")
    packages = []
    artifacts = {}
    problem_dll_symbols = {}
    for f in options.dir.glob('*.pkg.tar.*'):
        pkgname = f.name.rsplit("-", 3)[0]
        pkg = repo.get_pkg(f.name.rsplit("-", 3)[0])
        if pkg is None:
            print("WARNING: package does not exist in sync db: {}, skipping".format(pkgname), file=sys.stderr)
            continue
        packages.append(pkgname)
        artifacts[pkgname] = f

        if local_mirror:
            old_url = Path(os.path.join(local_mirror, pkg.filename)).as_uri()
        else:
            old_url = "{}/{}".format(pkg.db.url, pkg.filename)

        new_url = Path(os.path.abspath(f)).as_uri()
        for dll, exports in grokkermod.diff_package_exports(old_url, new_url).items():
            problem_dll_symbols.setdefault(dll, set()).update(exports)

if options.verbose:
    with gha_group('Removed DLLs/Symbols'):
        pprint.pprint(problem_dll_symbols)

if problem_dll_symbols:
    package_handler = grokkermod.ProblematicImportSearcher(problem_dll_symbols, local_mirror, artifacts)

    seen = set()
    for pkgbase in grokkermod.grok_dependency_tree(repo, packages, package_handler):
        if pkgbase not in seen:
            print(pkgbase)
            seen.add(pkgbase)
