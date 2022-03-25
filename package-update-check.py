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
parser.add_argument('-p', '--package', required=True, help='package from which to find dependents')
parser.add_argument('-l', '--local-mirror', help='root directory of local mirror')
parser.add_argument('url', nargs=2, help='url to old and new packages')

options = parser.parse_args()

local_mirror = None
if options.local_mirror:
    if options.repo == 'msys':
        local_mirror = os.path.join(options.local_mirror, options.repo, 'x86_64')
    else:
        local_mirror = os.path.join(options.local_mirror, 'mingw', options.repo)

    repo = pacdb.Database(options.repo, filename=os.path.join(local_mirror, '{}.files'.format(options.repo)))
elif options.repo == 'msys':
    repo = pacdb.msys_db_by_arch('x86_64', 'files')
else:
    repo = pacdb.mingw_db_by_name(options.repo, 'files')

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
with gha_group('Removed DLLs/Symbols'):
    pprint.pprint(problem_dll_symbols)

if problem_dll_symbols:
    package_handler = grokkermod.ProblematicImportSearcher(problem_dll_symbols, local_mirror)

    for pkgbase in grokkermod.grok_dependency_tree(repo, options.package, package_handler):
        print(pkgbase)
