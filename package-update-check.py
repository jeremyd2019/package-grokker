import argparse
import os

from pacdb import pacdb
import grokkermod

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

package_handler = grokkermod.ProblematicImportSearcher(grokkermod.diff_package_exports(*options.url), local_mirror)

for pkgbase in grokkermod.grok_dependency_tree(repo, options.package, package_handler):
    print(pkgbase)