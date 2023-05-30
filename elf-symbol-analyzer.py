#!/bin/env python3
"""ELF symbol analyzer script. Processes individual ELF files and / or entire directories. Searches directories
recursively for all ELF files. Collects all exported and imported symbols of all ELF files and stores the information in
a relational database.
"""
from pathlib import Path
import argparse
import logging
import magic
import sqlite3
import subprocess


def main():
    args = parse_args()
    try:
        cxxfilt = start_cxxfilt()
    except FileNotFoundError:
        logging.error('Could not start c++filt process. Please install c++filt first.')
        return
    create_new_database(args.database)
    elves = collect_elves(args)
    if not elves:
        logging.warning('No ELF files found.')
        return
    elves = analyze_elves(elves)
    symbols = enumerate_symbols(cxxfilt, elves)
    fill_database(args.database, elves, symbols)


def parse_args():
    """Parses command line arguments and performs sanity checks."""
    def dir_or_elf_file(string):
        """Returns the Path object of the specified path, if it belongs to a directory or an ELF file."""
        path = Path(string).resolve(strict=True)
        if path.is_dir() or is_dynamic_elf(path):
            return path
        raise argparse.ArgumentTypeError(f'"{string}" is neither a directory nor a dynamically linked ELF file')

    parser = argparse.ArgumentParser(description='Stores symbol usage information in a relational database.',
                                     epilog='Hint: Use the SQL views provided by the result database.')
    in_group = parser.add_argument_group('input')
    in_group.add_argument('paths', metavar='PATH', nargs='+', type=dir_or_elf_file, help='''List of individual ELF files
                          and / or directories that will be recursively searched for ELF files.''')
    out_group = parser.add_argument_group('result database (SQLite)')
    out_group.add_argument('-o', '--database', type=Path, required=True, help='''Database file. Will not be overwritten
                           unless --force is used.''')
    out_group.add_argument('-f', '--force', action='store_true', help='''Overwrite the specified --database file, if it
                           already exists.''')
    args = parser.parse_args()
    args.database = args.database.resolve()
    if args.database.exists():
        if not args.database.is_file():
            raise argparse.ArgumentTypeError(f'database path "{args.database}" exists, but is not a file')
        if not args.force:
            raise argparse.ArgumentTypeError(f'specify --force to overwrite "{args.database}", or use another path')
    return args


def is_dynamic_elf(file):
    """Returns True if the specified Path object belongs to a file that identifies as a dynamically linked ELF file."""
    try:
        if file.is_file():
            magic_string = magic.from_file(file)
            return magic_string.startswith('ELF ') and 'dynamically linked' in magic_string
    except PermissionError:
        logging.warning(f'No permission to read {file}')
    return False


def start_cxxfilt():
    """Returns a c++filt process that continuously reads mangled symbol names via stdin and prints their demangled
    equivalents to stdout. This approach yields significantly better performance than calling subprocess.run() for each
    individual symbol. Note that there are various pip packages that offer C++ symbol demangling. However, in the
    author's experience they provide worse results than the c++filt binary.
    """
    return subprocess.Popen(['c++filt'], bufsize=1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def demangle(cxxfilt_process, symbol):
    """Uses a started c++filt process to demangle a symbol."""
    cxxfilt_process.stdin.write(symbol+'\n')
    return cxxfilt_process.stdout.readline().rstrip()


def create_new_database(db_path):
    """Overwrites any existing file at the specified path with a new SQLite database."""
    db_path.unlink(missing_ok=True)
    db_connection = sqlite3.connect(db_path)
    db = db_connection.cursor()
    db.execute('CREATE TABLE "elf" ("id" INTEGER PRIMARY KEY, "absolute_path" UNIQUE, "relative_path")')
    db.execute('CREATE TABLE "symbol" ("id" INTEGER PRIMARY KEY, "name" UNIQUE, "demangled")')
    db.execute('''CREATE TABLE "export" ("elf", "symbol", "address",
                  FOREIGN KEY ("elf")    REFERENCES "elf"    ("id") ON DELETE CASCADE,
                  FOREIGN KEY ("symbol") REFERENCES "symbol" ("id") ON DELETE CASCADE)''')
    db.execute('''CREATE TABLE "import" ("elf", "symbol",
                  FOREIGN KEY ("elf")    REFERENCES "elf"    ("id") ON DELETE CASCADE,
                  FOREIGN KEY ("symbol") REFERENCES "symbol" ("id") ON DELETE CASCADE)''')
    db.execute('''CREATE TABLE "dependency" ("elf", "dependency",
                  FOREIGN KEY ("elf") REFERENCES "elf" ("id") ON DELETE CASCADE)''')
    db.execute('''CREATE VIEW "dependencies" AS SELECT "elf"."relative_path"     AS "ELF",
                                                       "dependency"."dependency" AS "dependency"
                  FROM "elf" LEFT JOIN "dependency" ON "dependency"."elf" = "elf"."id"''')
    db.execute('''CREATE VIEW "exports" AS SELECT "elf"."relative_path" AS "ELF",
                                                  "export"."address"    AS "address",
                                                  "symbol"."name"       AS "symbol",
                                                  "symbol"."demangled"  AS "demangled"
                  FROM "export" LEFT JOIN "elf"    ON "elf"."id"    = "export"."elf"
                                LEFT JOIN "symbol" ON "symbol"."id" = "export"."symbol"''')
    db.execute('''CREATE VIEW "imports" AS SELECT "elf"."relative_path" AS "ELF",
                                                  "symbol"."name"       AS "symbol",
                                                  "symbol"."demangled"  AS "demangled"
                  FROM "import" LEFT JOIN "elf"    ON "elf"."id"    = "import"."elf"
                                LEFT JOIN "symbol" ON "symbol"."id" = "import"."symbol"''')
    db.execute('''CREATE VIEW "export_relations" AS SELECT "export_elf"."relative_path" AS "exporter",
                                                           "symbol"."name"              AS "symbol",
                                                           "symbol"."demangled"         AS "demangled",
                                                           "import_elf"."relative_path" AS "importers"
                  FROM "export" LEFT JOIN "elf" AS "export_elf" ON "export_elf"."id" = "export"."elf"
                                LEFT JOIN "symbol"              ON "symbol"."id"     = "export"."symbol"
                                LEFT JOIN "import"              ON "import"."symbol" = "export"."symbol"
                                LEFT JOIN "elf" AS "import_elf" ON "import_elf"."id" = "import"."elf"''')
    db.execute('''CREATE VIEW "import_relations" AS SELECT "import_elf"."relative_path" AS "importer",
                                                           "symbol"."name"              AS "symbol",
                                                           "symbol"."demangled"         AS "demangled",
                                                           "export_elf"."relative_path" AS "exporters"
                  FROM "import" LEFT JOIN "elf" AS "import_elf" ON "import_elf"."id" = "import"."elf"
                                LEFT JOIN "symbol"              ON "symbol"."id"     = "import"."symbol"
                                LEFT JOIN "export"              ON "export"."symbol" = "import"."symbol"
                                LEFT JOIN "elf" AS "export_elf" ON "export_elf"."id" = "export"."elf"''')
    db_connection.commit()
    logging.info(f'Created new result database in {db_path}')


def fill_database(db_path, elves, symbols):
    """Populates an existing but empty SQLite database with provided ELF and symbols information."""
    logging.info(f'Writing results to {db_path}')
    export_rows = []
    import_rows = []
    dependency_rows = []
    for elf in elves:
        export_rows += [(elf['id'], x['id'], x['address']) for x in elf['exports']]
        import_rows += [(elf['id'], x['id']) for x in elf['imports']]
        dependency_rows += [(elf['id'], x) for x in elf['dependencies']]
    db_connection = sqlite3.connect(db_path)
    db = db_connection.cursor()
    db.executemany('INSERT INTO elf (id, absolute_path, relative_path) VALUES (:id, :absolute_path, :relative_path)',
                   elves)
    db.executemany('INSERT INTO symbol (id, name, demangled) VALUES (:id, :name, :demangled)', symbols.values())
    db.executemany('INSERT INTO export (elf, symbol, address) VALUES (?, ?, ?)', export_rows)
    db.executemany('INSERT INTO import (elf, symbol) VALUES (?, ?)', import_rows)
    db.executemany('INSERT INTO dependency (elf, dependency) VALUES (?, ?)', dependency_rows)
    db_connection.commit()
    logging.info(f'Stored {len(export_rows)} export and {len(import_rows)} import records for {len(symbols)} symbols '
                 f'in {len(elves)} ELF files')


def collect_elves(args):
    """Resolves all specified file and directory paths. Recursively searches all directories for ELF files. Ignores
    duplicate paths. Returns a sorted list of resolved absolute Path objects to all found ELF files.
    """
    elves = {x.resolve(strict=True) for x in args.paths if x.is_file()}
    directories = {x.resolve(strict=True) for x in args.paths if x.is_dir()}
    if directories:
        logging.info(f'Recursively searching for ELF files in {len(directories)} directories')
    for i, directory in enumerate(directories):
        logging.info(f'[{i+1}/{len(directories)}] {directory}')
        for file in directory.glob('**/*'):
            if is_dynamic_elf(file):
                elves.add(file.resolve(strict=True))
    return sorted(elves)


def analyze_elves(elf_paths):
    """Collects all exported and imported symbols and linking dependencies for all ELF files. Determines relative file
    paths based on the longest common ancestor directory.
    """
    def run(cmd, check=True):
        """Executes a command and returns its stdout output as a list of lines. Filters out empty lines."""
        process = subprocess.run(cmd.split(), check=check, capture_output=True, text=True)
        if not check and process.returncode != 0:
            return []
        raw = process.stdout.splitlines()
        filtered = list(filter(None, raw))
        empty_lines = len(raw) - len(filtered)
        if empty_lines:
            logging.warning(f'Corrupted or obfuscated ELF file: "{cmd}" produced {empty_lines} empty lines')
        return filtered

    def get_exports(elf_path):
        """Returns a list with a dictionary for each symbol exported by the ELF file."""
        exports = []
        nm_output = run(f'nm --dynamic --defined-only --format=posix {elf_path}')
        if len(nm_output) == 1 and nm_output[0].endswith(': no symbols'):
            logging.warning(f'Possibly obfuscated ELF file: nm did not find any symbols exports in "{elf_path}"')
            return []
        for line in nm_output:
            tokens = line.split()
            exports.append({'name': tokens[0], 'address': tokens[2]})
        return exports

    def get_imports(elf_path):
        """Returns a list with a dictionary for each symbol imported by the ELF file."""
        imports = []
        nm_output = run(f'nm --dynamic --undefined-only --format=just-symbols {elf_path}')
        if len(nm_output) == 1 and nm_output[0].endswith(': no symbols'):
            logging.warning(f'Possibly obfuscated ELF file: nm did not find any symbol imports in "{elf_path}"')
            return []
        for line in nm_output:
            imports.append({'name': line})
            if line.split('@')[0] == 'dlsym':
                logging.warning(f'dlsym() import detected in "{elf_path}"')
        return imports

    def get_dependencies(elf_path):
        """Returns a list of linkage dependencies of the ELF file, if available. ldd may fail for some ELF files."""
        return [line.strip().split()[0] for line in run(f'ldd {elf_path}', check=False)]

    def find_common_ancestor(current_ancestor, elf_path):
        """Returns the longest common ancestor directory between the specified paths."""
        while current_ancestor.parents and not elf_path.is_relative_to(current_ancestor):
            current_ancestor = current_ancestor.parent
        return current_ancestor

    logging.info(f'Analyzing {len(elf_paths)} ELF files')
    common_ancestor = elf_paths[0].parent
    elves = []
    for i, elf_path in enumerate(elf_paths):
        elves.append({
            'id': len(elves)+1,
            'name': elf_path.name,
            'absolute_path': str(elf_path),
            'exports': get_exports(elf_path),
            'imports': get_imports(elf_path),
            'dependencies': get_dependencies(elf_path)
        })
        common_ancestor = find_common_ancestor(common_ancestor, elf_path)
    logging.info(f'Determining relative file paths based on common ancestor {common_ancestor}')
    for elf in elves:
        elf['relative_path'] = str(Path(elf['absolute_path']).relative_to(common_ancestor))
    return elves


def enumerate_symbols(cxxfilt, elves):
    def get_or_add_symbol_id(name):
        """Looks up the symbol by its provided mangled name. Returns the ID if it exists, or adds and demangles a new
        symbol and returns its ID.
        """
        symbol = all_symbols.setdefault(name, {
            'id': len(all_symbols)+1,
            'name': name,
            'demangled': demangle(cxxfilt, name)
        })
        return symbol['id']

    logging.info('Enumerating all exported and imported symbols')
    all_symbols = {}
    for elf in elves:
        for symbol in elf['exports']:
            symbol['id'] = get_or_add_symbol_id(symbol['name'])
        for symbol in elf['imports']:
            symbol['id'] = get_or_add_symbol_id(symbol['name'])
    return all_symbols


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S', level=logging.INFO)
    main()
