# ELF Symbol Analyzer
The ELF symbol analyzer is a Python script that collects symbols exported and imported by dynamically linked ELF files,
analyzes them and stores the results in a relational database.

## Usage Scenario
Whenever the target is not a standalone executable,
one must first identify which files qualify for analysis before firing up
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) or
[IDA Pro](https://hex-rays.com/ida-pro/).
This discovery process can become tedious if the software is distributed as a collection of shared objects.
For instance, firmware images typically contain entire file systems.

The ELF symbol analyzer is a quick and easy way to get an initial overview of such targets.

## How to use
Install the dependencies:
```
$ sudo apt install binutils
$ pip install -r requirements.txt
```
Run the script specifying the output database file and one or several directories and / or ELF files:
```
$ ./elf-symbol-analyzer.py -o results.sqlite3 /opt/target-dir/ /opt/other/libsome.so
```
After the script finishes, open `results.sqlite3` in your favorite [SQLite database
browser](https://sqlitebrowser.org/).
Use the SQL views and the interactive filters to discover and follow symbols of interest.

## SQL Views
* Use the *dependencies* view to inspect linkage dependencies as reported by `ldd`.
* Use the *exports* and *imports* views to inspect exported and imported symbols as reported by `nm`.
* Use the *export_relations* view to see how the symbols that are exported by analyzed ELF files are being used.
* Use the *import_relations* view to see where the symbols that are imported by analyzed ELF files come from.

## Additional Information
The script will produce a warning for each ELF file that imports the `dlsym()` symbol.
This means that the ELF file is likely loading additional symbols at runtime.
Such symbols are not analyzed by this script and are thus not presented in the result database.

## Requirements
### System Utilities
* c++filt
* ldd
* nm
### Python Modules
* python-magic
