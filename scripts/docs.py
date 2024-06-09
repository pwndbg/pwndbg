from __future__ import annotations

import cProfile
import glob
import locale
import os
import site
import sys
import time
from glob import glob
from os import environ
from os import path
import pdb, traceback, code

_profiler = cProfile.Profile()

_start_time = None
if environ.get("PWNDBG_PROFILE") == "1":
    _start_time = time.time()
    _profiler.enable()

# Get virtualenv's site-packages path
venv_path = os.environ.get("PWNDBG_VENV_PATH")
    pass
else:
    directory, file = path.split(__file__)
    directory = path.expanduser(directory)
    directory = path.abspath(directory)

    if not venv_path:
        venv_path = os.path.join(directory, ".venv")

    if not os.path.exists(venv_path):
        print(f"Cannot find Pwndbg virtualenv directory: {venv_path}: please re-run setup.sh")
        sys.exit(1)

    site_pkgs_path = glob(os.path.join(venv_path, "lib/*/site-packages"))[0]

    # add virtualenv's site-packages to sys.path and run .pth files
    site.addsitedir(site_pkgs_path)

    # remove existing, system-level site-packages from sys.path
    for site_packages in site.getsitepackages():
        if site_packages in sys.path:
            sys.path.remove(site_packages)

    # Set virtualenv's bin path (needed for utility tools like ropper, pwntools etc)
    bin_path = os.path.join(venv_path, "bin")
    os.environ["PATH"] = bin_path + os.pathsep + os.environ.get("PATH")

    # Add pwndbg directory to sys.path so it can be imported
    sys.path.insert(0, directory)

    # Push virtualenv's site-packages to the front
    sys.path.remove(site_pkgs_path)
    sys.path.insert(1, site_pkgs_path)


# warn if the user has different encoding than utf-8
encoding = locale.getpreferredencoding()

# use casefold, since the string may be "UTF-8" on some platforms and "utf-8" on others
if encoding.casefold() != "utf-8":
    print("******")
    print(f"Your encoding ({encoding}) is different than UTF-8. pwndbg might not work properly.")
    print("You might try launching GDB with:")
    print("    LC_CTYPE=C.UTF-8 gdb")
    print(
        "If that does not work, make sure that en_US.UTF-8 is uncommented in /etc/locale.gen and that you called `locale-gen` command"
    )
    print("******")

environ["PWNLIB_NOTERM"] = "1"

from sphinx.cmd.build import build_main

# import os
# import sys
#
# # These paths are relative to the 'source' directory
# os.environ["SPHINX"] = "1"
# sys.path.insert(0, os.path.abspath(".."))  # <-- For 'gdb'
# sys.path.insert(0, os.path.abspath("../.."))  # <-- For 'pwndbg'

def generate_sphinx_docs(source_dir, output_dir):
    # Run the sphinx build_main function
    try:
        build_main(["-b", "html", source_dir, output_dir])
        print("Documentation generated successfully.")
    except Exception as e:
        print(f"Error generating documentation: {e}")
        exit(1)


from mkdocs.commands.build import build
from mkdocs.config import load_config
def build_mkdocs(docs_dir="docs", output_dir="site"):
    # Change to the directory containing your mkdocs.yml configuration file
    os.chdir(docs_dir)

    # Load MkDocs configuration
    config = load_config()

    # Specify the desired output directory
    config["site_dir"] = output_dir

    # Build the documentation
    build(config)

    print("MkDocs build completed successfully.")


print("Current Directory:", os.getcwd())
os.environ['READTHEDOCS'] = 'True'

# Ensure the source directory exists
# if not os.path.exists(source_directory):
#     print(f"Source directory '{source_directory}' not found.")
#     exit(1)

# Ensure the output directory exists, create if not
# if not os.path.exists(output_directory):
#     os.makedirs(output_directory)

# Call the function to generate documentation
try:
    print("Start docs generating")
    source_directory = "docs/source"
    output_directory = "docs/build"
    generate_sphinx_docs(source_directory, output_directory)


    # source_directory = "."
    # output_directory = "site"
    # build_mkdocs(source_directory, output_directory)
    print("Docs generated successfully.")
except:
    extype, value, tb = sys.exc_info()
    traceback.print_exc()
    pdb.post_mortem(tb)
