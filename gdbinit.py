import glob
import locale
import sys
from os import environ
from os import path

# Allow users to use packages from a virtualenv
# That's not 100% supported, but they do it on their own,
# so we will warn them if the GDB's Python is not virtualenv's Python
virtual_env = environ.get("VIRTUAL_ENV")

if virtual_env:
    no_venv_warning = environ.get("PWNDBG_NO_VENV_WARNING", 0)
    if not no_venv_warning and not sys.executable.startswith(virtual_env):
        print("[!] Pwndbg Python virtualenv warning [!]")
        print(
            "Found Python virtual environment (VIRTUAL_ENV='%s') while GDB is built with a different Python binary (%s)"
            % (virtual_env, sys.executable)
        )
        print("Assuming that you installed Pwndbg dependencies into the virtual environment")
        print("If this is not true, this may cause import errors or other issues in Pwndbg")
        print(
            "If all works for you, you can suppress this warning by setting PWNDBG_NO_VENV_WARNING=1"
        )
        print("")

        possible_site_packages = glob.glob(
            path.join(virtual_env, "lib", "python*", "site-packages")
        )
        if len(possible_site_packages) > 1:
            print("Found multiple site packages in virtualenv, using the last choice.")
        virtualenv_site_packages = []
        for site_packages in possible_site_packages:
            virtualenv_site_packages = site_packages
        if not virtualenv_site_packages:
            print("Not found site-packages in virtualenv, guessing")
            guessed_python_directory = "python%s.%s" % (
                sys.version_info.major,
                sys.version_info.minor,
            )
            virtualenv_site_packages = path.join(
                virtual_env, "lib", guessed_python_directory, "site-packages"
            )

        print("Adding virtualenv's python site packages: %s to sys.path" % virtualenv_site_packages)
        sys.path.append(virtualenv_site_packages)


directory, file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)


gdbpt = path.join(directory, "gdb-pt-dump")
sys.path.append(directory)
sys.path.append(gdbpt)

# warn if the user has different encoding than utf-8
encoding = locale.getpreferredencoding()

if encoding != "UTF-8":
    print("******")
    print(
        "Your encoding ({}) is different than UTF-8. pwndbg might not work properly.".format(
            encoding
        )
    )
    print("You might try launching gdb with:")
    print("    LC_ALL=en_US.UTF-8 PYTHONIOENCODING=UTF-8 gdb")
    print("Make sure that en_US.UTF-8 is activated in /etc/locale.gen and you called locale-gen")
    print("******")

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
