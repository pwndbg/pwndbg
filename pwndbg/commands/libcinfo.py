from __future__ import annotations

import os
import re
import subprocess

import gdb

import pwndbg.aglib.vmmap
import pwndbg.commands


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenLocal
def libcinfo():
        """Identifies the libc version used by the binary and provides a link to its sources.
           This command only works in local debugging sessions
        """

        try:
            libc_path = next(
                (m.objfile for m in pwndbg.aglib.vmmap.get() if "libc.so" in m.objfile), None
            )
            
            if not libc_path:
                print("[!] Could not find 'libc.so' string in vmmap memory mappings.")
                return
            
            print(f"[+] libc found at: {libc_path}")

            # Resolve the real path in case it's a symlink
            real_libc_path = os.path.realpath(libc_path)
            print(f"[+] Resolved libc to: {real_libc_path}")

            # Try opening the libc file
            with open(real_libc_path, "rb") as libc_file:
                buffer = libc_file.read()

            version_pattern = rb"GNU C Library.*?(\d+\.\d+)|libc-?(\d+\.\d+)"
            
            # Look for version strings in the current chunk
            match = re.search(version_pattern, buffer)
            if match:
                libc_version = (match.group(1) or match.group(2)).decode()

                print(f"[+] libc version: {libc_version}")

                # Generate source link
                source_url = f"https://ftp.gnu.org/gnu/libc/glibc-{libc_version}.tar.gz"
                print(f"[+] libc source link: {source_url}")

            else:
                print("[!] Could not determine libc version using file read.")
        except Exception as e:
            print(f"[!] Error: {e}")

