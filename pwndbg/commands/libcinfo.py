import gdb
import os
import pwndbg.commands
import pwndbg.aglib.vmmap
import re
import subprocess

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenLocal
def libcinfo():
        """Identifies the libc version used by the binary and provides a link to its sources.
           This command only works in local debugging sessions
        """

        try:
            mappings = pwndbg.aglib.vmmap.get()
            libc_path = None
            real_libc_path = None

            for mapping in mappings:
                if "libc.so" in mapping.objfile:
                    libc_path = mapping.objfile
                    break
            
            if not libc_path:
                print("[!] Could not find libc in memory mappings.")
                return
            
            print(f"[+] libc found at: {libc_path}")

            # Resolve the real path in case it's a symlink
            real_libc_path = os.path.realpath(libc_path)
            real_libc_path = real_libc_path.replace('\x1b[0m', '')
            print(f"[+] Resolved libc to: {real_libc_path}")
            
            # Try opening the libc file
            with open(real_libc_path, "rb") as libc_file:
                chunk_size = 4096
                buffer = libc_file.read(chunk_size)

                version_pattern = rb"GNU C Library.*?(\d+\.\d+)|libc-?(\d+\.\d+)"

                found_versions = []
                while buffer:
                    # Look for version strings in the current chunk
                    match = re.search(version_pattern, buffer)
                    if match:
                        libc_version = match.group(1) or match.group(2)
                        found_versions.append(libc_version.decode())

                    # Read the next chunk
                    buffer = libc_file.read(chunk_size)

                if found_versions:
                    libc_version = found_versions[0]
                    print(f"[+] libc version: {libc_version}")


                    # Generate source link
                    source_url = f"https://ftp.gnu.org/gnu/libc/glibc-{libc_version}.tar.gz"
                    print(f"[+] libc source: {source_url}")

                else:
                    print("[!] Could not determine libc version using file read.")
        except Exception as e:
            print(f"[!] Error: {e}")

