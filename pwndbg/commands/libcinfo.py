import pwndbg.commands
import gdb
import re
import subprocess
import os

@pwndbg.commands.Command
def libcinfo():
        """Identifies the libc version used by the binary and provides a link to its sources."""

        try:
            # Run the `vmmap` command and capture output
            vmmap_output = gdb.execute("vmmap", to_string=True)
            libc_path = None
            real_libc_path = None

            # Search for the libc entry in vmmap output
            for line in vmmap_output.splitlines():
                if "libc" in line and ".so" in line:
                    parts = line.split()
                    libc_path = parts[-1]
                    break
            
            if not libc_path:
                print("[!] Could not find libc in memory mappings.")
                return
            
            print(f"[+] libc found at: {libc_path}")

            # Resolve the real path in case it's a symlink
            real_libc_path = os.path.realpath(libc_path)
            real_libc_path = real_libc_path.replace('\x1b[0m', '')
            print(f"[+] Resolved libc to: {real_libc_path}")
            
            try:
                result = subprocess.run(["/usr/bin/strings", real_libc_path], capture_output=True, text=True, check=True)
                strings_output = result.stdout
                version_match = re.search(r'GNU C Library.*?(\d+\.\d+)|libc-?(\d+\.\d+)', strings_output)
                if version_match:
                    libc_version = version_match.group(1) or version_match.group(2)
                    print(f"[+] libc version: {libc_version}")

                    # Generate source link
                    source_url = f"https://ftp.gnu.org/gnu/libc/glibc-{libc_version}.tar.gz"
                    print(f"[+] libc source: {source_url}")
                else:
                    print("[!] Could not determine libc version using strings.")

            except subprocess.CalledProcessError as e:
                print(f"[!] Error running strings on {real_libc_path}: {e}")
                print("[!] This could be due to restricted access or permissions.")
                print(f"stderr: {e.stderr}")
        
        except Exception as e:
            print(f"[!] Error: {e}")

