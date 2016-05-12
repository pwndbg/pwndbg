import os
import subprocess

file_path = os.path.dirname(__file__)
pwndbg_pwndbg = os.path.abspath(file_path)
pwndbg = os.path.dirname(pwndbg_pwndbg)
capstone = os.path.join(pwndbg, 'capstone')
unicorn = os.path.join(pwndbg, 'unicorn')

def get_hash(directory):
    argv = ['git', '-C', directory, 'describe', '--always']
    return subprocess.check_output(argv).strip()

hashes = {
    'capstone': get_hash(capstone),
    'unicorn':  get_hash(unicorn),
    'pwndbg':   get_hash(pwndbg)
}

if __name__ == '__main__':
    print(hashes)
