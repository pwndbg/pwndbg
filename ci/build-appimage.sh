#! /bin/bash

set -x
set -e

# use RAM disk if possible
if [ "$CI" == "" ] && [ -d /dev/shm ]; then
    TEMP_BASE=/dev/shm
else
    TEMP_BASE=/tmp
fi

BUILD_DIR="$(mktemp -d -p "$TEMP_BASE" pwndbg-build-XXXXXX)"

cleanup () {
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}

trap cleanup EXIT

# store repo root as variable
REPO_ROOT="$(readlink -f "$(dirname "$0")/..")"
OLD_CWD="$(readlink -f .)"

pushd "$BUILD_DIR"

# first, we have to prepare an AppDir with a portable Python environment
# note: we only build for x86_64 for now
wget -c https://raw.githubusercontent.com/TheAssassin/linuxdeploy-plugin-conda/master/linuxdeploy-plugin-conda.sh
wget -c https://github.com/TheAssassin/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage

chmod +x linuxdeploy-x86_64.AppImage
chmod +x linuxdeploy-plugin-conda.sh

export PIP_REQUIREMENTS="-r $REPO_ROOT/requirements.txt"
./linuxdeploy-x86_64.AppImage --appdir AppDir --plugin conda

# next, build up-to-date GDB against this Python environment
wget https://ftp.gnu.org/gnu/gdb/gdb-10.1.tar.xz -O- | tar xJ

pushd gdb-10.1

# the following script, which we use in place of a real python binary, lets us build gdb against the conda Python environment
# don't ask how long it took to figure out how to persuade GDB's configure stuff to fetch the correct data...
# thanks, automake, for wasting my lifetime...
# note: for the script to work, one needs to set the environment variable CONDA_PREFIX
cat > wrapper.sh <<\EOF
#! /bin/bash

if [[ -z "$CONDA_PREFIX" ]]; then
    echo "Error: CONDA_PREFIX not set"
    exit 2
fi

echo "$(date +%F) -- $@" >> /tmp/args.txt

if [[ $1 != *"python-config.py"* ]]; then
    exec "$CONDA_PREFIX"/bin/python3
fi

# get rid of the first parameter, which is the path to the python-config.py script
shift

# python3-config --ldflags lacks the python library
# also gdb won't link on GitHub actions without libtinfow, which is not provided by the conda environment
if [[ "$1" == "--ldflags" ]]; then
    echo -n "-lpython3.8 -ltinfow "
fi

exec "$CONDA_PREFIX"/bin/python3-config "$@"
EOF

chmod +x wrapper.sh

CONDA_PREFIX="$(readlink -f "$BUILD_DIR"/AppDir/usr/conda)"
export CONDA_PREFIX

./configure --with-python="$(readlink -f wrapper.sh)" --prefix=/usr

if [[ "$CI" == "" ]]; then
    nproc="$(nproc --ignore=1)"
else
    nproc="$(nproc)"
fi

make -j"$nproc"

make install DESTDIR="$BUILD_DIR"/AppDir

popd

# now, we set up some metadata for the AppImage
cat > AppDir/usr/share/applications/pwndbg.desktop <<\EOF
[Desktop Entry]
Name=pwndbg
# note: this is a fake entry to make appimagetool happy; in reality, we use a custom AppRun script
Exec=pwndbg
Icon=pwndbg
Type=Application
Terminal=true
Categories=Development;
EOF

# todo: use some real icon
touch AppDir/usr/share/icons/hicolor/scalable/pwndbg.svg

cat > AppRun.sh <<\EOF
#! /bin/bash

this_dir="$(dirname "$0")"

# pwndbg recommends these settings
export LC_ALL=en_US.UTF-8
export PYTHONIOENCODING=UTF-8

# make sure the libpython3.x gdb is linked to uses the conda environment
export PYTHONHOME="$this_dir"/usr/conda

abs_path_to_gdbinit="$(readlink -f "$this_dir"/pwndbg/gdbinit.py)"
escaped_path_to_gdbinit="$(printf '%q' "$abs_path_to_gdbinit")"

exec "$this_dir"/usr/bin/gdb -nh -nx -ex "source $escaped_path_to_gdbinit" "$@"
EOF

chmod +x AppRun.sh

# we also have to copy over pwndbg to the AppDir
mkdir AppDir/pwndbg/ -p

for i in caps gdbinit.py ida_script.py LICENSE.md pwndbg ; do
    cp -R "$REPO_ROOT"/"$i" AppDir/pwndbg/"$i"
done

# finally, we can build the AppImage
VERSION="$(cd "$REPO_ROOT" && git describe --tags)"
export VERSION

# workaround: the gdb binaries lack a proper rpath, so we have to help linuxdeploy find the Python binaries
LD_LIBRARY_PATH="$(readlink -f "$BUILD_DIR"/AppDir/usr/conda/lib)"
export LD_LIBRARY_PATH

./linuxdeploy-x86_64.AppImage --appdir AppDir/ --output appimage --custom-apprun AppRun.sh

# done -- let's move the AppImage to safety before the tempdir gets cleaned up
mv pwndbg*.AppImage "$OLD_CWD"
