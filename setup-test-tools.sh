#!/bin/bash -e

echo "# --------------------------------------"
echo "# Install testing tools."
echo "# Only works with Ubuntu / APT."
echo "# --------------------------------------"

# If we are a root in a Docker container and `sudo` doesn't exist
# lets overwrite it with a function that just executes things passed to sudo
# (yeah it won't work for sudo executed with flags)
if [ -f /.dockerenv ] && ! hash sudo 2>/dev/null && whoami | grep root; then
  sudo() {
    ${*}
  }
fi

linux() {
  uname | grep -i Linux &>/dev/null
}

install_apt() {
  sudo apt-get update || true
  sudo apt-get install -y nasm
  test -f /usr/bin/go || sudo apt-get install -y golang
}

if linux; then
  distro=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | sed -e 's/"//g')

  case $distro in
  "ubuntu")
    install_apt
    ;;
  *) # we can add more install command for each distros.
    echo "\"$distro\" is not supported distro. Will search for 'apt' or 'dnf' package managers."
    if hash apt; then
      install_apt
    else
      echo "\"$distro\" is not supported and your distro don't have apt or dnf that we support currently."
      exit
    fi
    ;;
  esac
fi
