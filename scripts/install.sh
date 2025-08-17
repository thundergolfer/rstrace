#!/bin/env sh

# This is a short script to install the latest version of the thundergolfer/rstrace binary.

set -eu


case "$(uname -s)" in
  Linux*) suffix="-unknown-linux-gnu";;
  Darwin*) suffix="-apple-darwin";;
  FreeBSD*) suffix="-unknown-freebsd";;
  MINGW*|MSYS*|CYGWIN*)
    echo "You are on Windows. rstrace is not yet supported on Windows.";
    exit 1;;
  *) echo "Unknown OS $(uname -s)"; exit 1;;
esac

case "$(uname -m)" in
  aarch64 | aarch64_be | arm64 | armv8b | armv8l) arch="aarch64";;
  armv6l) arch="arm"; suffix="${suffix}eabihf";;
  armv7l) arch="armv7"; suffix="${suffix}eabihf";;
  x86_64 | x64 | amd64) arch="x86_64";;
  *) echo "Unsupported arch $(uname -m)"; exit 1;;
esac

if [ "$arch" != "x86_64" ]; then
  echo "Error: Only the x86_64 architecture is currently supported"
  exit 1
fi

if [ -z "${NO_COLOR:-}" ]; then
  ansi_reset="\033[0m"
  ansi_info="\033[35;1m"
  ansi_error="\033[31m"
  ansi_underline="\033[4m"
fi

url="https://github.com/thundergolfer/rstrace/releases/latest/download/rstrace-${arch}${suffix}.tar.gz"
cmd=${1:-install}
temp=$(mktemp)

case $cmd in
  "download")
    path=$(pwd)
    ;;
  "install")
    path=/usr/local/bin
    ;;
  *)
    printf "${ansi_error}Error: Invalid command. Please use 'download' or 'install'.\n"
    exit 2
    ;;
esac

printf "${ansi_reset}${ansi_info}↯ Downloading rstrace from ${ansi_underline}%s${ansi_reset}\n" "$url"
http_code=$(curl -L "$url" -o "$temp" -w "%{http_code}")
if [ "$http_code" -lt 200 ] || [ "$http_code" -gt 299 ]; then
  printf "${ansi_error}Error: Response status code ${http_code}.\n"
  cat "$temp" 1>&2
  printf "${ansi_reset}\n"
  exit 1
fi

printf "\n${ansi_reset}${ansi_info}↯ Adding rstrace binary to ${ansi_underline}%s${ansi_reset}\n" "$path"
# Extract the binary to the target path, using sudo if necessary.
if [ "$(id -u)" -ne 0 ] && [ "$path" = "/usr/local/bin" ]; then
  sudo tar xf "$temp" -C "$path" || exit 1
else
  tar xf "$temp" -C "$path" || exit 1
fi

printf "\n${ansi_reset}${ansi_info}↯ Done! You can now run rstrace.${ansi_reset}\n"
