#!/usr/bin/env sh
# gate.cat user-local installer
# Installs into a private virtualenv; never writes to system Python.
set -eu

PACKAGE="${GATECAT_PACKAGE:-gate.cat}"
INSTALL_ROOT="${GATECAT_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/gate.cat}"
VENV="$INSTALL_ROOT/venv"
BIN_DIR="${GATECAT_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
PYTHON="${PYTHON:-}"

if [ -z "$PYTHON" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
  elif command -v python >/dev/null 2>&1; then
    PYTHON=python
  else
    printf '%s\n' 'gate.cat: Python 3 is required (>=3.10).' >&2
    exit 1
  fi
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  printf '%s\n' 'gate.cat: Python >=3.10 is required.' >&2
  exit 1
fi

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"

if [ ! -x "$VENV/bin/python" ]; then
  rm -rf "$VENV"
  "$PYTHON" -m venv "$VENV" || {
    printf '%s\n' 'gate.cat: could not create a venv.' >&2
    printf '%s\n' 'On Debian/Ubuntu install the venv module: sudo apt install python3-venv' >&2
    exit 1
  }
fi

"$VENV/bin/python" -m pip install --disable-pip-version-check --upgrade "$PACKAGE"

for command_name in gatecat-hook gatecat gatecat-cli gatecat-shell gatecat-proxy; do
  if [ -x "$VENV/bin/$command_name" ]; then
    ln -sfn "$VENV/bin/$command_name" "$BIN_DIR/$command_name"
  fi
done

"$VENV/bin/python" -c 'import gatecat; print("gate.cat installed:", getattr(gatecat, "__version__", "ok"))'

case ":${PATH}:" in
  *":$BIN_DIR:"*) ;;
  *)
    printf '\nAdd the local bin directory to PATH for this shell:\n  export PATH="%s:$PATH"\n' "$BIN_DIR"
    ;;
esac

printf '\nInstalled gate.cat into %s\n' "$VENV"
printf 'Hook: %s/gatecat-hook\n' "$BIN_DIR"
printf 'Claude Code config command: gatecat-hook\n'
printf '\nThe local gate stays free and works without an account.\n'
printf '%s\n' 'Optional signed policy sync and stack-specific packs: https://gate.cat/?utm_source=installer&utm_medium=cli&utm_campaign=launch_20260714#pricing'
