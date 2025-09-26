#!/usr/bin/env bash
# Install a launcher into /usr/local/bin so the command `DorkDigger` can be run without a local path like `./`
set -euo pipefail

proj_dir="$(cd "$(dirname "$0")" && pwd)"
launcher="$proj_dir/DorkDigger"
target="/usr/local/bin/DorkDigger"

# Ensure the launcher file exists at the expected path
if [ ! -f "$launcher" ]; then
  echo "Launcher not found at $launcher"
  exit 1
fi

echo "Installing DorkDigger -> $target"

# If a target already exists, back it up to a .bak file
if [ -e "$target" ]; then
  echo "Warning: $target already exists. Backing it up to ${target}.bak"
  sudo mv "$target" "${target}.bak"
fi

# Try to create a symlink without sudo; if that fails, retry with sudo
if ln -s "$launcher" "$target" 2>/dev/null; then
  echo "Installed symlink: $target -> $launcher"
else
  echo "Creating symlink requires elevated privileges. Prompting for sudo..."
  sudo ln -sf "$launcher" "$target"
  echo "Installed symlink (via sudo): $target -> $launcher"
fi

# Ensure the target and launcher are executable
sudo chmod +x "$target" || true
chmod +x "$launcher" || true

echo "Done. You can now run 'DorkDigger' from any directory."
echo "To uninstall: run ./uninstall.sh"

#!/usr/bin/env bash
set -e

# Virtual environment directory name
VENV_DIR=".venv_dork_monitor"

echo
echo "=== Dork Monitor installer ==="
echo "Creating virtual environment at ./$VENV_DIR"

# Create the virtual environment
python3 -m venv "$VENV_DIR" || { echo "Error: python3 -m venv failed. Ensure Python 3 is installed."; exit 1; }

# Activate the virtual environment for this shell
# Note: activation affects the current shell environment
source "$VENV_DIR/bin/activate"

# Upgrade core packaging tools
python -m pip install --upgrade pip setuptools wheel

# Install dependencies either from requirements.txt or a default set
if [ -f "requirements.txt" ]; then
  echo "Installing dependencies from requirements.txt..."
  pip install -r requirements.txt
else
  echo "requirements.txt not found. Installing default packages..."
  pip install serpapi requests beautifulsoup4 python-dotenv
fi

echo
echo "Installation complete."
echo "To run the tool, activate the virtualenv:"
echo "  source $VENV_DIR/bin/activate"
echo "Then run:"
echo "  python dork_serpapi_monitor.py --serpapi-key YOUR_KEY --site example.com"
