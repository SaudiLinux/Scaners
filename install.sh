#!/bin/bash

# Advanced Web Vulnerability Scanner - Installation Script
# This script installs all required dependencies for the Lua vulnerability scanner

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║          Advanced Web Vulnerability Scanner - Installation                   ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if Lua is installed
echo "[*] Checking Lua installation..."
if command -v lua &> /dev/null; then
    LUA_VERSION=$(lua -v 2>&1 | head -n1)
    echo "[+] Lua found: $LUA_VERSION"
else
    echo "[!] Lua not found. Please install Lua 5.1+ or LuaJIT first."
    echo "[!] Installation aborted."
    exit 1
fi

# Check if LuaRocks is installed
echo "[*] Checking LuaRocks installation..."
if command -v luarocks &> /dev/null; then
    echo "[+] LuaRocks found"
else
    echo "[!] LuaRocks not found. Please install LuaRocks first."
    echo "[!] Installation aborted."
    exit 1
fi

# Create installation directory
echo "[*] Creating installation directory..."
INSTALL_DIR="$HOME/.lua_vuln_scanner"
mkdir -p "$INSTALL_DIR"
echo "[+] Installation directory created: $INSTALL_DIR"

# Install required Lua packages
echo "[*] Installing required Lua packages..."

echo "    Installing luasocket..."
luarocks install luasocket --local
if [ $? -eq 0 ]; then
    echo "    [+] luasocket installed successfully"
else
    echo "    [!] Failed to install luasocket"
fi

echo "    Installing dkjson..."
luarocks install dkjson --local
if [ $? -eq 0 ]; then
    echo "    [+] dkjson installed successfully"
else
    echo "    [!] Failed to install dkjson"
fi

echo "    Installing lua-cjson..."
luarocks install lua-cjson --local
if [ $? -eq 0 ]; then
    echo "    [+] lua-cjson installed successfully"
else
    echo "    [!] Failed to install lua-cjson"
fi

# Check if all required files exist
echo "[*] Checking scanner files..."
REQUIRED_FILES=(
    "web_scanner.lua"
    "vulnerability_scanner.lua"
    "vulnerability_tests.lua"
    "exploitation_tests.lua"
    "README.md"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "    [+] Found: $file"
        cp "$file" "$INSTALL_DIR/"
    else
        echo "    [!] Missing: $file"
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo ""
    echo "[!] Warning: The following files are missing:"
    for file in "${MISSING_FILES[@]}"; do
        echo "    - $file"
    done
    echo "[!] Please ensure all files are in the current directory."
fi

# Create wrapper script
echo "[*] Creating wrapper script..."
cat > "$INSTALL_DIR/vuln_scanner" << 'EOF'
#!/bin/bash
# Wrapper script for the Lua vulnerability scanner

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set up Lua path to include local rocks
export LUA_PATH="$HOME/.luarocks/share/lua/5.1/?.lua;$HOME/.luarocks/share/lua/5.1/?/init.lua;;"
export LUA_CPATH="$HOME/.luarocks/lib/lua/5.1/?.so;;"

# Run the scanner
cd "$SCRIPT_DIR"
lua web_scanner.lua "$@"
EOF

chmod +x "$INSTALL_DIR/vuln_scanner"
echo "[+] Wrapper script created"

# Create symbolic link
echo "[*] Creating symbolic link..."
if [ -w "$HOME/bin" ]; then
    ln -sf "$INSTALL_DIR/vuln_scanner" "$HOME/bin/vuln_scanner"
    echo "[+] Symbolic link created: $HOME/bin/vuln_scanner"
    echo "[+] You can now run: vuln_scanner --help"
elif [ -w "/usr/local/bin" ]; then
    sudo ln -sf "$INSTALL_DIR/vuln_scanner" "/usr/local/bin/vuln_scanner"
    echo "[+] Symbolic link created: /usr/local/bin/vuln_scanner"
    echo "[+] You can now run: vuln_scanner --help"
else
    echo "[!] Could not create symbolic link. Add $INSTALL_DIR to your PATH."
    echo "[!] Run: export PATH=\"$INSTALL_DIR:\$PATH\""
fi

# Test installation
echo ""
echo "[*] Testing installation..."
cd "$INSTALL_DIR"
if lua -e "require('socket'); require('dkjson'); print('Dependencies loaded successfully')" 2>/dev/null; then
    echo "[+] All dependencies loaded successfully"
else
    echo "[!] Some dependencies failed to load"
    echo "[!] You may need to manually configure your Lua path"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    Installation Complete!                                    ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "The Advanced Web Vulnerability Scanner has been installed successfully!"
echo ""
echo "Quick start:"
echo "  vuln_scanner https://example.com"
echo "  vuln_scanner -v -e -o report.json https://example.com"
echo ""
echo "For help:"
echo "  vuln_scanner --help"
echo ""
echo "⚠️  Remember: Only use this tool on systems you own or have permission to test!"
echo ""

# Return to original directory
cd - > /dev/null