#!/bin/bash
# Post-install script for LLMtary Linux packages

# Update the desktop application database
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi

# Update the icon cache
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache /usr/share/pixmaps || true
fi

# Ensure the binary is executable
chmod +x /opt/LLMtary/llmtary || true
