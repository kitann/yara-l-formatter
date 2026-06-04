#!/bin/bash

echo "=================================="
echo "   Git Auto Push Utility"
echo "=================================="

# Show current git status
echo ""
echo "[*] Checking git status..."
git status

# Ask for commit message
echo ""
read -p "Enter git commit message: " commitmsg

# Add all files
echo ""
echo "[*] Adding files..."
git add .

# Commit changes
echo ""
echo "[*] Committing changes..."
git commit -m "$commitmsg"

# Push to remote
echo ""
echo "[*] Pushing to GitHub..."
git push origin main

# Show latest commits
echo ""
echo "[*] Latest commits:"
git log --oneline -5

# Show current git status
echo ""
echo "[*] Checking git status..."
git status

# Completion message
echo ""
echo "=================================="
echo " Git push process completed!"
echo "=================================="
