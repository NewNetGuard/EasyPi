#!/bin/bash
set -euo pipefail

# EasyPi security scan

RED="\033[31m"
YELLOW="\033[33m"
GREEN="\033[32m"
RESET="\033[0m"

report_issue() {
  local severity="$1"; shift
  local message="$1"; shift
  local advice="$1"
  case "$severity" in
    high) color="$RED" ;;
    medium) color="$YELLOW" ;;
    low) color="$GREEN" ;;
    *) color="$RESET" ;;
  esac
  echo -e "${color}[${severity^^}]${RESET} $message"
  if [[ -n "$advice" ]]; then
    echo "  -> $advice"
  fi
  echo
}

echo "Running EasyPi security checks..."

# 1. Default password check
if getent passwd pi >/dev/null 2>&1; then
  report_issue "high" "Default user 'pi' exists. Ensure the password is not the factory default." "Run 'passwd pi' to change the password."
else
  echo -e "${GREEN}[OK]${RESET} Default 'pi' user not found." && echo
fi

SSH_CONFIG=/etc/ssh/sshd_config
if [[ -f "$SSH_CONFIG" ]]; then
  if grep -Ei '^\s*PermitRootLogin\s+yes' "$SSH_CONFIG" >/dev/null 2>&1; then
    report_issue "high" "SSH allows root login (PermitRootLogin yes)." "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no', then restart sshd."
  else
    echo -e "${GREEN}[OK]${RESET} SSH root login disabled." && echo
  fi
else
  echo -e "${YELLOW}[WARN]${RESET} sshd_config not found." && echo
fi

# Check open ports using ss
echo -e "${BLUE}[INFO]${RESET} Checking open ports..."
LISTENING_PORTS=$(ss -lnt 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -oE '[0-9]+$' | sort -u | paste -sd ', ' -)
if [[ -n "$LISTENING_PORTS" ]]; then
  report_issue "medium" "Listening TCP ports: $LISTENING_PORTS" "Review services and restrict access if unnecessary."
else
  echo -e "${GREEN}[OK]${RESET} No listening TCP ports detected." && echo
fi

if command -v apt >/dev/null 2>&1; then
  UPDATES=$(apt list --upgradable 2>/dev/null | grep -v "Listing")
  if [[ -n "$UPDATES" ]]; then
    COUNT=$(echo "$UPDATES" | wc -l | tr -d ' ')
    report_issue "medium" "$COUNT packages have updates available." "Run 'sudo apt-get update && sudo apt-get upgrade'."
  else
    echo -e "${GREEN}[OK]${RESET} No pending package updates." && echo
  fi
else
  echo -e "${YELLOW}[WARN]${RESET} apt command not found; skipping update check." && echo
fi

echo "Security scan completed."
