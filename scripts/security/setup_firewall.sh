#!/bin/bash
set -euo pipefail

# EasyPi firewall setup

remove_easypi_rules() {
  local -a rule_numbers=()
  local number=""

  command -v ufw >/dev/null 2>&1 || return 0
  # Keep the SSH rule that was already active while EasyPi was installed.
  # Removing it while UFW still has a deny-incoming policy can lock a remote
  # administrator out before an uninstall/reinstall failure can be repaired.
  # No new access is granted here: HTTP, HTTPS, DNS, and all other tagged
  # product rules are deleted. UFW rule numbers shift after deletion, so
  # delete matching entries from highest to lowest.
  mapfile -t rule_numbers < <(
    LC_ALL=C sudo ufw status numbered 2>/dev/null \
      | sed -nE \
          -e '/# EasyPi SSH([[:space:]]|$)/d' \
          -e '/# EasyPi([[:space:]]|$)/s/^\[[[:space:]]*([0-9]+)\].*/\1/p' \
      | sort -rn
  )
  for number in "${rule_numbers[@]}"; do
    sudo ufw --force delete "$number" >/dev/null
  done
}

if [[ "${1:-}" == "clear-runtime" ]]; then
  [[ "$#" -eq 1 ]] || {
    echo "Usage: $0 clear-runtime" >&2
    exit 1
  }
  remove_easypi_rules
  exit 0
fi

if ! command -v ufw >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "ufw not installed. Installing..."
    sudo apt-get install -y ufw
  else
    echo "ufw not installed and apt-get not found." >&2
    exit 1
  fi
fi

get_ssh_port() {
  local port=""
  if command -v sshd >/dev/null 2>&1; then
    port="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')"
  fi
  if [[ -z "${port}" ]]; then
    port="$(awk '$1 == "Port" {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
  fi
  if [[ -z "${port}" ]]; then
    port="22"
  fi
  echo "${port}"
}

is_private_ipv4() {
  local ip="$1"
  if [[ "${ip}" == 10.* || "${ip}" == 192.168.* ]]; then
    return 0
  fi
  if [[ "${ip}" =~ ^172\.([1-2][0-9]|3[0-1])\. ]]; then
    return 0
  fi
  return 1
}

is_excluded_iface() {
  local iface="$1"
  case "${iface}" in
    lo|docker*|br-*|veth*|tailscale0|wg*|tun*|tap*|virbr*|lxc*)
      return 0
      ;;
  esac
  return 1
}

detect_dns_ifaces() {
  local ifaces=()

  if [[ -n "${EASYPI_DNS_IFACES:-}" ]]; then
    for iface in ${EASYPI_DNS_IFACES}; do
      ifaces+=("${iface}")
    done
    printf '%s\n' "${ifaces[@]}"
    return 0
  fi

  if ! command -v ip >/dev/null 2>&1; then
    return 0
  fi

  mapfile -t iface_lines < <(ip -o -4 addr show up scope global | awk '{print $2, $4}')
  for line in "${iface_lines[@]}"; do
    local iface="${line%% *}"
    local addr="${line##* }"
    local ip="${addr%%/*}"

    if is_private_ipv4 "${ip}" && ! is_excluded_iface "${iface}"; then
      ifaces+=("${iface}")
    fi
  done

  printf '%s\n' "${ifaces[@]}" | sort -u
}

allow_dns_rules() {
  local ifaces=("$@")
  if [[ "${#ifaces[@]}" -eq 0 ]]; then
    return 0
  fi
  for iface in "${ifaces[@]}"; do
    sudo ufw allow in on "${iface}" to any port 53 proto udp comment "EasyPi DNS ${iface}"
    sudo ufw allow in on "${iface}" to any port 53 proto tcp comment "EasyPi DNS ${iface}"
  done
}

if [[ "$#" -eq 0 ]]; then
  echo "Configuring default firewall rules..."
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  ssh_port="$(get_ssh_port)"
  sudo ufw allow "${ssh_port}/tcp" comment 'EasyPi SSH'
  sudo ufw allow 80/tcp comment 'EasyPi HTTP'
  sudo ufw allow 443/tcp comment 'EasyPi HTTPS'
  mapfile -t dns_ifaces < <(detect_dns_ifaces)
  allow_dns_rules "${dns_ifaces[@]}"
  if ! sudo ufw status | grep -q "Status: active"; then
    sudo ufw --force enable
  fi
  sudo ufw reload
  sudo ufw status verbose
  exit 0
fi

action="$1"
case "$action" in
  add)
    [[ "$#" -eq 2 || "$#" -eq 3 ]] || {
      echo "Usage: $0 add <port/protocol> [allow|deny|limit|reject]" >&2
      exit 1
    }
    port_protocol="$2"
    if [[ ! "$port_protocol" =~ ^([0-9]{1,5})/(tcp|udp)$ ]] \
        || (( 10#${BASH_REMATCH[1]} < 1 || 10#${BASH_REMATCH[1]} > 65535 )); then
      echo "Port must be 1..65535 followed by /tcp or /udp" >&2
      exit 1
    fi
    rule_action="${3:-allow}"
    [[ "$rule_action" =~ ^(allow|deny|limit|reject)$ ]] || {
      echo "Invalid firewall action" >&2
      exit 1
    }
    sudo ufw "$rule_action" "$port_protocol" comment 'EasyPi managed rule'
    ;;
  delete)
    [[ "$#" -eq 2 ]] || {
      echo "Usage: $0 delete <port/protocol>" >&2
      exit 1
    }
    port_protocol="$2"
    if [[ ! "$port_protocol" =~ ^([0-9]{1,5})/(tcp|udp)$ ]] \
        || (( 10#${BASH_REMATCH[1]} < 1 || 10#${BASH_REMATCH[1]} > 65535 )); then
      echo "Port must be 1..65535 followed by /tcp or /udp" >&2
      exit 1
    fi
    sudo ufw --force delete allow "$port_protocol"
    ;;
  *)
    echo "Usage: $0 [add|delete] <port/protocol> [allow|deny] | clear-runtime" >&2
    exit 1
    ;;
esac

sudo ufw status verbose
