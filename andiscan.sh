#!/bin/bash

# ==============================================
# ULTIMATE ANDROID SECURITY AUDIT SCRIPT (v5.0)
# Combines extended checks from final.sh and CLI polish from improved version
# ==============================================

# Output file and counters
output_file="android_security_audit_$(date +%Y%m%d_%H%M%S).txt"
critical_count=0
warning_count=0
safe_count=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

# ADB Check
if ! adb get-state 1>/dev/null 2>&1; then
    echo -e "${RED}[X] No device detected via ADB${NC}"
    exit 1
fi

# Init
echo -e "${CYAN}=== ANDROID SECURITY AUDIT REPORT ===${NC}" > "$output_file"
echo -e "Generated: $(date '+%Y-%m-%d %H:%M:%S')" >> "$output_file"
echo -e "Device: $(adb shell getprop ro.product.model)" >> "$output_file"
echo -e "========================================\n" >> "$output_file"

echo -e "\n${BLUE}${BOLD}[*] DEVICE INFORMATION${NC}${NORMAL}"
adb shell getprop | grep -E 'ro.product.(brand|manufacturer|model|name)' >> "$output_file"



# Function to evaluate checks
evaluate_check() {
  local label="$1"
  local command="$2"
  local safe_pattern="$3"
  local level="$4"
  local desc="$5"

  result=$(adb shell "$command" 2>/dev/null | tr -d '\r' || echo "[Not Supported]")
  echo -e "[+] $label:" >> "$output_file"
  echo -e "Description: $desc" >> "$output_file"
  echo -e "Command: $command" >> "$output_file"
  echo -e "Result: $result\n" >> "$output_file"

  if [[ "$result" =~ $safe_pattern ]]; then
    echo -e "[*] $label: $result -> ${GREEN}SAFE${NC}"
    ((safe_count++))
  else
    case "$level" in
      "critical") echo -e "[*] $label: $result -> ${RED}CRITICAL${NC}"; ((critical_count++)) ;;
      "warning") echo -e "[*] $label: $result -> ${YELLOW}WARNING${NC}"; ((warning_count++)) ;;
      *) echo -e "[*] $label: $result -> ${NC}INFO${NC}" ;;
    esac
  fi
}

# --- USER & PRIVACY ---
echo -e "\n${BLUE}${BOLD}[*] USER & PRIVACY${NC}${NORMAL}"
evaluate_check "Screen Lock" "dumpsys keyguard | grep 'secure=true'" "secure=true" "critical" "Screen lock must be enabled"
evaluate_check "Clipboard Access" "cmd clipboard get-primary-clip" "^$" "safe" "Check if clipboard has sensitive data"
evaluate_check "Location Services" "settings get secure location_mode" "3" "safe" "Mode 3 means high-accuracy enabled"

# --- BOOT & SECURITY ---
echo -e "\n${BLUE}${BOLD}[*] BOOT & SECURITY${NC}${NORMAL}"
evaluate_check "Verified Boot State" "getprop ro.boot.verifiedbootstate" "green" "critical" "Should be green for locked bootloader"
evaluate_check "Encryption" "getprop ro.crypto.state" "encrypted" "critical" "Storage should be encrypted"
evaluate_check "SELinux" "getenforce" "Enforcing" "warning" "SELinux should be enforcing"
evaluate_check "OEM Unlock Allowed" "getprop sys.oem_unlock_allowed" "0" "critical" "Should be disabled to prevent unlock"
evaluate_check "USB Debugging" "settings get global adb_enabled" "0" "warning" "Disable unless needed"
evaluate_check "Unknown Sources" "settings get secure install_non_market_apps" "0" "warning" "Should be disabled"
evaluate_check "Device Debuggable" "getprop ro.debuggable" "0" "critical" "Production devices must not be debuggable"
evaluate_check "Safe Mode" "getprop persist.sys.safemode" "0" "info" "Should not be running in Safe Mode"
evaluate_check "FRP Policy" "settings get global frp_policy" "1" "critical" "Factory Reset Protection should be enabled"
evaluate_check "ADB Over Wi-Fi" "settings get global adb_wifi_enabled" "0" "warning" "Risky if enabled"

# --- APPS & RUNTIME ---
echo -e "\n${BLUE}${BOLD}[*] APPS & RUNTIME${NC}${NORMAL}"
evaluate_check "Root Access (su)" "which su" "^$" "critical" "Check for root binaries"
evaluate_check "Debuggable Apps" "pm list packages -d | wc -l" "0" "warning" "Debuggable apps should be 0"
evaluate_check "Accessibility Services" "settings get secure enabled_accessibility_services" "^$" "warning" "Keylogging/clickjacking risk"
evaluate_check "Device Admin Apps" "dumpsys device_policy | grep 'Admin:' | wc -l" "0" "warning" "Admins may have control"
evaluate_check "Running Services Count" "dumpsys activity services | grep -E 'package|process' | wc -l" ".*" "info" "Running services on device"

# --- NETWORK & FILESYSTEM ---
echo -e "\n${BLUE}${BOLD}[*] NETWORK & FILESYSTEM${NC}${NORMAL}"
evaluate_check "Open Ports" "netstat -tuln | grep -E '0.0.0.0|::' | wc -l" "0" "critical" "No open TCP/UDP ports"
evaluate_check "DNS Servers" "getprop net.dns1" ".*" "info" "Check DNS configs"
evaluate_check "User Certs" "ls /data/misc/user/0/cacerts-added/ | wc -l" "0" "warning" "Certs could bypass pinning"
evaluate_check "SUID/SGID Binaries" "find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {{}} \; 2>/dev/null | wc -l" "0" "critical" "Privilege escalation vectors"
evaluate_check "World-Writable Files" "find /data -type f \( -perm -o+w \) -exec ls -l {{}} \; 2>/dev/null | wc -l" "0" "critical" "Unprotected sensitive files"


# --- ADDITIONAL SECURITY CHECKS ---

echo -e "\n${BLUE}${BOLD}[*] ADDITIONAL SECURITY CHECKS${NC}${NORMAL}"

evaluate_check "Play Protect" "settings get secure package_verifier_enable" "1" "warning" "Play Protect should be enabled"
evaluate_check "Security Patch Level" "getprop ro.build.version.security_patch" "[0-9]{4}-[0-9]{2}-[0-9]{2}" "info" "Check for latest Android patch level"
evaluate_check "Keyguard Timeout" "settings get secure lock_screen_lock_after_timeout" ".*" "info" "Time delay before screen locks"

evaluate_check "Third-Party App Stores" "pm list packages | grep -E 'amazon|aptoide|getjar'" "^$" "warning" "Avoid non-Google app stores"
evaluate_check "User-installed Apps" "pm list packages -3 | wc -l" ".*" "info" "Check how many user apps installed"

evaluate_check "Logcat Access" "getprop ro.debuggable" "0" "critical" "Only system should access logs"
evaluate_check "Unusual Files in /sdcard/" "ls /sdcard/ | grep -Ei '(key|creds|dump|log|backup)'" "^$" "warning" "Sensitive files in user-accessible storage"

evaluate_check "VPN Active" "dumpsys connectivity | grep -i vpn" ".*" "info" "Indicates if VPN is running"
evaluate_check "Wi-Fi SSID" "dumpsys netstats | grep -i 'iface=wlan0'" ".*" "info" "Shows current Wi-Fi network"

evaluate_check "Zygote Process Check" "ps | grep zygote" "zygote" "critical" "Zygote process is core to Android app lifecycle"


# --- APP & SYSTEM INTEGRITY CHECKS (ADB-BASED) ---

echo -e "\n${BLUE}${BOLD}[*] APP & SYSTEM INTEGRITY CHECKS${NC}${NORMAL}"

# AppOps for private-data access (Android 11+)
evaluate_check "AppOps: private-data access" "dumpsys appops | grep -E 'READ_EXTERNAL_STORAGE|ACCESS_FINE_LOCATION'" "^$" "warning" "Monitor unexpected accesses to sensitive data"

# Known Pentest Tools Detected
evaluate_check "Security Tools Detected" "pm list packages | grep -E 'org.mobsf|com.offsec.nethunter|de.robv.android.xposed'" "^$" "warning" "Pentest frameworks or hacking tools found"

# Custom CAs installed
evaluate_check "Custom CAs Installed" "ls /data/misc/user/0/cacerts-added/ | wc -l" "0" "warning" "Custom certs may bypass pinning"

# APK Signature Path Validity (basic)
evaluate_check "APK Signature Path Check" "pm list packages -f | grep .apk | head -n 1" "package:" "info" "Checks for valid APK path info"

# --- SUMMARY ---
echo -e "\n===== AUDIT SUMMARY ====="
echo -e "${RED}Critical Issues: $critical_count${NC}"
echo -e "${YELLOW}Warnings: $warning_count${NC}"
echo -e "${GREEN}Safe Checks: $safe_count${NC}"
echo -e "📄 Report saved to: $output_file"
