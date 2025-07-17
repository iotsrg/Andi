#!/bin/bash

# ==============================================
# ULTIMATE ANDROID SECURITY AUDIT SCRIPT 
# ==============================================

timestamp=$(date +%Y%m%d_%H%M%S)
txt_dir="android_audit_output/txt_report_$timestamp"
html_dir="android_audit_output/html_report_$timestamp"
mkdir -p "$txt_dir" "$html_dir"

txt_file="$txt_dir/audit_report.txt"
html_file="$html_dir/audit_report.html"

critical_count=0
warning_count=0
safe_count=0

# HTML header
cat <<EOF > "$html_file"
<html>
<head>
  <title>Android Security Audit Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background: #f4f4f4; padding: 20px; }
    h1, h2, h3 { color: #222; }
    .summary-table { border-collapse: collapse; width: 50%; margin-bottom: 20px; }
    .summary-table th, .summary-table td { border: 1px solid #ccc; padding: 8px; text-align: center; }
    .summary-table th { background-color: #eee; }
    .box { border-radius: 5px; padding: 15px; margin: 10px 0; }
    .safe { background-color: #e0f7e9; border-left: 6px solid #2e7d32; }
    .warning { background-color: #fff8e1; border-left: 6px solid #f9a825; }
    .critical { background-color: #ffebee; border-left: 6px solid #c62828; }
    .info { background-color: #e3f2fd; border-left: 6px solid #1565c0; }
    pre { background: #f9f9f9; padding: 10px; overflow-x: auto; max-height: 250px; font-size: 13px; border: 1px solid #ddd; white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
<h1>Android Security Audit Report</h1>
<p><strong>Generated:</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>
<div style="float:right; width:250px;"><canvas id="summaryChart" width="250" height="250"></canvas></div>
<script>
window.onload = function() {
  var ctx = document.getElementById("summaryChart").getContext("2d");
  window.chart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Safe", "Warnings", "Critical"],
      datasets: [{
        label: "Audit Results",
        data: [SAFE_COUNT, WARNING_COUNT, CRITICAL_COUNT],
        backgroundColor: ["#66bb6a", "#fdd835", "#ef5350"]
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: "top"
        }
      }
    }
  });
}
</script>
EOF

# Device connection check
if ! adb get-state 1>/dev/null 2>&1; then
  echo "[X] No device detected via ADB"
  exit 1
fi

# Device Info
model=$(adb shell getprop ro.product.model | tr -d '\r')
brand=$(adb shell getprop ro.product.brand | tr -d '\r')
manufacturer=$(adb shell getprop ro.product.manufacturer | tr -d '\r')
name=$(adb shell getprop ro.product.name | tr -d '\r')
soc_manufacturer=$(adb shell getprop ro.soc.manufacturer | tr -d '\r')
soc_model=$(adb shell getprop ro.soc.model | tr -d '\r')

echo -e "Device: $model\nBrand: $brand\nManufacturer: $manufacturer\nName: $name\nSoC Manufacturer: $soc_manufacturer\nSoC Model: $soc_model" >> "$txt_file"

cat <<EOF >> "$html_file"
<h2>Device Information</h2><ul>
<li><strong>Model:</strong> $model</li>
<li><strong>Brand:</strong> $brand</li>
<li><strong>Manufacturer:</strong> $manufacturer</li>
<li><strong>Device Name:</strong> $name</li>
<li><strong>SoC Manufacturer:</strong> $soc_manufacturer</li>
<li><strong>SoC Model:</strong> $soc_model</li>
</ul>
EOF

evaluate_check() {
  local category="$1"
  local label="$2"
  local command="$3"
  local safe_pattern="$4"
  local level="$5"
  local desc="$6"

  result=$(adb shell "$command" 2>/dev/null | tr -d '\r')
  [[ -z "$result" ]] && result="[Not Supported]"

  echo -e "\n# ==========================================" >> "$txt_file"
  echo -e "# CATEGORY: $category" >> "$txt_file"
  echo -e "# ==========================================" >> "$txt_file"
  echo -e "Check: $label\nCommand: $command\nDescription: $desc\nResult: $result" >> "$txt_file"

  echo "<h3>$category - $label</h3><p><strong>Command:</strong> $command<br>" >> "$html_file"
  echo "<strong>Description:</strong> $desc<br><strong>Result:</strong><br><pre>$result</pre>" >> "$html_file"

  if [[ "$result" == "[Not Supported]" ]]; then
    echo "Status: INFO" >> "$txt_file"
    echo "<div class='box info'><strong>Status:</strong> INFO</div>" >> "$html_file"
    return
  fi

  if [[ "$result" =~ $safe_pattern ]]; then
    echo "Status: SAFE" >> "$txt_file"
    echo "<div class='box safe'><strong>Status:</strong> SAFE</div>" >> "$html_file"
    ((safe_count++))
  else
    case "$level" in
      "critical")
        echo "Status: CRITICAL" >> "$txt_file"
        echo "<div class='box critical'><strong>Status:</strong> CRITICAL</div>" >> "$html_file"
        ((critical_count++))
        echo "<p><strong>How to Fix:</strong> Refer to the official documentation or disable/uninstall if insecure.</p>" >> "$html_file"
        echo "<p><a href='https://source.android.com/security' target='_blank'>Android Security Guidelines</a></p>" >> "$html_file"
        ;;
      "warning")
        echo "Status: WARNING" >> "$txt_file"
        echo "<div class='box warning'><strong>Status:</strong> WARNING</div>" >> "$html_file"
        ((warning_count++))
        ;;
      *)
        echo "Status: INFO" >> "$txt_file"
        echo "<div class='box info'><strong>Status:</strong> INFO</div>" >> "$html_file"
        ;;
    esac
  fi
}

# Truncated the rest for clarity. You can append your existing checks block below here.

# === SECURITY CHECKS ===

# USER & PRIVACY
evaluate_check "USER & PRIVACY" "Screen Lock" "dumpsys keyguard | grep 'secure=true'" "secure=true" "critical" "Screen lock must be enabled"
evaluate_check "USER & PRIVACY" "Clipboard Access" "cmd clipboard get-primary-clip" "^$" "safe" "Check if clipboard has sensitive data"
evaluate_check "USER & PRIVACY" "Location Services" "settings get secure location_mode" "^3$" "safe" "Mode 3 means high-accuracy enabled"

# BOOT & SECURITY
evaluate_check "BOOT & SECURITY" "Verified Boot State" "getprop ro.boot.verifiedbootstate" "^green$" "critical" "Should be green for locked bootloader"
evaluate_check "BOOT & SECURITY" "Encryption" "getprop ro.crypto.state" "^encrypted$" "critical" "Storage should be encrypted"
evaluate_check "BOOT & SECURITY" "SELinux" "getenforce" "^Enforcing$" "warning" "SELinux should be enforcing"
evaluate_check "BOOT & SECURITY" "OEM Unlock Allowed" "getprop sys.oem_unlock_allowed" "^0$" "critical" "Should be disabled to prevent unlock"
evaluate_check "BOOT & SECURITY" "USB Debugging" "settings get global adb_enabled" "^0$" "warning" "Disable unless needed"
evaluate_check "BOOT & SECURITY" "Unknown Sources" "settings get secure install_non_market_apps" "^0$" "warning" "Should be disabled"
evaluate_check "BOOT & SECURITY" "Device Debuggable" "getprop ro.debuggable" "^0$" "critical" "Production devices must not be debuggable"
evaluate_check "BOOT & SECURITY" "Safe Mode" "getprop persist.sys.safemode" "^0$" "info" "Should not be running in Safe Mode"
evaluate_check "BOOT & SECURITY" "FRP Policy" "settings get global frp_policy" "^1$" "critical" "Factory Reset Protection should be enabled"
evaluate_check "BOOT & SECURITY" "ADB Over Wi-Fi" "settings get global adb_wifi_enabled" "^0$" "warning" "Risky if enabled"

# APPS & RUNTIME
evaluate_check "APPS & RUNTIME" "Root Access (su)" "which su" "^$" "critical" "Check for root binaries"
evaluate_check "APPS & RUNTIME" "Debuggable Apps" "pm list packages -d | wc -l" "^0$" "warning" "Debuggable apps should be 0"
evaluate_check "APPS & RUNTIME" "Accessibility Services" "settings get secure enabled_accessibility_services" "^$" "warning" "Keylogging/clickjacking risk"
evaluate_check "APPS & RUNTIME" "Device Admin Apps" "dumpsys device_policy | grep 'Admin:' | wc -l" "^0$" "warning" "Admins may have control"
evaluate_check "APPS & RUNTIME" "Running Services Count" "dumpsys activity services | grep -E 'package|process' | wc -l" ".*" "info" "Running services on device"

# NETWORK & FILESYSTEM
evaluate_check "NETWORK & FILESYSTEM" "Open Ports" "netstat -tuln | grep -E '0.0.0.0|::'" "^\s*$" "critical" "No open TCP/UDP ports"
evaluate_check "NETWORK & FILESYSTEM" "Open TCP Ports (excluding localhost)" "netstat -lntp | grep -v 127.0.0.1" "^\s*$" "critical" "No open TCP ports externally accessible"
evaluate_check "NETWORK & FILESYSTEM" "Open UDP Ports (excluding localhost)" "netstat -lnup | grep -v 127.0.0.1" "^\s*$" "critical" "No open UDP ports externally accessible"
evaluate_check "NETWORK & FILESYSTEM" "DNS Servers" "getprop net.dns1" ".*" "info" "Check DNS configs"
evaluate_check "NETWORK & FILESYSTEM" "User Certs" "ls /data/misc/user/0/cacerts-added/ | wc -l" "^0$" "warning" "Certs could bypass pinning"
evaluate_check "NETWORK & FILESYSTEM" "SUID/SGID Binaries" "find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null | wc -l" "^0$" "critical" "Privilege escalation vectors"
evaluate_check "NETWORK & FILESYSTEM" "World-Writable Files" "find /data -type f \( -perm -o+w \) -exec ls -l {} \; 2>/dev/null | wc -l" "^0$" "critical" "Unprotected sensitive files"

# ADDITIONAL SECURITY
evaluate_check "ADDITIONAL SECURITY" "Play Protect" "settings get secure package_verifier_enable" "^1$" "warning" "Play Protect should be enabled"
evaluate_check "ADDITIONAL SECURITY" "Security Patch Level" "getprop ro.build.version.security_patch" "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" "info" "Check for latest Android patch level"
evaluate_check "ADDITIONAL SECURITY" "Keyguard Timeout" "settings get secure lock_screen_lock_after_timeout" ".*" "info" "Time delay before screen locks"
evaluate_check "ADDITIONAL SECURITY" "Third-Party App Stores" "pm list packages | grep -E 'amazon|aptoide|getjar'" "^$" "warning" "Avoid non-Google app stores"
evaluate_check "ADDITIONAL SECURITY" "User-installed Apps" "pm list packages -3 | wc -l" ".*" "info" "Check how many user apps installed"
evaluate_check "ADDITIONAL SECURITY" "Logcat Access" "getprop ro.debuggable" "^0$" "critical" "Only system should access logs"
evaluate_check "ADDITIONAL SECURITY" "Unusual Files in /sdcard/" "ls /sdcard/ | grep -Ei '(key|creds|dump|log|backup)'" "^$" "warning" "Sensitive files in user-accessible storage"
evaluate_check "ADDITIONAL SECURITY" "Wi-Fi SSID" "dumpsys netstats | grep -i 'iface=wlan0'" ".*" "info" "Shows current Wi-Fi network"
evaluate_check "ADDITIONAL SECURITY" "Zygote Process Check" "ps | grep zygote" "zygote" "critical" "Zygote process is core to Android app lifecycle"

# APP & SYSTEM INTEGRITY
evaluate_check "APP & SYSTEM INTEGRITY" "AppOps: private-data access" "dumpsys appops | grep -E 'READ_EXTERNAL_STORAGE|ACCESS_FINE_LOCATION'" "mode=ignore" "safe" "Monitor unexpected accesses to sensitive data"
evaluate_check "APP & SYSTEM INTEGRITY" "Security Tools Detected" "pm list packages | grep -E 'org.mobsf|com.offsec.nethunter|de.robv.android.xposed'" "^$" "warning" "Pentest frameworks or hacking tools found"
evaluate_check "APP & SYSTEM INTEGRITY" "Custom CAs Installed" "ls /data/misc/user/0/cacerts-added/ | wc -l" "^0$" "warning" "Custom certs may bypass pinning"
evaluate_check "APP & SYSTEM INTEGRITY" "APK Signature Path Check" "pm list packages -f | grep .apk | head -n 1" "package:" "info" "Checks for valid APK path info"

# === ADVANCED CHECKS ===

# BOOTLOADER & AVB
evaluate_check "BOOT & SECURITY" "Bootloader Locked" "getprop ro.boot.flash.locked" "^1$" "critical" "1 means locked bootloader; 0 means unlocked"
evaluate_check "BOOT & SECURITY" "AVB Version" "getprop ro.boot.avb_version" ".*" "info" "Android Verified Boot version info"

# KERNEL & SYSTEM
evaluate_check "SYSTEM" "Kernel Version" "uname -r" ".*" "info" "Kernel build/version details"
evaluate_check "SYSTEM" "Audit Logs Enabled" "cat /proc/sys/kernel/printk" ".*" "warning" "Non-zero values indicate audit logs may be active"

# PACKAGE AUDIT
evaluate_check "APPS & RUNTIME" "Frida Detected" "pm list packages | grep frida" "^$" "critical" "Frida binary indicates runtime manipulation"
evaluate_check "APPS & RUNTIME" "Magisk Detected" "pm list packages | grep magisk" "^$" "critical" "Magisk can hide root access"
evaluate_check "APPS & RUNTIME" "Xposed Framework" "pm list packages | grep xposed" "^$" "critical" "Xposed framework enables deep system tweaks"
evaluate_check "APPS & RUNTIME" "Unapproved APKs in /data/local/tmp" "ls /data/local/tmp/*.apk" "^ls:.*No such file or directory$" "warning" "Unauthorized sideloading or testing APKs"

# NETWORK ENHANCEMENTS
evaluate_check "NETWORK" "ARP Table Dump" "cat /proc/net/arp" ".*" "info" "Lists resolved ARP IP-MAC mappings"
evaluate_check "NETWORK" "Proxy Configuration" "settings get global http_proxy" "^$" "warning" "Proxy set may indicate MITM or forced redirection"
evaluate_check "NETWORK" "Captive Portal Detection" "settings get global captive_portal_mode" "^1$" "warning" "Should be 1 (default); 0 disables captive portal checks"

# DEVICE SECURITY
evaluate_check "USER & PRIVACY" "Fingerprint / Setup Complete" "settings get secure user_setup_complete" "^1$" "info" "Check if device setup is complete"
evaluate_check "USER & PRIVACY" "Trust Agents Enabled" "settings get secure enabled_trust_agents" "^$" "warning" "May allow unlock bypass via smart lock"

# ROOT TRACE
evaluate_check "ROOT TRACE" "Magisk Binary Presence" "ls /sbin | grep magisk" "^$" "critical" "Indicates root hiding tools like Magisk are installed"
evaluate_check "ROOT TRACE" "su Binary in Common Paths" "ls /system/xbin/su /system/bin/su 2>/dev/null" "^ls:.*No such file or directory$" "critical" "su binary indicates rooted device"

# FILESYSTEM & MOUNTS
evaluate_check "FILESYSTEM" "Mount Points (rw/ro)" "mount | grep -E ' rw| ro'" ".*" "info" "Review mounted partitions and access permissions"
evaluate_check "FILESYSTEM" "tmpfs Usage" "mount | grep tmpfs" ".*" "info" "Shows use of temporary memory file system"

# ADB SECURITY
evaluate_check "ADB SECURITY" "ADB Keys Present" "ls /data/misc/adb/adb_keys" "^ls:.*No such file or directory$" "warning" "Presence of adb_keys may indicate previously trusted host"

# PROCESS SNAPSHOT
evaluate_check "PROCESS SNAPSHOT" "Top 5 Running Processes" "ps | head -n 5" ".*" "info" "Initial list of active processes"

# MALWARE CHECKS
evaluate_check "MALWARE SCAN" "Suspicious Packages" "pm list packages | grep -Ei 'spy|inject|keylog|steal|remote|sms|trojan'" "^$" "critical" "Flag suspicious package names"
evaluate_check "MALWARE SCAN" "Temp APKs in /data/local/tmp" "ls /data/local/tmp/*.apk" "^ls:.*No such file or directory$" "warning" "Hidden payloads or test malware"
evaluate_check "MALWARE SCAN" "Suspicious SDCard Files" "ls /sdcard/ | grep -Ei '(key|creds|dump|log|backup)'" "^$" "warning" "Suspicious files stored externally"
evaluate_check "MALWARE SCAN" "Non-System Apps Count" "pm list packages -3 | wc -l" ".*" "info" "Apps installed outside system image"

# Additional CHECKS
evaluate_check "CIS MODE" "USB File Transfer Disabled" "settings get global usb_mass_storage_enabled" "^0$" "warning" "Should be disabled to block unauthorized USB file access"
evaluate_check "CIS MODE" "Development Settings Disabled" "settings get global development_settings_enabled" "^0$" "warning" "Developer mode should be disabled for production devices"
evaluate_check "CIS MODE" "Wi-Fi Direct Disabled (WFD)" "pm list packages | grep wfd" "^$" "warning" "Wi-Fi Direct (WFD) should be removed if unused"
evaluate_check "CIS MODE" "Auto System Update Enabled" "settings get global auto_update_system" "^1$" "info" "Auto updates improve patch consistency"
evaluate_check "CIS MODE" "Credential Storage Cleared" "ls /data/misc/keystore/user_0" "^ls:.*No such file or directory$" "info" "No residual user credential files"
