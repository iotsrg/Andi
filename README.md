
# ANDI – Android Inspector

[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](#)
[![Status](https://img.shields.io/badge/status-Active-brightgreen)](#)

---

**Andi** is an advanced, fully open-source, automated Android device security audit toolkit built in Bash.  
It combines deep device and OS inspection (CIS, NIST, custom) with beautiful, interactive HTML reporting for security, research, and compliance.

---

## ✨ Features

- **CLI and Modern HTML Dashboard Reporting**  
  - Interactive HTML report with sticky toolbar (search & dark mode)
  - Pie/doughnut chart summary, clean color-coded sections
- **Zero-Blank Device Info**  
  - Robust fallback for device, SoC, and build details (never empty!)
- **Comprehensive Audit Coverage**  
  - User & Privacy, Boot, System/Kernel, Apps, Network, Bluetooth, Filesystem, CIS, NIST 800-121 checks, and more!
- **Portable, Fast, and Read-Only**  
  - Works on all ADB-accessible Androids (root not required for most checks)

---

## 🚀 Quick Start

### 1. **Clone and Download**

```bash
git clone https://github.com/iotsrg/Andi.git
cd Andi
```

Or [**Download andi.sh**](https://github.com/iotsrg/Andi/raw/main/andi.sh) directly:

```bash
curl -LO https://github.com/iotsrg/Andi/raw/main/andi.sh
chmod +x andi.sh
```

### 2. **Requirements**

- **Linux** (tested on Ubuntu, Debian, Fedora, Kali, etc.)
- [**ADB**](https://developer.android.com/tools/adb) (Android Debug Bridge):
  ```bash
  sudo apt install android-tools-adb
  ```
- Android device with **USB debugging enabled**

### 3. **Run the Audit**

```bash
./andi.sh
```

> Output files will be created in `android_audit_output/` as TXT and HTML.

---

## 📊 HTML Report Preview

- **Sticky top toolbar** with instant search and dark/light mode toggle
- **Summary chart** of findings (safe/warning/critical)
- **Device info** (never blank!)
- **All findings**, grouped and color-coded, with code/command/output
- **Live filter/search** for rapid triage

<!-- Optionally add a screenshot if you have one!
<p align="center">
  <img src="assets/andiscan_html_report_screenshot.png" width="800" alt="AndiScan HTML report preview"/>
</p>
-->

---

## 🛡️ Checks Included

| Section         | Checks (Examples)                                | Methods Used               |
| --------------- | ------------------------------------------------ | -------------------------- |
| Device Info     | Model, Brand, Android Version, SoC, etc          | `adb shell getprop ...`    |
| User & Privacy  | Locks, Biometrics, Clipboard, Backups            | Settings & dumpsys queries |
| Boot & Security | Verified Boot, Encryption, Debugging, FRP        | getprop/settings, SELinux  |
| Apps & Runtime  | Root, Debuggable, Device Admins                  | pm, dumpsys                |
| Network/FS      | Open Ports, World-Writable Files, SUID/SGID      | netstat, find, ls, getprop |
| Integrity       | AppOps, Custom CA, APK Signature                 | dumpsys, pm, ls            |
| Kernel/Memory   | ASLR, KASLR, Stack Canary, NX, ROP, SECCOMP      | dmesg, zcat, cat /proc     |
| Bluetooth       | NIST 800-121, encryption, pairing, MAC, profiles | dumpsys, settings          |
| Malware         | Suspicious APKs/Packages/Files                   | pm, ls, grep               |
| CIS Checks      | USB/File Transfer, Dev Settings, Updates         | settings, pm, ls           |
| Root Traces     | su, magisk, xposed detection                     | ls, pm                     |

---

## 📝 Output Files

- **TXT Report**: `android_audit_output/txt_report_<timestamp>/audit_report.txt`
- **HTML Report**: `android_audit_output/html_report_<timestamp>/audit_report.html`

Open the HTML file in any modern browser for full dashboard features!
<img width="1923" height="798" alt="Screenshot from 2025-07-18 16-21-12" src="https://github.com/user-attachments/assets/f0408e72-7da8-497d-85da-66b96c4a1b3a" />

---

## 👨‍💻 Customization

- **Add More Checks**:  
  Insert new `evaluate_check` lines in `andi.sh`:
  ```bash
  evaluate_check "<CATEGORY>" "<LABEL>" "<ADB_COMMAND>" "<SAFE_REGEX>" "<LEVEL>" "<DESCRIPTION>"
  ```
- **Branding/Style**:  
  Edit the CSS/HTML in the script for logos, colors, or layouts.

---

## ❗ Limitations

- Some checks require root or special permissions.
- Device must have ADB debugging enabled.
- Certain very locked-down or vendor-modified devices may return limited data.

---

## 🤝 Contributing

Pull requests welcome!  
Feel free to fork, enhance, or open issues for ideas and bugfixes.

---

## 📜 License

MIT License – see [LICENSE](LICENSE)

---

## 🏷️ Credits

Built with ❤️ by [IoTSRG Team](https://iotsrg.org/) 

---
