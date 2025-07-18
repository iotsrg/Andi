# 🤖 Andi - Android Inspector 

**Andi** is a no-root, portable Android security auditing tool that inspects Android smartphones, tablets, and smart devices over ADB.

[![Platform](https://img.shields.io/badge/platform-Android-blue)](https://developer.android.com/)
[![ADB Required](https://img.shields.io/badge/ADB-Required-green)](https://developer.android.com/studio/command-line/adb)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Shell Script](https://img.shields.io/badge/language-Bash-lightgrey)](https://www.gnu.org/software/bash/)
[![Status](https://img.shields.io/badge/status-Production--Ready-brightgreen)]()

A powerful and extensible **Android Security Auditing Script** designed for penetration testers, red teams, forensic analysts, and IoT security professionals.

This tool inspects **device security posture** using ADB with **zero modifications or app installations**.

---

## ✨ Features

- 📱 Device & SoC fingerprinting
- 🔐 Bootloader, encryption, and Verified Boot checks
- ⚠️ Root, Magisk, Xposed & Frida detection
- 🧠 App runtime configuration & dangerous permission checks
- 🌐 Network, proxy, open port & captive portal detection
- 🗂️ Filesystem audit for `SUID`, world-writable & `tmpfs`
- 🔒 SELinux, ADB Keys, USB Debugging, Safe Mode analysis
- 📈 Auto-generated TXT and HTML reports with chart visualizations

---

## 🚀 Usage

```bash

```

> 🔌 Make sure a device is connected and authorized via ADB before running.

---

## 📂 Output

- All reports are stored under the `android_audit_output/` folder:
  - ✅ `txt_report_<timestamp>/audit_report.txt`
  - 🌐 `html_report_<timestamp>/audit_report.html` (with Chart.js visualization)

---

## 📋 Example Output (HTML)

![audit-html-preview](https://i.imgur.com/XvW7qJd.png)

---

## 📚 Checks Performed

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

## 🔒 Security Philosophy

This tool follows the **non-invasive, read-only** principle. It does not install apps, write files to the device, or require root unless explicitly requested.

---

## 🧠 Ideal Use Cases

- Android smartphone audits
- IoT device Android firmware testing
- Pre-deployment enterprise validation
- Mobile app security posture verification

---

## 🛠 Requirements

- `adb` installed and accessible from terminal
- Bash-compatible environment (Linux/macOS/WSL)
- Android device with USB debugging enabled

---

## 🧩 Optional Enhancements (Planned)

- [ ] Frida-assisted runtime fuzzing
- [ ] OTA/bootloader image comparison (offline)
- [ ] PDF report generation

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

> _“If you can't audit it, you can't trust it.” — Unknown_
