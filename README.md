<!--
Language switch:
- English: scroll down
- فارسی: پایین‌تر
-->

# ehiniumNetProbe

**Language**
- [English](#english)
- [فارسی](#فارسی)

---

## English

### ehiniumNetProbe

A small interactive network diagnostic script for Linux servers.
It checks ICMP ping, TCP connect, TCP/UDP echo, TLS handshake, iperf3 throughput, and TCP/TLS soak stability.

Status: **beta (0.1.9)**  

---

### Features
- Interactive menu (Client or Server)
- Test suites:
  - Express Test (all checks)
  - Baseline Connectivity Test (icmp, tcp connect, tcp/udp echo, tls)
  - Throughput Test (iperf3 tcp + udp)
  - Stability Soak Test (tcp + tls repeated checks)
  - Custom Test (tune ports, loops, output format, optional TSV)
- Multiple hosts supported (comma separated) for Baseline and Throughput tests

---

### Requirements

Server mode may use:
- openssl
- iperf3
- socat or python3
- netcat (nc) or python3

Client mode may use:
- ping
- netcat (nc)
- openssl
- iperf3
- socat or python3

Recommended install (Ubuntu):
```bash
sudo apt update
sudo apt install -y iperf3 openssl netcat-openbsd socat
```

---

### Usage

#### Download and run latest version
```bash
curl -fsSL https://raw.githubusercontent.com/ehinium/ehiniumNetProbe/main/ehiniumNetProbe.sh -o ehiniumNetProbe.sh
chmod +x ehiniumNetProbe.sh
./ehiniumNetProbe.sh
```

Run the same command again to update.

---

#### Server mode
Run on the target server:
```bash
sudo ./ehiniumNetProbe.sh
```
Choose **Server** mode and keep it running.

---

#### Client mode
Run from another machine:
```bash
./ehiniumNetProbe.sh
```
Choose **Client** mode and enter target host (or multiple hosts where supported).

---

#### Optional: install globally
```bash
sudo mv ehiniumNetProbe.sh /usr/local/bin/ehiniumNetProbe
sudo chmod +x /usr/local/bin/ehiniumNetProbe
ehiniumNetProbe
```

---

## فارسی

### ehiniumNetProbe

یک اسکریپت سبک و تعاملی برای تست و عیب‌یابی شبکه روی سرورهای لینوکس.
این ابزار موارد زیر را بررسی می‌کند:
Ping (ICMP)، اتصال TCP، Echo در TCP و UDP، هندشیک TLS، تست سرعت iperf3 و تست پایداری (Soak).

وضعیت: **بتا (0.1.9)**  

---

### قابلیت‌ها
- منوی تعاملی (Client یا Server)
- انواع تست:
  - Express Test: همه تست‌ها
  - Baseline Connectivity Test: ping، tcp connect، tcp/udp echo، tls
  - Throughput Test: تست سرعت iperf3 (TCP و UDP)
  - Stability Soak Test: بررسی پایداری اتصال TCP و TLS
  - Custom Test: تنظیم پورت‌ها، تعداد تکرار، فرمت خروجی
- امکان تست چند سرور به‌صورت همزمان (با کاما) در Baseline و Throughput

---

### پیش‌نیازها

در حالت Server ممکن است نیاز باشد:
- openssl
- iperf3
- socat یا python3
- netcat (nc) یا python3

در حالت Client ممکن است نیاز باشد:
- ping
- netcat (nc)
- openssl
- iperf3
- socat یا python3

نصب پیشنهادی در اوبونتو:
```bash
sudo apt update
sudo apt install -y iperf3 openssl netcat-openbsd socat python3
```

---

### نحوه استفاده

#### دانلود و اجرای آخرین نسخه
```bash
curl -fsSL https://raw.githubusercontent.com/ehinium/ehiniumNetProbe/main/ehiniumNetProbe.sh -o ehiniumNetProbe.sh
chmod +x ehiniumNetProbe.sh
./ehiniumNetProbe.sh
```

برای بروزرسانی، همین دستور را دوباره اجرا کنید.

---

#### حالت Server
روی سرور مقصد اجرا کنید:
```bash
sudo ./ehiniumNetProbe.sh
```
حالت **Server** را انتخاب کرده و اسکریپت را روشن نگه دارید.

---

#### حالت Client
روی سرور یا سیستم دیگر اجرا کنید:
```bash
./ehiniumNetProbe.sh
```
حالت **Client** را انتخاب کرده و آدرس سرور (یا چند آدرس) را وارد کنید.

---

#### نصب سراسری (اختیاری)
```bash
sudo mv ehiniumNetProbe.sh /usr/local/bin/ehiniumNetProbe
sudo chmod +x /usr/local/bin/ehiniumNetProbe
ehiniumNetProbe
```
