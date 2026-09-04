# ESP32-C3 WiFi Sniffer / 无线嗅探与安全监测

基于合宙 CORE-ESP32-C3 核心板（ESP32-C3, 4MB flash, rev v0.4）开发的 WiFi 嗅探器与无线环境监测固件。

> 呼号：BI4IVE ｜ 个人无线电/数码折腾项目
> 板端 MAC: 14:63:93:fa:52:3c ｜ 端口 COM4 ｜ FlashMode DIO 40MHz

## 版本演进

| 版本 | 源码 | 固件 (merged.bin) | 核心能力 |
|------|------|-------------------|----------|
| v1 (dio40m) | `firmware/v1_sniffer_dio40m/sniffer_c3.ino` | `releases/sniffer_c3_dio_40m.merged.bin` | 被动嗅探原始帧、基础 AP/设备发现 |
| v1 AP 版 | - | `releases/sniffer_c3_dio_40m_ap.merged.bin` | v1 + 内置 AP 热点 |
| v2 (AP+LAN) | `firmware/v2_ap_lan/sniffer_c3_ap.ino` | `releases/sniffer_c3_ap_v2_lan.merged.bin` | 热点配网（Web 配网）+ 主动扫描 + 局域网 Web 控制台 |
| v2.1 (Security) | `firmware/v21_security/sniffer_c3_v21.ino` | `releases/sniffer_c3_v21_security.merged.bin` | + 加密方式检测 + 设备命名/陌生人告警 + Deauth 风暴检测 |

## 技术栈

- 编译：arduino-cli 1.5.1 + esp32 core 2.0.17 (IDF 4.4)
- fqbn: `esp32:esp32:esp32c3:CPUFreq=160,FlashFreq=40,FlashMode=dio,FlashSize=4M`
- 烧录：esptool 4.5.1, COM4 @ 460800 baud, merged.bin 从 0x0 写入
- 运行环境：Windows / PowerShell / Python 3.11.8

## 烧录方法

```powershell
# 生成 merged.bin（如已提供则跳过）
esptool.exe --chip esp32c3 merge_bin -o merged.bin 0x0 bootloader.bin 0x8000 partitions.bin 0xe000 boot_app0.bin 0x10000 firmware.bin

# 烧录
esptool.exe --chip esp32c3 --port COM4 --baud 460800 write_flash 0x0 merged.bin
```

## 目录

- `firmware/` — 各版本 Arduino 源码 (.ino)
- `releases/` — 编译产物 merged.bin（可直接烧录）
