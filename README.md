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
| v2.3 (Quality) | `firmware/v23_quality/sniffer_c3_v23.ino` | `releases/sniffer_c3_v23_ui.merged.bin` | + 信号打点采样与评级（均值/最差/最好/标准差/中断率/点位名）+ CSV 导出与历史比对 + 主动测速（STA 连被测 WiFi，TCP 握手延迟/丢包统计，测后自动恢复局域网） |
| v2.2 (Ops) | `firmware/v22_ops/sniffer_c3_v22.ino` | `releases/sniffer_c3_v22_ops.merged.bin` | 完整运维版：信道体检 + 非法/钓鱼 AP 检测 + OUI 厂商识别 + 关联拓扑 + 实时流量图表 + 事件时间线 + 设备清点比对 + Beacon 消失监控 + pcap 导出 + REST JSON API + Prometheus 指标 + Webhook 推送 |

## v2.3 信号质量功能

- **信号打点**：指定 BSSID 采样指定秒数，输出均值/最差/最好 RSSI、标准差、中断率与评级（优/良/中/差/极差），可带点位名称，历史存 12 槽循环
- **历史记录与 CSV**：/qpoints 查看全部打点（含距今时间、评级），一键导出 UTF-8 BOM CSV（时间,点位,BSSID,SSID,信道,样本,中断次数,均值,最差,最好,标准差,评级）
- **主动测速**：板子切 STA 连接被测 WiFi（AP 热点 ESP32C3-Sniffer 全程保持），解析网关 IP 后对网关 80/443 端口 TCP 握手计时，统计平均延迟/丢包/当前 RSSI/信道，测试结束后自动恢复配网局域网 WiFi
- **UI 改版**：统一顶部品牌栏 + Tabs 导航 + 卡片面板布局 + 统一页脚，全站 8 页面一致风格

## v2.2 功能清单

- **信道体检**：全信道 2.4G 占用扫描，按信道聚合 AP 数量/RSSI/流量，生成体检报告（HTML 与 JSON）
- **非法/钓鱼 AP 检测**：SSID 匹配信任列表但 BSSID 不在白名单即标记 rogue，去重告警
- **OUI 厂商识别**：内置常见 OUI 前缀表，自动识别 AP/设备的厂商
- **设备命名与清点**：手动命名（持久化）、未命名设备陌生人告警、设备在线/掉线跟踪
- **Beacon 消失监控**：信任 AP 超时未收到 Beacon 即产生离线事件
- **Deauth 风暴检测**：单 MAC 每秒 Deauth 超阈值告警
- **事件时间线**：环形缓冲事件记录（系统/陌生人/钓鱼/风暴/离线），网页与 JSON 均可查看
- **关联拓扑**：通过关联帧/数据帧推断 STA-AP 关联关系，提供 /api/topo
- **实时流量图表**：每秒收包速率环形历史（/api/hist），前端自动刷新图表
- **pcap 导出**：按原始帧缓存（滚动环形缓冲），支持 /dump 流式下载 pcap 文件
- **REST JSON API**：/api/stats、/api/aps、/api/devs、/api/events、/api/survey、/api/topo、/api/hist、/api/metrics
- **Prometheus 指标**：/metrics 输出标准 Prometheus 文本格式
- **Webhook 推送**：事件发生时 POST JSON 到自定义 URL（带去重与限流），支持测试按钮
- **Web 控制台**：热点配网 + 局域网 Web 页面（状态/AP 列表/设备列表/事件/体检报告/配置）

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
