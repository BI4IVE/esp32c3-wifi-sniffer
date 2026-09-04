/*
 * ESP32-C3 WiFi 被动嗅探器
 * - 轮换扫描 2.4G 信道 (1~13)
 * - 收集 Beacon：附近 AP 名称/地址/信道/信号
 * - 收集 Probe Request 等：附近活跃设备（谁在找 WiFi）
 * - 板载 LED 闪烁表示工作状态
 * - 浏览器打开本机 IP 实时查看
 * 仅供学习/自家网络调试使用，请勿用于非法监听。
 */
#include <WiFi.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <vector>
#include <cstring>
#include <stdio.h>

// ================= 可调参数 =================
#define HOP_INTERVAL_MS   300     // 信道轮换间隔
#define DEVICE_TIMEOUT_MS 90000   // 设备静默 90s 后移除
#define AP_TIMEOUT_MS     120000  // AP 静默 120s 后移除
#define MAX_APS           48
#define MAX_DEVS          64

WebServer server(80);

struct ApInfo {
  uint8_t bssid[6];
  char ssid[33];
  int8_t  channel;
  int8_t  rssi;
  uint32_t packets;
  uint32_t lastSeen;
};
struct DevInfo {
  uint8_t mac[6];
  int8_t  rssi;
  uint32_t packets;
  uint32_t lastSeen;
};

std::vector<ApInfo>  aps;
std::vector<DevInfo> devs;
volatile uint32_t totalPackets = 0;
volatile uint32_t mgmtCount = 0;
volatile uint32_t dataCount = 0;
uint8_t  curChannel = 1;
bool     autoHop = false;   // true=全信道轮换(AP可能掉线)；false=固定当前信道
uint32_t lastHop = 0;
uint32_t lastStat = 0;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

#ifdef LED_BUILTIN
uint32_t lastLedBlink = 0;
#endif

String macStr(const uint8_t* m) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(buf);
}
bool sameMac(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }
bool isIgnorable(const uint8_t* a) {
  for (int i = 0; i < 6; i++)
    if (a[i] != 0xFF && a[i] != 0x00) return false;
  return true; // 全 FF 或全 00
}

bool isKnownAP(const uint8_t* mac) {
  for (size_t i = 0; i < aps.size(); i++)
    if (sameMac(aps[i].bssid, mac)) return true;
  return false;
}

void addAP(const uint8_t* bssid, const char* ssid, uint8_t ch, int8_t rssi) {
  for (size_t i = 0; i < aps.size(); i++) {
    if (sameMac(aps[i].bssid, bssid)) {
      aps[i].rssi = rssi;
      aps[i].channel = ch;
      aps[i].packets++;
      aps[i].lastSeen = millis();
      if (ssid[0]) { strncpy(aps[i].ssid, ssid, 32); aps[i].ssid[32] = 0; }
      return;
    }
  }
  if (aps.size() >= MAX_APS) return;
  ApInfo a;
  memset(&a, 0, sizeof(a));
  memcpy(a.bssid, bssid, 6);
  strncpy(a.ssid, ssid, 32);
  a.ssid[32] = 0;
  a.channel = ch;
  a.rssi = rssi;
  a.packets = 1;
  a.lastSeen = millis();
  aps.push_back(a);
}

void touchDev(const uint8_t* mac, int8_t rssi) {
  if (isIgnorable(mac) || (mac[0] & 0x01)) return; // 广播/组播/零地址跳过
  for (size_t i = 0; i < devs.size(); i++) {
    if (sameMac(devs[i].mac, mac)) {
      devs[i].rssi = rssi;
      devs[i].packets++;
      devs[i].lastSeen = millis();
      return;
    }
  }
  if (devs.size() >= MAX_DEVS) return;
  DevInfo d;
  memset(&d, 0, sizeof(d));
  memcpy(d.mac, mac, 6);
  d.rssi = rssi;
  d.packets = 1;
  d.lastSeen = millis();
  devs.push_back(d);
}

// 802.11 混杂模式收包回调
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t* ctrl = &pkt->rx_ctrl;
  uint8_t* f = pkt->payload;
  int len = ctrl->sig_len;
  if (len < 24) return;

  totalPackets++;
  uint16_t fc = f[0] | (f[1] << 8);
  uint8_t ft = (fc >> 2) & 0x03;   // 0=mgmt 1=ctl 2=data
  uint8_t st = (fc >> 4) & 0x0F;
  const uint8_t* addr2 = f + 10;   // 发送者

  portENTER_CRITICAL(&mux);

  if (ft == 0) { // 管理帧
    mgmtCount++;
    if (st == 8) { // Beacon -> 附近 AP
      char ssid[33] = {0};
      int off = 36; // 24 头 + 12 固定
      while (off + 2 <= len) {
        uint8_t tag = f[off];
        uint8_t tlen = f[off + 1];
        if (off + 2 + tlen > len) break;
        if (tag == 0) {
          int n = tlen < 32 ? tlen : 32;
          memcpy(ssid, f + off + 2, n);
          ssid[n] = 0;
          break;
        }
        off += 2 + tlen;
      }
      addAP(addr2, ssid, ctrl->channel, ctrl->rssi);
    } else if (st == 5 || st == 1 || st == 3) {
      // Probe Response / (Re)Assoc Response：发送者是 AP
      addAP(addr2, "", ctrl->channel, ctrl->rssi);
    } else {
      // Probe Request 等：客户端活动
      if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi);
    }
  } else if (ft == 2) { // 数据帧：双方都在通信
    dataCount++;
    if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi);
  }

  portEXIT_CRITICAL(&mux);
}

// ================= 网页 =================
String buildHTML() {
  String html = R"HTML(<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>ESP32-C3 WiFi Sniffer</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1220;color:#d8e0f0;margin:0;padding:16px}
h1{font-size:20px;color:#7ee787}.dim{color:#8b93a8;font-size:12px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.card{background:#1a1f33;border-radius:10px;padding:10px 16px;min-width:90px}
.card b{display:block;font-size:22px;color:#ffd166}
.card span{font-size:11px;color:#8b93a8}
table{width:100%;border-collapse:collapse;font-size:13px;background:#141828;border-radius:10px;overflow:hidden}
th{background:#202642;color:#9aa7c7;text-align:left;padding:6px 10px;font-weight:600}
td{padding:6px 10px;border-top:1px solid #1f2440}
tr:hover td{background:#1a2035}
.rssi-good{color:#7ee787}.rssi-mid{color:#ffd166}.rssi-bad{color:#ff7b72}
h2{font-size:15px;margin:18px 0 8px;color:#a5b4fc}
</style></head><body>
<h1>📡 ESP32-C3 WiFi Sniffer</h1>
<div class="dim">被动监听模式 · 仅供学习调试</div>
<div class="cards">
<div class="card"><b>)HTML";
  char tmp[32];
  snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)totalPackets);
  html += tmp;
  html += "</b><span>收包总数</span></div><div class=\"card\"><b>";
  snprintf(tmp, sizeof(tmp), "%d", curChannel);
  html += tmp;
  html += "</b><span>当前信道</span></div><div class=\"card\"><b>";
  snprintf(tmp, sizeof(tmp), "%d", (int)aps.size());
  html += tmp;
  html += "</b><span>附近WiFi</span></div><div class=\"card\"><b>";
  snprintf(tmp, sizeof(tmp), "%d", (int)devs.size());
  html += tmp;
  html += "</b><span>活跃设备</span></div></div>";

  // AP 表
  html += "<h2>附近 WiFi（AP）</h2><table><tr><th>SSID</th><th>BSSID</th><th>信道</th><th>信号</th><th>包数</th></tr>";
  for (size_t i = 0; i < aps.size(); i++) {
    String s = aps[i].ssid[0] ? String(aps[i].ssid) : String("(隐藏/未知)");
    if (s.length() == 0 || (unsigned char)s[0] == 0xFF) s = "(隐藏/未知)";
    html += "<tr><td>" + s + "</td><td class=\"dim\">" + macStr(aps[i].bssid) + "</td><td>" + aps[i].channel + "</td><td class=\"";
    html += (aps[i].rssi >= -60 ? "rssi-good" : (aps[i].rssi >= -75 ? "rssi-mid" : "rssi-bad"));
    html += "\">" + String(aps[i].rssi) + " dBm</td><td>" + String(aps[i].packets) + "</td></tr>";
  }
  html += "</table>";

  // 设备表
  html += "<h2>活跃设备（探测/通信中的网卡）</h2><table><tr><th>MAC</th><th>信号</th><th>包数</th><th>最近活跃</th></tr>";
  for (size_t i = 0; i < devs.size(); i++) {
    uint32_t age = millis() - devs[i].lastSeen;
    html += "<tr><td>" + macStr(devs[i].mac) + "</td><td class=\"";
    html += (devs[i].rssi >= -60 ? "rssi-good" : (devs[i].rssi >= -75 ? "rssi-mid" : "rssi-bad"));
    html += "\">" + String(devs[i].rssi) + " dBm</td><td>" + String(devs[i].packets) + "</td><td class=\"dim\">";
    if (age < 5000) html += "刚刚";
    else if (age < 30000) html += String(age / 1000) + " 秒前";
    else html += String(age / 60000) + " 分钟前";
    html += "</td></tr>";
  }
  html += "</table></body></html>";
  return html;
}

void handleRoot()  { server.send(200, "text/html; charset=utf-8", buildHTML()); }

void handleSet() {
  if (server.hasArg("ch")) {
    int ch = server.arg("ch").toInt();
    if (ch == 0) {
      autoHop = true;
      server.send(200, "text/plain", "auto hop ON (AP may disconnect)");
      return;
    }
    if (ch >= 1 && ch <= 13) {
      autoHop = false;
      curChannel = (uint8_t)ch;
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      server.send(200, "text/plain", "fixed ch=" + String(ch));
      return;
    }
  }
  server.send(400, "text/plain", "usage: /set?ch=1..13 (fixed) or /set?ch=0 (auto hop)");
}

void handleNotFound() { server.send(404, "text/plain", "Not Found"); }

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nESP32-C3 WiFi Sniffer starting...");

#ifdef LED_BUILTIN
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);
#endif

  aps.reserve(MAX_APS);
  devs.reserve(MAX_DEVS);

  // 开热点(AP)供浏览器查看：默认固定信道1保证连接稳定，/set?ch=0 可开全信道轮换
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("ESP32C3-Sniffer");
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  server.on("/", handleRoot);
  server.on("/set", handleSet);
  server.onNotFound(handleNotFound);
  server.begin();

  Serial.print("Open http://");
  Serial.print(WiFi.softAPIP());
  Serial.println(" in your browser");
  Serial.println("SSID: ESP32C3-Sniffer (no password)");
}

void loop() {
  server.handleClient();

  // 信道轮换（默认固定信道1保证AP连接稳定；/set?ch=0 开启全信道轮换）
  if (autoHop && millis() - lastHop >= HOP_INTERVAL_MS) {
    lastHop = millis();
    curChannel++;
    if (curChannel > 13) curChannel = 1;
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  // 清理超时设备/AP
  if (millis() - lastStat >= 5000) {
    lastStat = millis();
    uint32_t now = millis();
    portENTER_CRITICAL(&mux);
    for (size_t i = aps.size(); i-- > 0;)
      if (now - aps[i].lastSeen > AP_TIMEOUT_MS) aps.erase(aps.begin() + i);
    for (size_t i = devs.size(); i-- > 0;)
      if (now - devs[i].lastSeen > DEVICE_TIMEOUT_MS) devs.erase(devs.begin() + i);
    portEXIT_CRITICAL(&mux);

    // 串口摘要
    char buf[80];
    snprintf(buf, sizeof(buf), "[%02d] pkts=%lu mgmt=%lu data=%lu AP=%d dev=%d ip=%s",
             curChannel, (unsigned long)totalPackets, (unsigned long)mgmtCount,
             (unsigned long)dataCount, (int)aps.size(), (int)devs.size(),
             WiFi.softAPIP().toString().c_str());
    Serial.println(buf);
  }

#ifdef LED_BUILTIN
  // LED 快闪 = 抓包中
  if (millis() - lastLedBlink >= 500) {
    lastLedBlink = millis();
    digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
  }
#endif
}
