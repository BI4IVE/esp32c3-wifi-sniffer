/*
 * ESP32-C3 WiFi 嗅探器 v2（自家网络调试学习用）
 * - AP 热点: ESP32C3-Sniffer (无密码) -> http://192.168.4.1 管理入口
 * - 可选 STA 连自家路由器 -> 局域网 IP 访问（/config 网页配网，掉电记忆）
 * - 被动嗅探：Beacon 收集附近 AP；Probe Request/数据帧收集活跃设备
 * - 主动扫描：周期发空 SSID Probe Request，隐藏 SSID 的 AP 也会现形
 * - 局域网模式：信道锁定路由器信道；纯热点模式可固定信道或全信道轮换
 * 仅供自家网络学习调试使用，请勿用于非法监听。
 */
#include <WiFi.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <vector>
#include <cstring>
#include <stdio.h>

// ================= 可调参数 =================
#define HOP_INTERVAL_MS   300     // 信道轮换间隔（仅非 STA 连接时有效）
#define PROBE_INTERVAL_MS 15000   // 主动扫描间隔
#define DEVICE_TIMEOUT_MS 90000   // 设备静默 90s 后移除
#define AP_TIMEOUT_MS     120000  // AP 静默 120s 后移除
#define MAX_APS           48
#define MAX_DEVS          64
#define AP_SSID           "ESP32C3-Sniffer"

WebServer server(80);
Preferences prefs;

struct ApInfo {
  uint8_t bssid[6];
  char ssid[33];
  int8_t  channel;
  int8_t  rssi;
  uint32_t packets;
  uint32_t lastSeen;
  bool viaProbe;   // true=由主动扫描(Probe Response)挖出
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
bool     autoHop = false;    // 全信道轮换（连上局域网后自动关闭）
bool     activeScan = true;  // 主动扫描开关
uint32_t lastHop = 0;
uint32_t lastProbe = 0;
uint32_t lastStat = 0;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

bool savedSSIDMode();
volatile uint32_t totalProbes = 0;

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

// 从 802.11 管理帧尾部 tagged params 解析 SSID (tag=0)
String parseSSID(const uint8_t* f, int len) {
  int off = 36; // 24 头 + 12 固定域
  while (off + 2 <= len) {
    uint8_t tag = f[off];
    uint8_t tlen = f[off + 1];
    if (off + 2 + tlen > len) break;
    if (tag == 0) {
      int n = tlen < 32 ? tlen : 32;
      return String((const char*)(f + off + 2), n);
    }
    off += 2 + tlen;
  }
  return String();
}

void addAP(const uint8_t* bssid, const char* ssid, uint8_t ch, int8_t rssi, bool viaProbe) {
  for (size_t i = 0; i < aps.size(); i++) {
    if (sameMac(aps[i].bssid, bssid)) {
      aps[i].rssi = rssi;
      aps[i].channel = ch;
      aps[i].packets++;
      aps[i].lastSeen = millis();
      if (viaProbe) aps[i].viaProbe = true;           // 一旦主动挖出永久标记
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
  a.viaProbe = viaProbe;
  aps.push_back(a);
}

void touchDev(const uint8_t* mac, int8_t rssi) {
  if (isIgnorable(mac) || (mac[0] & 0x01)) return;
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
  uint8_t ft = (fc >> 2) & 0x03;
  uint8_t st = (fc >> 4) & 0x0F;
  const uint8_t* addr2 = f + 10;

  portENTER_CRITICAL(&mux);

  if (ft == 0) { // 管理帧
    mgmtCount++;
    if (st == 8) { // Beacon -> 附近 AP
      String ssid = parseSSID(f, len);
      char tmp[33]; ssid.toCharArray(tmp, 33);
      addAP(addr2, tmp, ctrl->channel, ctrl->rssi, false);
    } else if (st == 5 || st == 1 || st == 3) {
      // Probe Response / (Re)Assoc Response：主动扫描挖出的 AP 带真名
      String ssid = parseSSID(f, len);
      char tmp[33]; ssid.toCharArray(tmp, 33);
      addAP(addr2, tmp, ctrl->channel, ctrl->rssi, true);
    } else {
      if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi);
    }
  } else if (ft == 2) { // 数据帧
    dataCount++;
    if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi);
  }

  portEXIT_CRITICAL(&mux);
}

// 主动扫描：发一个空 SSID 的 Probe Request 广播帧（等价手机找 WiFi）
void sendProbeRequest() {
  uint8_t frame[26] = {0};
  frame[0] = 0x40; frame[1] = 0x00;          // mgmt / Probe Request
  memset(frame + 4, 0xFF, 6);                // DA 广播
  uint8_t mac[6] = {0};
  esp_wifi_get_mac(WIFI_IF_AP, mac);         // 用 AP 接口 MAC
  memcpy(frame + 10, mac, 6);                // SA
  memset(frame + 16, 0xFF, 6);               // BSSID 广播
  // frame[22..23] 序列号交给 en_sys_seq=true 自动管理
  frame[24] = 0; frame[25] = 0;              // SSID tag(0) len(0) = 探测所有
  esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), true);
  totalProbes++;
}

// ================= 网页 =================
String buildHTML() {
  String html = R"HTML(<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>ESP32-C3 Sniffer v2</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1220;color:#d8e0f0;margin:0;padding:16px}
h1{font-size:20px;color:#7ee787}.dim{color:#8b93a8;font-size:12px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.card{background:#1a1f33;border-radius:10px;padding:10px 16px;min-width:90px}
.card b{display:block;font-size:20px;color:#ffd166}
.card span{font-size:11px;color:#8b93a8}
table{width:100%;border-collapse:collapse;font-size:13px;background:#141828;border-radius:10px;overflow:hidden}
th{background:#202642;color:#9aa7c7;text-align:left;padding:6px 10px;font-weight:600}
td{padding:6px 10px;border-top:1px solid #1f2440}
tr:hover td{background:#1a2035}
.rssi-good{color:#7ee787}.rssi-mid{color:#ffd166}.rssi-bad{color:#ff7b72}
.ops{background:#1a1f33;border-radius:10px;padding:10px 16px;margin:12px 0;font-size:13px}
.ops a{color:#a5b4fc;text-decoration:none;margin-right:14px;white-space:nowrap}
.ops a:hover{color:#7ee787}
h2{font-size:15px;margin:18px 0 8px;color:#a5b4fc}
</style></head><body>
<h1>ESP32-C3 WiFi Sniffer v2</h1>
<div class="dim">被动嗅探 + 主动扫描 · 自家网络调试学习</div>
<div class="cards">
<div class="card"><b>)HTML";
  char tmp[64];
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
  html += "</b><span>活跃设备</span></div><div class=\"card\"><b>";
  snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)totalProbes);
  html += tmp;
  html += "</b><span>主动探测</span></div></div>";

  // 网络状态与快捷操作
  String staState = WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : "未连接";
  html += "<div class=\"ops\"><b>管理入口:</b> AP <span class=\"dim\">http://192.168.4.1</span>";
  if (WiFi.status() == WL_CONNECTED) {
    html += " &nbsp;|&nbsp; 局域网 <span class=\"dim\">http://" + WiFi.localIP().toString() + "</span>";
  }
  html += "<br><b>操作:</b> ";
  html += "<a href=\"/set?ch=1\">固定CH1</a>";
  html += "<a href=\"/set?ch=6\">固定CH6</a>";
  html += "<a href=\"/set?ch=0\">全信道轮换</a>";
  html += activeScan ? "<a href=\"/scan?on=0\">关闭主动扫描</a>" : "<a href=\"/scan?on=1\">开启主动扫描</a>";
  html += "<a href=\"/config\">局域网配网</a></div>";

  // AP 表
  html += "<h2>附近 WiFi（AP）</h2><table><tr><th>SSID</th><th>BSSID</th><th>信道</th><th>信号</th><th>包数</th><th>来源</th></tr>";
  for (size_t i = 0; i < aps.size(); i++) {
    String s = String(aps[i].ssid);
    if (s.length() == 0) s = "(隐藏/未知)";
    html += "<tr><td>" + s + "</td><td class=\"dim\">" + macStr(aps[i].bssid) + "</td><td>" + aps[i].channel + "</td><td class=\"";
    html += (aps[i].rssi >= -60 ? "rssi-good" : (aps[i].rssi >= -75 ? "rssi-mid" : "rssi-bad"));
    html += "\">" + String(aps[i].rssi) + " dBm</td><td>" + String(aps[i].packets) + "</td><td class=\"dim\">";
    html += aps[i].viaProbe ? "主动挖出" : "Beacon";
    html += "</td></tr>";
  }
  html += "</table>";

  // 设备表
  html += "<h2>活跃设备</h2><table><tr><th>MAC</th><th>信号</th><th>包数</th><th>最近活跃</th></tr>";
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
    if (WiFi.status() == WL_CONNECTED) {
      server.send(200, "text/plain", "局域网模式下信道由路由器锁定，无法手动切换");
      return;
    }
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
  server.send(400, "text/plain", "usage: /set?ch=1..13 or ch=0 auto");
}

void handleScan() {
  if (server.hasArg("on")) {
    activeScan = server.arg("on") == "1";
    server.send(200, "text/plain", activeScan ? "active scan ON" : "active scan OFF");
    return;
  }
  server.send(400, "text/plain", "usage: /scan?on=1|0");
}

// 配网页：填自家 WiFi，保存后板子连局域网
void handleConfig() {
  String html = R"HTML(<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>局域网配网</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1220;color:#d8e0f0;padding:20px;max-width:420px;margin:0 auto}
h1{font-size:20px;color:#7ee787}
input{width:100%;padding:10px;margin:6px 0 14px;border:1px solid #2a3050;border-radius:8px;background:#141828;color:#d8e0f0;font-size:15px;box-sizing:border-box}
button{width:100%;padding:11px;background:#2ea043;border:0;border-radius:8px;color:#fff;font-size:16px;cursor:pointer}
.dim{color:#8b93a8;font-size:12px}
</style></head><body>
<h1>局域网配网</h1>
<p class="dim">填写自家路由器 WiFi，板子连上后可通过局域网 IP 访问本页（无需再连热点）。已保存配置：</p>
<form method="POST" action="/save">
<label>WiFi 名称 (SSID)</label><br>
<input name="ssid" placeholder="例如 TP-LINK_5G" value=")HTML";
  html += prefs.getString("ssid", "");
  html += R"HTML("><br>
<label>WiFi 密码</label><br>
<input type="password" name="pass" placeholder="留空 = 不修改/开放网络"><br>
<button type="submit">保存并连接</button>
</form>
<p class="dim">提示：连接局域网后信道固定为路由器信道；要清除配置改回纯热点，访问 /forget</p>
</body></html>)HTML";
  server.send(200, "text/html; charset=utf-8", html);
}

void handleSave() {
  String ssid = server.arg("ssid");
  ssid.trim();
  if (ssid.length() == 0) { server.send(400, "text/plain", "SSID 不能为空"); return; }
  String pass = server.arg("pass");
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  autoHop = false; // 连局域网后强制固定信道
  server.send(200, "text/html; charset=utf-8",
    "<html><body style='font-family:system-ui;background:#0f1220;color:#d8e0f0;padding:30px'><h2>已保存，正在连接 "
    + ssid + " ...</h2><p>连上后本页地址变为局域网 IP（看串口或路由器后台）。<a href='/' style='color:#a5b4fc'>返回</a></p></body></html>");
  delay(300);
  WiFi.disconnect();
  WiFi.begin(ssid.c_str(), pass.c_str());
}

void handleForget() {
  prefs.remove("ssid");
  prefs.remove("pass");
  server.send(200, "text/plain", "已清除局域网配置，重启后为纯热点模式。请断电重启。");
}

void handleNotFound() { server.send(404, "text/plain", "Not Found"); }

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nESP32-C3 Sniffer v2 starting...");

  prefs.begin("sniffer", false);
  String savedSSID = prefs.getString("ssid", "");

  aps.reserve(MAX_APS);
  devs.reserve(MAX_DEVS);

  // 双模：AP 热点固定开（管理入口）+ 可选 STA 连局域网
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID);

  if (savedSSID.length() > 0) {
    String savedPass = prefs.getString("pass", "");
    WiFi.begin(savedSSID.c_str(), savedPass.c_str());
    Serial.print("Connecting LAN: ");
    Serial.println(savedSSID);
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  if (WiFi.status() == WL_CONNECTED) {
    curChannel = WiFi.channel();
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
    Serial.print("LAN connected, locked ch=");
    Serial.println(curChannel);
  } else {
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  server.on("/", handleRoot);
  server.on("/set", handleSet);
  server.on("/scan", handleScan);
  server.on("/config", handleConfig);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/forget", handleForget);
  server.onNotFound(handleNotFound);
  server.begin();

  Serial.println("AP: ESP32C3-Sniffer -> http://192.168.4.1");
}

void loop() {
  server.handleClient();

  uint32_t now = millis();

  // 等 STA 连上后锁定路由器信道并打印局域网 IP
  static bool lanAnnounced = false;
  if (savedSSIDMode() && WiFi.status() == WL_CONNECTED) {
    if (!lanAnnounced) {
      lanAnnounced = true;
      curChannel = WiFi.channel();
      autoHop = false;
      Serial.print("LAN IP: http://");
      Serial.println(WiFi.localIP());
      Serial.print("Locked ch=");
      Serial.println(curChannel);
    }
  } else if (WiFi.status() != WL_CONNECTED && !savedSSIDMode()) {
    // 未配网无操作
  }

  // 信道轮换（未连局域网时允许）
  if (autoHop && WiFi.status() != WL_CONNECTED && now - lastHop >= HOP_INTERVAL_MS) {
    lastHop = now;
    curChannel++;
    if (curChannel > 13) curChannel = 1;
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  // 主动扫描：每 PROBE_INTERVAL_MS 发一次空 SSID Probe Request
  if (activeScan && now - lastProbe >= PROBE_INTERVAL_MS) {
    lastProbe = now;
    sendProbeRequest();
  }

  // 清理超时设备/AP + 串口摘要
  if (now - lastStat >= 5000) {
    lastStat = now;
    uint32_t t = millis();
    portENTER_CRITICAL(&mux);
    for (size_t i = aps.size(); i-- > 0;)
      if (t - aps[i].lastSeen > AP_TIMEOUT_MS) aps.erase(aps.begin() + i);
    for (size_t i = devs.size(); i-- > 0;)
      if (t - devs[i].lastSeen > DEVICE_TIMEOUT_MS) devs.erase(devs.begin() + i);
    portEXIT_CRITICAL(&mux);

    char buf[110];
    snprintf(buf, sizeof(buf), "[%02d] pkts=%lu mgmt=%lu data=%lu AP=%d dev=%d probe=%lu sta=%s",
             curChannel, (unsigned long)totalPackets, (unsigned long)mgmtCount,
             (unsigned long)dataCount, (int)aps.size(), (int)devs.size(),
             (unsigned long)totalProbes,
             (WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString().c_str() : "off"));
    Serial.println(buf);
  }
}

bool savedSSIDMode() {
  return prefs.getString("ssid", "").length() > 0;
}
