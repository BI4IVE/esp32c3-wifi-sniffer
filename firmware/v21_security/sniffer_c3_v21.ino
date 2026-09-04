/*
 * ESP32-C3 WiFi 嗅探器 v2.1（自家网络调试学习用）
 * 在 v2 基础上新增：
 *  - 加密方式检测：解析 Beacon 的 RSN/WPA 字段，标出 开放/WPA/WPA2/WPA3/OWE
 *  - 设备命名 + 陌生人告警：/names 页面给 MAC 起名（Preferences 掉电记忆），
 *    未命名设备出现标红"未识别"并串口告警一次
 *  - Deauth/Disassoc 风暴检测：1 秒窗口 > 阈值即页面横幅告警
 * 保留 v2：AP 热点 + 网页配网连局域网 + 主动扫描 + 信道切换
 * 仅供自家网络学习调试使用。
 */
#include <WiFi.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <vector>
#include <cstring>
#include <stdio.h>

// ================= 可调参数 =================
#define HOP_INTERVAL_MS   300
#define PROBE_INTERVAL_MS 15000
#define DEVICE_TIMEOUT_MS 90000
#define AP_TIMEOUT_MS     120000
#define MAX_APS           48
#define MAX_DEVS          64
#define AP_SSID           "ESP32C3-Sniffer"
#define DEAUTH_BURST_N    10     // 1 秒内 >= N 次 deauth/disassoc 视为风暴
#define DEAUTH_BURST_MS   1000

WebServer server(80);
Preferences prefs;

struct ApInfo {
  uint8_t bssid[6];
  char ssid[33];
  char enc[10];     // 开放 / WPA / WPA2 / WPA3 / OWE / 未知
  int8_t  channel;
  int8_t  rssi;
  uint32_t packets;
  uint32_t lastSeen;
  bool viaProbe;
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
volatile uint32_t totalProbes = 0;
volatile uint32_t deauthCnt = 0;    // deauth+disassoc 总数
volatile uint32_t burstCnt = 0;     // 窗口内突发计数
uint32_t burstWindowStart = 0;
bool deauthAlert = false;
bool savedSSIDMode();
uint8_t  curChannel = 1;
bool     autoHop = false;
bool     activeScan = true;
uint32_t lastHop = 0, lastProbe = 0, lastStat = 0, lastBurstCheck = 0;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

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
  return true;
}
bool isKnownAP(const uint8_t* mac) {
  for (size_t i = 0; i < aps.size(); i++)
    if (sameMac(aps[i].bssid, mac)) return true;
  return false;
}

// 管理帧 tagged params 中取指定 tag 内容
bool getTag(const uint8_t* f, int len, uint8_t want, const uint8_t** out, int* outLen) {
  int off = 36;
  while (off + 2 <= len) {
    uint8_t tag = f[off];
    uint8_t tlen = f[off + 1];
    if (off + 2 + tlen > len) break;
    if (tag == want) { *out = f + off + 2; *outLen = tlen; return true; }
    off += 2 + tlen;
  }
  return false;
}

String parseSSID(const uint8_t* f, int len) {
  const uint8_t* p; int pl;
  if (getTag(f, len, 0, &p, &pl)) {
    int n = pl < 32 ? pl : 32;
    return String((const char*)p, n);
  }
  return String();
}

// 解析加密方式：RSN(48) -> WPA2/WPA3/OWE；vendor WPA(221) -> WPA1
String parseEnc(const uint8_t* f, int len) {
  const uint8_t* rsn; int rl;
  if (getTag(f, len, 48, &rsn, &rl)) {
    if (rl >= 8) {
      // RSN body: ver(2) group(4) pairwise_cnt(2) ...
      uint16_t pc = (rsn[6] << 8) | rsn[7];
      int akmOff = 8 + pc * 4;
      if (rl >= akmOff + 6) {
        uint16_t ac = (rsn[akmOff] << 8) | rsn[akmOff + 1];
        if (ac >= 1 && rl >= akmOff + 2 + 4) {
          uint8_t akmType = rsn[akmOff + 2 + 3]; // 第一个 AKM suite 的第 4 字节
          if (akmType == 6 || akmType == 12 || akmType == 13) return "WPA3";
          if (akmType == 8) return "OWE";
        }
      }
    }
    return "WPA2";
  }
  const uint8_t* v; int vl;
  if (getTag(f, len, 221, &v, &vl)) {
    // WPA vendor IE: OUI 00:50:F2 type 01
    if (vl >= 6 && v[0] == 0x00 && v[1] == 0x50 && v[2] == 0xF2 && v[3] == 0x01)
      return "WPA";
  }
  return "开放";
}

void addAP(const uint8_t* bssid, const char* ssid, const char* enc, uint8_t ch, int8_t rssi, bool viaProbe) {
  for (size_t i = 0; i < aps.size(); i++) {
    if (sameMac(aps[i].bssid, bssid)) {
      aps[i].rssi = rssi;
      aps[i].channel = ch;
      aps[i].packets++;
      aps[i].lastSeen = millis();
      if (viaProbe) aps[i].viaProbe = true;
      if (ssid[0]) { strncpy(aps[i].ssid, ssid, 32); aps[i].ssid[32] = 0; }
      if (String(aps[i].enc) == "未知") strncpy(aps[i].enc, enc, 9);
      return;
    }
  }
  if (aps.size() >= MAX_APS) return;
  ApInfo a;
  memset(&a, 0, sizeof(a));
  memcpy(a.bssid, bssid, 6);
  strncpy(a.ssid, ssid, 32);
  a.ssid[32] = 0;
  strncpy(a.enc, enc, 9);
  a.enc[9] = 0;
  a.channel = ch;
  a.rssi = rssi;
  a.packets = 1;
  a.lastSeen = millis();
  a.viaProbe = viaProbe;
  aps.push_back(a);
}

// 设备是否有名字（白名单）
String devName(const uint8_t* mac) {
  return prefs.getString(("d_" + macStr(mac)).c_str(), "");
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
  // 陌生人（未命名且非 AP）：串口告警一次（页面持续标红）
  if (devName(mac).length() == 0) {
    Serial.print("STRANGER dev: ");
    Serial.print(macStr(mac));
    Serial.print(" rssi=");
    Serial.println(rssi);
  }
}

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
    if (st == 8) { // Beacon
      String ssid = parseSSID(f, len);
      String enc = parseEnc(f, len);
      char s[33], e[10];
      ssid.toCharArray(s, 33);
      enc.toCharArray(e, 10);
      addAP(addr2, s, e, ctrl->channel, ctrl->rssi, false);
    } else if (st == 5 || st == 1 || st == 3) {
      String ssid = parseSSID(f, len);
      String enc = parseEnc(f, len);
      char s[33], e[10];
      ssid.toCharArray(s, 33);
      enc.toCharArray(e, 10);
      addAP(addr2, s, e, ctrl->channel, ctrl->rssi, true);
    } else if (st == 12 || st == 10) { // deauth / disassoc
      deauthCnt++;
      burstCnt++;
    } else {
      if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi);
    }
  } else if (ft == 2) { // 数据帧
    dataCount++;
    if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi);
  }

  portEXIT_CRITICAL(&mux);
}

void sendProbeRequest() {
  uint8_t frame[26] = {0};
  frame[0] = 0x40; frame[1] = 0x00;
  memset(frame + 4, 0xFF, 6);
  uint8_t mac[6] = {0};
  esp_wifi_get_mac(WIFI_IF_AP, mac);
  memcpy(frame + 10, mac, 6);
  memset(frame + 16, 0xFF, 6);
  frame[24] = 0; frame[25] = 0;
  esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), true);
  totalProbes++;
}

// ================= 网页 =================
String encBadge(const String& enc) {
  if (enc == "开放") return "<span style='color:#ff7b72;font-weight:600'>开放!</span>";
  return enc;
}

String buildHTML() {
  String html = R"HTML(<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>ESP32-C3 Sniffer v2.1</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1220;color:#d8e0f0;margin:0;padding:16px}
h1{font-size:20px;color:#7ee787}.dim{color:#8b93a8;font-size:12px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.card{background:#1a1f33;border-radius:10px;padding:10px 16px;min-width:80px}
.card b{display:block;font-size:20px;color:#ffd166}
.card span{font-size:11px;color:#8b93a8}
table{width:100%;border-collapse:collapse;font-size:13px;background:#141828;border-radius:10px;overflow:hidden}
th{background:#202642;color:#9aa7c7;text-align:left;padding:6px 10px;font-weight:600}
td{padding:6px 10px;border-top:1px solid #1f2440}
tr:hover td{background:#1a2035}
.rssi-good{color:#7ee787}.rssi-mid{color:#ffd166}.rssi-bad{color:#ff7b72}
.stranger{color:#ff7b72;font-weight:600}
.ops{background:#1a1f33;border-radius:10px;padding:10px 16px;margin:12px 0;font-size:13px}
.ops a{color:#a5b4fc;text-decoration:none;margin-right:14px;white-space:nowrap}
.ops a:hover{color:#7ee787}
.alert{background:#3d1a1a;border:1px solid #ff7b72;color:#ffb3ad;border-radius:10px;padding:10px 16px;margin:12px 0;font-size:14px}
h2{font-size:15px;margin:18px 0 8px;color:#a5b4fc}
</style></head><body>
<h1>ESP32-C3 WiFi Sniffer v2.1</h1>
<div class="dim">被动嗅探 + 主动扫描 · 自家网络调试学习</div>)HTML";

  if (deauthAlert) {
    char buf[80];
    snprintf(buf, sizeof(buf), "疑似 deauth/disassoc 风暴！共 %lu 次（含历史）。", (unsigned long)deauthCnt);
    html += "<div class=\"alert\">⚠ " + String(buf) + " <a href=\"/clearalert\" style='color:#a5b4fc'>清除告警</a></div>";
  }

  html += "<div class=\"cards\">";
  char tmp[64];
  auto card = [&](const char* v, const char* l) {
    html += "<div class=\"card\"><b>" + String(v) + "</b><span>" + String(l) + "</span></div>";
  };
  snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)totalPackets); card(tmp, "收包总数");
  snprintf(tmp, sizeof(tmp), "%d", curChannel); card(tmp, "信道");
  snprintf(tmp, sizeof(tmp), "%d", (int)aps.size()); card(tmp, "附近WiFi");
  snprintf(tmp, sizeof(tmp), "%d", (int)devs.size()); card(tmp, "活跃设备");
  snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)totalProbes); card(tmp, "主动探测");
  snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)deauthCnt); card(tmp, "Deauth");
  html += "</div>";

  html += "<div class=\"ops\"><b>管理入口:</b> AP <span class=\"dim\">http://192.168.4.1</span>";
  if (WiFi.status() == WL_CONNECTED)
    html += " &nbsp;|&nbsp; 局域网 <span class=\"dim\">http://" + WiFi.localIP().toString() + "</span>";
  html += "<br><b>操作:</b> ";
  html += "<a href=\"/set?ch=1\">固定CH1</a><a href=\"/set?ch=6\">固定CH6</a><a href=\"/set?ch=0\">轮换</a>";
  html += activeScan ? "<a href=\"/scan?on=0\">关主动扫描</a>" : "<a href=\"/scan?on=1\">开主动扫描</a>";
  html += "<a href=\"/names\">设备命名</a><a href=\"/config\">局域网配网</a></div>";

  html += "<h2>附近 WiFi（AP）</h2><table><tr><th>SSID</th><th>加密</th><th>BSSID</th><th>信道</th><th>信号</th><th>包数</th><th>来源</th></tr>";
  for (size_t i = 0; i < aps.size(); i++) {
    String s = String(aps[i].ssid);
    if (s.length() == 0) s = "(隐藏/未知)";
    html += "<tr><td>" + s + "</td><td>" + encBadge(aps[i].enc) + "</td><td class=\"dim\">" + macStr(aps[i].bssid) + "</td><td>" + aps[i].channel + "</td><td class=\"";
    html += (aps[i].rssi >= -60 ? "rssi-good" : (aps[i].rssi >= -75 ? "rssi-mid" : "rssi-bad"));
    html += "\">" + String(aps[i].rssi) + " dBm</td><td>" + String(aps[i].packets) + "</td><td class=\"dim\">";
    html += aps[i].viaProbe ? "主动挖出" : "Beacon";
    html += "</td></tr>";
  }
  html += "</table>";

  html += "<h2>活跃设备</h2><table><tr><th>名称</th><th>MAC</th><th>信号</th><th>包数</th><th>最近活跃</th></tr>";
  for (size_t i = 0; i < devs.size(); i++) {
    String name = devName(devs[i].mac);
    uint32_t age = millis() - devs[i].lastSeen;
    html += "<tr><td>";
    if (name.length() > 0) html += name;
    else html += "<span class=\"stranger\">未识别</span>";
    html += "</td><td>" + macStr(devs[i].mac) + "</td><td class=\"";
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
void handleClearAlert() { deauthAlert = false; server.send(200, "text/plain", "alert cleared"); }

void handleSet() {
  if (server.hasArg("ch")) {
    int ch = server.arg("ch").toInt();
    if (WiFi.status() == WL_CONNECTED) {
      server.send(200, "text/plain", "局域网模式下信道由路由器锁定");
      return;
    }
    if (ch == 0) { autoHop = true; server.send(200, "text/plain", "auto hop ON"); return; }
    if (ch >= 1 && ch <= 13) {
      autoHop = false;
      curChannel = (uint8_t)ch;
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      server.send(200, "text/plain", "fixed ch=" + String(ch));
      return;
    }
  }
  server.send(400, "text/plain", "usage: /set?ch=1..13 or ch=0");
}

void handleScan() {
  if (server.hasArg("on")) {
    activeScan = server.arg("on") == "1";
    server.send(200, "text/plain", activeScan ? "active scan ON" : "active scan OFF");
    return;
  }
  server.send(400, "text/plain", "usage: /scan?on=1|0");
}

// 命名页：当前活跃设备列表 + 命名表单
void handleNames() {
  String html = R"HTML(<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>设备命名</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1220;color:#d8e0f0;padding:16px;max-width:640px;margin:0 auto}
h1{font-size:19px;color:#7ee787}.dim{color:#8b93a8;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px;background:#141828;border-radius:10px}
th{background:#202642;color:#9aa7c7;padding:6px 10px;text-align:left}
td{padding:6px 10px;border-top:1px solid #1f2440}
input[type=text]{padding:6px;border:1px solid #2a3050;border-radius:6px;background:#0f1220;color:#d8e0f0;width:130px}
button{padding:6px 10px;background:#2ea043;border:0;border-radius:6px;color:#fff;cursor:pointer}
a{color:#a5b4fc;text-decoration:none;font-size:13px}
</style></head><body>
<h1>设备命名（白名单）</h1>
<p class="dim">给自家设备起名后，它就不再算"陌生人"。名字保存在板子里，掉电不丢。</p>
<table><tr><th>当前名称</th><th>MAC</th><th>操作</th></tr>)HTML";
  for (size_t i = 0; i < devs.size(); i++) {
    String m = macStr(devs[i].mac);
    String name = devName(devs[i].mac);
    html += "<tr><td>" + (name.length() ? name : "<span class='dim'>未命名</span>") + "</td><td>" + m + "</td><td>";
    html += "<form method='GET' action='/name' style='display:inline'><input type='hidden' name='mac' value='" + m + "'>";
    html += "<input type='text' name='name' placeholder='例如 老板手机' value='" + name + "'>";
    html += "<button type='submit'>保存</button></form> ";
    html += "<form method='GET' action='/name' style='display:inline'><input type='hidden' name='mac' value='" + m + "'><input type='hidden' name='name' value=''>";
    html += "<button type='submit' style='background:#3b3f55'>清除</button></form></td></tr>";
  }
  html += "</table><p><a href='/'>返回</a></p></body></html>";
  server.send(200, "text/html; charset=utf-8", html);
}

void handleName() {
  String mac = server.arg("mac");
  String name = server.arg("name");
  mac.toUpperCase();
  if (mac.length() == 0) { server.send(400, "text/plain", "need mac"); return; }
  String key = "d_" + mac;
  if (name.length() == 0) prefs.remove(key.c_str());
  else prefs.putString(key.c_str(), name);
  server.send(200, "text/plain", "ok: " + mac + " -> " + (name.length() ? name : "(清除)"));
}

void handleConfig() {
  String html = R"HTML(<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>局域网配网</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1220;color:#d8e0f0;padding:20px;max-width:420px;margin:0 auto}
h1{font-size:20px;color:#7ee787}.dim{color:#8b93a8;font-size:12px}
input{width:100%;padding:10px;margin:6px 0 14px;border:1px solid #2a3050;border-radius:8px;background:#141828;color:#d8e0f0;font-size:15px;box-sizing:border-box}
button{width:100%;padding:11px;background:#2ea043;border:0;border-radius:8px;color:#fff;font-size:16px;cursor:pointer}
</style></head><body>
<h1>局域网配网</h1>
<p class="dim">填写自家路由器 WiFi，板子连上后可通过局域网 IP 访问（无需再连热点）。当前已保存配置：</p>
<form method="POST" action="/save">
<label>WiFi 名称 (SSID)</label><br>
<input name="ssid" placeholder="例如 TP-LINK_5G" value=")HTML";
  html += prefs.getString("ssid", "");
  html += R"HTML("><br>
<label>WiFi 密码</label><br>
<input type="password" name="pass" placeholder="留空 = 不修改/开放网络"><br>
<button type="submit">保存并连接</button>
</form>
<p class="dim">清除配置改回纯热点：访问 /forget 后断电重启</p>
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
  autoHop = false;
  server.send(200, "text/html; charset=utf-8",
    "<html><body style='font-family:system-ui;background:#0f1220;color:#d8e0f0;padding:30px'><h2>已保存，正在连接 "
    + ssid + " ...</h2><p>连上后地址变为局域网 IP（看串口）。<a href='/' style='color:#a5b4fc'>返回</a></p></body></html>");
  delay(300);
  WiFi.disconnect();
  WiFi.begin(ssid.c_str(), pass.c_str());
}

void handleForget() {
  prefs.remove("ssid");
  prefs.remove("pass");
  server.send(200, "text/plain", "已清除局域网配置，重启后为纯热点模式");
}
void handleNotFound() { server.send(404, "text/plain", "Not Found"); }

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nESP32-C3 Sniffer v2.1 starting...");

  prefs.begin("sniffer", false);
  String savedSSID = prefs.getString("ssid", "");
  aps.reserve(MAX_APS);
  devs.reserve(MAX_DEVS);

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
  } else {
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  server.on("/", handleRoot);
  server.on("/set", handleSet);
  server.on("/scan", handleScan);
  server.on("/names", handleNames);
  server.on("/name", handleName);
  server.on("/clearalert", handleClearAlert);
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

  // STA 连上后锁定路由器信道并打印 IP
  static bool lanAnnounced = false;
  if (savedSSIDMode()) {
    if (WiFi.status() == WL_CONNECTED) {
      if (!lanAnnounced) {
        lanAnnounced = true;
        curChannel = WiFi.channel();
        autoHop = false;
        Serial.print("LAN IP: http://");
        Serial.println(WiFi.localIP());
        Serial.print("Locked ch=");
        Serial.println(curChannel);
      }
    }
  }

  if (autoHop && WiFi.status() != WL_CONNECTED && now - lastHop >= HOP_INTERVAL_MS) {
    lastHop = now;
    curChannel++;
    if (curChannel > 13) curChannel = 1;
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  if (activeScan && now - lastProbe >= PROBE_INTERVAL_MS) {
    lastProbe = now;
    sendProbeRequest();
  }

  // Deauth 风暴检测：滑动窗口突发计数
  if (now - burstWindowStart >= DEAUTH_BURST_MS) {
    if (burstCnt >= DEAUTH_BURST_N) {
      deauthAlert = true;
      Serial.print("DEAUTH storm: ");
      Serial.print(burstCnt);
      Serial.println(" frames/s");
    }
    burstCnt = 0;
    burstWindowStart = now;
  }

  if (now - lastStat >= 5000) {
    lastStat = now;
    uint32_t t = millis();
    portENTER_CRITICAL(&mux);
    for (size_t i = aps.size(); i-- > 0;)
      if (t - aps[i].lastSeen > AP_TIMEOUT_MS) aps.erase(aps.begin() + i);
    for (size_t i = devs.size(); i-- > 0;)
      if (t - devs[i].lastSeen > DEVICE_TIMEOUT_MS) devs.erase(devs.begin() + i);
    portEXIT_CRITICAL(&mux);

    char buf[120];
    snprintf(buf, sizeof(buf), "[%02d] pkts=%lu ap=%d dev=%d deauth=%lu probe=%lu sta=%s",
             curChannel, (unsigned long)totalPackets, (int)aps.size(), (int)devs.size(),
             (unsigned long)deauthCnt, (unsigned long)totalProbes,
             (WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString().c_str() : "off"));
    Serial.println(buf);
  }
}

bool savedSSIDMode() {
  return prefs.getString("ssid", "").length() > 0;
}
