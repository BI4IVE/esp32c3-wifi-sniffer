/*
 * ESP32-C3 WiFi 嗅探器 v2.3 - 运维全功能版（自家网络调试学习用）
 * v2.3 新增：RSSI 信号打点（指定AP采样->均值/标准差/评级/12条历史/CSV导出）
 *            + 主动测速（STA 连被测 AP -> TCP 探测网关 80/443 -> 延迟/丢包统计）
 * 在 v2.1 基础上新增（本版本全部纳入）：
 *  - 帧类型细分统计：beacon/probeReq/probeResp/deauth/disassoc/auth/assoc/data/EAPOL
 *  - 信道体检 survey：13 信道停留统计 + 推荐信道 + /report 体检报告
 *  - 非法/钓鱼 AP 检测：/protect 配置本家 SSID+BSSID 白名单，同名陌生 BSSID 标 rogue
 *  - OUI 厂商识别：内置常见厂商前缀表（Apple/小米/华为/TP-Link 等）
 *  - Beacon 消失监控：AP 超时掉线 -> 事件时间线
 *  - 设备关联拓扑：从数据帧解析 STA 连接到的 AP
 *  - 客户端暴露面：Probe Request 中寻找本家 SSID 的设备统计
 *  - 实时图表：主页 60 点收包速率折线（canvas + 轮询 JSON）
 *  - 事件时间线：100 条环形事件缓冲（陌生人/deauth风暴/rogue/掉线/开放网络/EAPOL/体检完成）
 *  - REST JSON API：/api/stats /api/aps /api/devs /api/events /api/survey /api/topo /api/hist
 *  - Prometheus 指标：/metrics
 *  - Webhook 告警：事件 POST JSON 到自定义 URL（deauth风暴/rogue/AP掉线）
 *  - pcap 导出：环形缓存最近管理帧原始数据，/dump 下载 pcap
 * 保留 v2.1：加密检测 / 设备命名白名单 / 陌生人告警 / deauth风暴 / AP热点+网页配网 / 主动扫描
 * 仅供自家网络学习调试使用。
 */
#include <WiFi.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <HTTPClient.h>
#include <vector>
#include <cstring>
#include <stdio.h>
#include <math.h>

#include <stdarg.h>

// ================= 可调参数 =================
#define HOP_INTERVAL_MS   300
#define PROBE_INTERVAL_MS 15000
#define DEVICE_TIMEOUT_MS 90000
#define AP_TIMEOUT_MS     120000
#define MAX_APS           48
#define MAX_DEVS          64
#define MAX_EVENTS        100
#define AP_SSID           "ESP32C3-Sniffer"
#define DEAUTH_BURST_N    10
#define DEAUTH_BURST_MS   1000
#define SURVEY_CH_MS      3000   // 每信道体检停留时长
#define PCAP_SLOTS        240
#define PCAP_MAXLEN       220
#define HIST_N            60     // 实时图表点数（秒）

WebServer server(80);
Preferences prefs;

// ---------------- AP / 设备 ----------------
struct ApInfo {
  uint8_t bssid[6];
  char ssid[33];
  char enc[10];      // 开放 / WPA / WPA2 / WPA3 / OWE / 未知
  char oui[24];
  int8_t  channel;
  int8_t  rssi;
  uint32_t packets;
  uint32_t beaconCnt;
  uint32_t firstSeen, lastSeen;
  bool viaProbe;
  bool rogue;        // 非法/钓鱼标记
};
struct DevInfo {
  uint8_t mac[6];
  int8_t  rssi;
  uint32_t packets;
  uint32_t firstSeen, lastSeen;
  int apIdx;                 // 关联 AP 下标，-1 未知
  char oui[24];
  char lastProbeSsid[33];    // 最近 probe 的 SSID（暴露面）
};
std::vector<ApInfo>  aps;
std::vector<DevInfo> devs;

// ---------------- 帧统计 ----------------
volatile uint32_t totalPackets = 0;
volatile uint32_t cntMgmt=0,cntData=0,cntCtrl=0;
volatile uint32_t cntBeacon=0,cntProbeReq=0,cntProbeResp=0,cntDeauth=0,cntDisassoc=0,cntAuth=0,cntAssoc=0;
volatile uint32_t cntEapol=0;
volatile uint32_t totalProbes = 0;
volatile uint32_t burstCnt = 0;
uint32_t burstWindowStart = 0;
bool deauthAlert = false;
volatile uint32_t deauthStormTimes = 0;

// ---------------- 事件时间线 ----------------
struct EvInfo { uint32_t tMs; uint8_t type; char mac[18]; char desc[64]; };
std::vector<EvInfo> events;
// type: 0=启动 1=陌生人 2=deauth风暴 3=rogue AP 4=AP掉线 5=开放网络 6=EAPOL握手 7=体检完成 8=新设备命名/信任 9=Webhook失败
const char* evTypeName(uint8_t t) {
  switch(t){case 0:return "系统";case 1:return "陌生人";case 2:return "Deauth风暴";case 3:return "疑似钓鱼AP";case 4:return "AP掉线";case 5:return "开放网络";case 6:return "WPA握手";case 7:return "信道体检";case 8:return "白名单";case 9:return "Webhook";default:return "其他";}
}
void pushEvent(uint8_t type, const char* mac, const char* fmt, ...) {
  EvInfo e; memset(&e,0,sizeof(e));
  e.tMs = millis(); e.type = type;
  if (mac) strncpy(e.mac, mac, 17);
  va_list ap; va_start(ap, fmt);
  vsnprintf(e.desc, sizeof(e.desc), fmt, ap);
  va_end(ap);
  events.push_back(e);
  if (events.size() > MAX_EVENTS) events.erase(events.begin());
  Serial.print("[EV "); Serial.print(evTypeName(type)); Serial.print("] ");
  Serial.println(e.desc);
}

// ---------------- 信道体检 ----------------
struct SurveyCh { uint32_t pkt, beacon, deauth; uint16_t apCnt; uint8_t apDetect; };
SurveyCh survey[14];
bool surveyActive = false;
uint8_t surveyCur = 1;
uint32_t surveyChStart = 0, surveyStartMs = 0;
bool surveyRunning = false;      // 是否正在巡检
String surveySummary = "";
uint32_t lastSurveyAuto = 0;
volatile uint32_t surveyAccPkt=0, surveyAccBeacon=0, surveyAccDeauth=0;

// ---------------- pcap 环形缓冲 ----------------
struct PcapSlot { uint32_t tsMs; int8_t rssi; uint8_t ch; uint16_t len; uint8_t data[PCAP_MAXLEN]; };
PcapSlot pcap[PCAP_SLOTS];
uint16_t pcapHead = 0, pcapCount = 0;
bool pcapEnable = true;

// ---------------- 速率历史（实时图） ----------------
uint32_t rateHist[HIST_N];
uint8_t rateIdx = 0;
uint32_t lastSecPkt = 0, lastRateTick = 0;

// ---------------- 其他状态 ----------------
uint8_t  curChannel = 1;
bool     autoHop = false;
bool     activeScan = true;
uint32_t lastHop = 0, lastProbe = 0, lastStat = 0, lastBurstCheck = 0, lastWebhook = 0;
uint32_t lastTrustBcast = 0; // 防重复事件
uint8_t lastRogueMac[6] = {0};
bool lastRogueSet = false;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
bool savedSSIDMode();

// ================= v2.3 信号质量 =================
#define QT_SLOTS          12
#define SIG_SAMPLE_MAX    300
#define SIG_TICK_MS       200
#define APTEST_MAX_N      30

// ---- RSSI 信号打点状态 ----
struct SigRun {
  bool running;
  uint8_t bssid[6];
  char ssid[33];
  char name[33];
  uint8_t ch;
  uint32_t durMs, startMs, lastTick;
  int16_t samples[SIG_SAMPLE_MAX];
  uint16_t n;
  uint16_t missN;
  int8_t lastRssi;
  bool priorAutoHop;
};
SigRun sig;
int qtNext = 0;                     // 历史槽循环指针（qt0..qt11）

// ---- 主动测速状态 ----
struct ApTestRun {
  bool running;
  uint8_t stage;                    // 0=空闲 1=连接中 2=测速中 3=完成(保留报告) 4=恢复原STA中
  char ssid[33];
  char pass[65];
  char err[90];
  uint32_t stMs, lastTick;
  int16_t rttMs[APTEST_MAX_N];      // 成功为RTT(ms)，失败为-1
  uint8_t totalN, probeIdx;
  uint32_t lastProbeMs;
  int8_t rssi;
  uint8_t ch;
  String gwIp, localIp;
};
ApTestRun apt;

// 打点历史槽缓存（collectSlots 填充）
struct SigSlot { uint32_t ts; String raw; };
SigSlot slotsCache[QT_SLOTS];

bool lanAnnounced = false;          // STA 锁定通告（全局化，测速重连后可复位）

// ================= 工具函数 =================
String macStr(const uint8_t* m) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(buf);
}
bool sameMac(const uint8_t* a, const uint8_t* b) { return memcmp(a,b,6)==0; }
bool isIgnorable(const uint8_t* a) {
  for (int i=0;i<6;i++) if (a[i]!=0xFF && a[i]!=0x00) return false;
  return true;
}
int findApIdx(const uint8_t* mac) {
  if (!mac) return -1;
  for (size_t i=0;i<aps.size();i++) if (sameMac(aps[i].bssid, mac)) return (int)i;
  return -1;
}
bool isKnownAP(const uint8_t* mac) { return findApIdx(mac) >= 0; }

// ---------------- OUI 厂商表（前缀匹配） ----------------
struct OuiEntry { const char* prefix; const char* vendor; };
const OuiEntry OUI_TABLE[] = {
  {"3C:22:FB","Apple"},{"AC:BC:32","Apple"},{"F0:18:98","Apple"},{"A4:83:E7","Apple"},{"88:66:5A","Apple"},
  {"DC:A9:71","Apple"},{"F4:0F:24","Apple"},{"64:09:80","小米"},{"28:6C:07","小米"},{"50:EC:50","小米/红米"},
  {"48:46:FB","华为"},{"8C:34:FD","华为"},{"60:DE:44","华为"},{"D4:6A:6A","华为"},
  {"B0:BE:76","TP-Link"},{"50:FA:84","TP-Link"},{"C8:3A:35","TP-Link"},
  {"B8:27:EB","树莓派"},{"DC:A6:32","树莓派"},
  {"E8:48:B8","三星"},{"8C:79:F5","三星"},
  {"B0:A7:B9","Realtek"},{"DC:4A:3E","Realtek"},{"00:E0:4C","Realtek"},
  {"24:0A:C4","乐鑫ESP"},{"30:AE:A4","乐鑫ESP"},{"A4:CF:12","乐鑫ESP"},
  {"D0:15:4A","Intel"},{"3C:52:82","Intel"},{"00:1A:7D","Davicom"},
  {"C8:69:CD","Sonos"},{"00:17:88","飞利浦Hue"},
  {"10:3D:1E","TP-Link"},{"58:6D:8F","Tenda"},
  {"44:D2:CA","联发科MTK"},{"A4:9B:13","Google"},
  {"F8:E4:E3","小米"},{"04:CF:8C","小米"},{"AC:37:43","小米"},
};
String ouiLookup(const uint8_t* mac) {
  char m[18]; snprintf(m, sizeof(m), "%02X:%02X:%02X", mac[0],mac[1],mac[2]);
  String up = String(m);
  for (size_t i=0;i<sizeof(OUI_TABLE)/sizeof(OuiEntry);i++) {
    if (up.startsWith(OUI_TABLE[i].prefix)) return String(OUI_TABLE[i].vendor);
  }
  return String("");
}

// ---------------- Preferences helpers ----------------
String devName(const uint8_t* mac) { return prefs.getString(("d_"+macStr(mac)).c_str(), ""); }
String getTrustSsid() { return prefs.getString("tssid",""); }
String getTrustBssid() { return prefs.getString("tbssid",""); }
String getHook() { return prefs.getString("hook",""); }
bool ssidInTrust(const char* ssid) {
  if (!ssid || !ssid[0]) return false;
  String t = getTrustSsid();
  if (t.length()==0) return false;
  String target = String(ssid); target.trim();
  int p=0;
  while (p <= t.length()) {
    int c = t.indexOf(',', p);
    String one = (c<0 ? t.substring(p) : t.substring(p,c)); one.trim();
    if (one.length() && one == target) return true;
    if (c<0) break; p = c+1;
  }
  return false;
}
bool bssidInTrust(const uint8_t* mac) {
  String t = getTrustBssid();
  if (t.length()==0) return false;
  String m = macStr(mac);
  int p=0;
  while (p <= t.length()) {
    int c = t.indexOf(',', p);
    String one = (c<0 ? t.substring(p) : t.substring(p,c)); one.trim();
    if (one.length() && one.equalsIgnoreCase(m)) return true;
    if (c<0) break; p = c+1;
  }
  return false;
}

// 管理帧 tagged params 中取指定 tag 内容
bool getTag(const uint8_t* f, int len, uint8_t want, const uint8_t** out, int* outLen) {
  int off = 36;
  while (off + 2 <= len) {
    uint8_t tag = f[off];
    uint8_t tlen = f[off+1];
    if (off + 2 + tlen > len) break;
    if (tag == want) { *out = f+off+2; *outLen = tlen; return true; }
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
String parseEnc(const uint8_t* f, int len) {
  const uint8_t* rsn; int rl;
  if (getTag(f, len, 48, &rsn, &rl)) {
    if (rl >= 8) {
      uint16_t pc = (rsn[6]<<8)|rsn[7];
      int akmOff = 8 + pc*4;
      if (rl >= akmOff + 6) {
        uint16_t ac = (rsn[akmOff]<<8)|rsn[akmOff+1];
        if (ac >= 1 && rl >= akmOff + 2 + 4) {
          uint8_t akmType = rsn[akmOff+2+3];
          if (akmType==6||akmType==12||akmType==13) return "WPA3";
          if (akmType==8) return "OWE";
        }
      }
    }
    return "WPA2";
  }
  const uint8_t* v; int vl;
  if (getTag(f, len, 221, &v, &vl)) {
    if (vl >= 6 && v[0]==0x00 && v[1]==0x50 && v[2]==0xF2 && v[3]==0x01) return "WPA";
  }
  return "开放";
}
bool isEapolFrame(const uint8_t* f, int len) {
  // 数据帧 LLC SNAP: AA AA 03 00 00 00 88 8E，查找偏移 24..len-8
  for (int i=24; i+1<len && i<48; i++) {
    if (f[i]==0x88 && f[i+1]==0x8E) {
      if (i>=6 && f[i-6]==0xAA && f[i-5]==0xAA && f[i-4]==0x03) return true;
    }
  }
  return false;
}

void addAP(const uint8_t* bssid, const char* ssid, const char* enc, uint8_t ch, int8_t rssi, bool viaProbe) {
  uint32_t now = millis();
  for (size_t i=0;i<aps.size();i++) {
    if (sameMac(aps[i].bssid, bssid)) {
      aps[i].rssi = rssi; aps[i].channel = ch; aps[i].packets++;
      aps[i].lastSeen = now;
      if (viaProbe) aps[i].viaProbe = true;
      if (ssid[0]) { strncpy(aps[i].ssid, ssid, 32); aps[i].ssid[32]=0; }
      if (String(aps[i].enc)=="未知") strncpy(aps[i].enc, enc, 9);
      // rogue 复查（信任 SSID 变更是低频事件，此处检查一次便宜）
      if (aps[i].rogue) {
        if (ssidInTrust(aps[i].ssid) && bssidInTrust(bssid)) aps[i].rogue = false;
      }
      return;
    }
  }
  if (aps.size() >= MAX_APS) return;
  ApInfo a; memset(&a,0,sizeof(a));
  memcpy(a.bssid, bssid, 6);
  strncpy(a.ssid, ssid, 32); a.ssid[32]=0;
  strncpy(a.enc, enc, 9); a.enc[9]=0;
  String o = ouiLookup(bssid); o.toCharArray(a.oui, 24);
  a.channel = ch; a.rssi = rssi; a.packets = 1; a.firstSeen = now; a.lastSeen = now;
  a.viaProbe = viaProbe;
  // 非法 AP 判定：SSID 属于信任 SSID，但 BSSID 不在白名单 -> rogue
  if (ssidInTrust(a.ssid) && !bssidInTrust(bssid)) {
    a.rogue = true;
    // 同一 MAC 只告警一次
    if (!lastRogueSet || !sameMac(lastRogueMac, bssid)) {
      lastRogueSet = true;
      memcpy(lastRogueMac, bssid, 6);
      pushEvent(3, macStr(bssid).c_str(), "发现同名疑似钓鱼AP: %s (%s) ch=%d", a.ssid, macStr(bssid).c_str(), ch);
    }
  }
  // 开放网络事件：只对非隐藏、非组播、非自身热点
  if (String(enc)=="开放" && ssid[0] && !(ssid[0]=='E' && strstr(ssid,"Sniffer"))) {
    // 放在 addAP 完成后再推送（外部处理，避免重复）
  }
  aps.push_back(a);
}

void touchDev(const uint8_t* mac, int8_t rssi, uint8_t ch, const uint8_t* f, int len, bool isData) {
  if (isIgnorable(mac) || (mac[0]&0x01)) return;
  uint32_t now = millis();
  int found = -1;
  for (size_t i=0;i<devs.size();i++) if (sameMac(devs[i].mac, mac)) { found=(int)i; break; }
  if (found >= 0) {
    devs[found].rssi = rssi; devs[found].packets++;
    devs[found].lastSeen = now;
    if (!isData && f && len>0) {
      String ps = parseSSID(f, len);
      if (ps.length()>0) ps.toCharArray(devs[found].lastProbeSsid, 33);
    }
    return;
  }
  if (devs.size() >= MAX_DEVS) return;
  DevInfo d; memset(&d,0,sizeof(d));
  memcpy(d.mac, mac, 6);
  d.rssi = rssi; d.packets = 1; d.firstSeen = now; d.lastSeen = now;
  d.apIdx = -1;
  String o = ouiLookup(mac); o.toCharArray(d.oui, 24);
  if (!isData && f && len>0) {
    String ps = parseSSID(f, len);
    if (ps.length()>0) ps.toCharArray(d.lastProbeSsid, 33);
  }
  devs.push_back(d);
  if (devName(mac).length()==0) {
    pushEvent(1, macStr(mac).c_str(), "发现未识别设备 %s rssi=%d %s", macStr(mac).c_str(), rssi, d.oui);
  }
}

// ================= 抓包回调 =================
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t* ctrl = &pkt->rx_ctrl;
  uint8_t* f = pkt->payload;
  int len = ctrl->sig_len;
  if (len < 24) return;
  uint32_t nowMs = millis();
  totalPackets++;
  uint16_t fc = f[0] | (f[1]<<8);
  uint8_t ft = (fc>>2)&0x03;
  uint8_t st = (fc>>4)&0x0F;
  bool toDS = f[1]&0x01, fromDS = f[1]&0x02;
  const uint8_t* addr1=f+4; const uint8_t* addr2=f+10; const uint8_t* addr3=f+16;

  // pcap 环形缓存（管理帧才存，防 RAM 爆）
  if (pcapEnable && ft==0 && len<=PCAP_MAXLEN+24 && len>=24) {
    PcapSlot& s = pcap[pcapHead];
    s.tsMs = nowMs; s.rssi = ctrl->rssi; s.ch = ctrl->channel; s.len = (uint16_t)len;
    memcpy(s.data, f, len);
    pcapHead = (pcapHead+1) % PCAP_SLOTS;
    if (pcapCount < PCAP_SLOTS) pcapCount++;
  }

  // 信道体检累计
  if (surveyActive && ctrl->channel == surveyCur) {
    surveyAccPkt++;
    if (ft==0) {
      if (st==8) surveyAccBeacon++;
      if (st==12||st==10) surveyAccDeauth++;
    }
  }

  portENTER_CRITICAL(&mux);
  if (ft==0) {
    cntMgmt++;
    if (st==8) { // Beacon
      cntBeacon++;
      String ssid = parseSSID(f,len);
      String enc  = parseEnc(f,len);
      char s[33],e[10]; ssid.toCharArray(s,33); enc.toCharArray(e,10);
      addAP(addr2, s, e, ctrl->channel, ctrl->rssi, false);
      int ai = findApIdx(addr2);
      if (ai>=0) aps[ai].beaconCnt++;
    } else if (st==5) { // Probe Resp
      cntProbeResp++;
      String ssid=parseSSID(f,len); String enc=parseEnc(f,len);
      char s[33],e[10]; ssid.toCharArray(s,33); enc.toCharArray(e,10);
      addAP(addr2,s,e,ctrl->channel,ctrl->rssi,true);
    } else if (st==4) { // Probe Req
      cntProbeReq++;
      // 发送方是设备（STA），解析其询问的 SSID 做暴露面
      if (!isKnownAP(addr2)) {
        touchDev(addr2, ctrl->rssi, ctrl->channel, f, len, false);
        // 关联拓扑：Probe 期间无 AP，跳过
      } else {
        // AP 主动探测，忽略
      }
    } else if (st==12) { cntDeauth++; burstCnt++; }
    else if (st==10) { cntDisassoc++; burstCnt++; }
    else if (st==11) { cntAuth++; }
    else if (st==0 || st==1) { cntAssoc++; }
    else {
      if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi, ctrl->channel, NULL, 0, false);
    }
  } else if (ft==2) {
    cntData++;
    // EAPOL 握手检测
    if (len>=32 && isEapolFrame(f,len)) {
      cntEapol++;
    }
    // 关联拓扑：找帧中含 AP BSSID 的一端，另一端为 STA
    int ai = findApIdx(addr1);
    if (ai<0) ai = findApIdx(addr2);
    if (ai<0) ai = findApIdx(addr3);
    if (ai>=0) {
      // addr2 通常为发送方 STA（除非 addr2 是 AP 本身）
      if (!isKnownAP(addr2)) {
        touchDev(addr2, ctrl->rssi, ctrl->channel, NULL, 0, true);
        for (size_t i=0;i<devs.size();i++)
          if (sameMac(devs[i].mac, addr2)) devs[i].apIdx = ai;
      }
    } else {
      if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi, ctrl->channel, NULL, 0, true);
    }
  } else {
    cntCtrl++;
    if (!isKnownAP(addr2)) touchDev(addr2, ctrl->rssi, ctrl->channel, NULL, 0, false);
  }
  portEXIT_CRITICAL(&mux);
}

void sendProbeRequest() {
  uint8_t frame[26] = {0};
  frame[0]=0x40; frame[1]=0x00;
  memset(frame+4,0xFF,6);
  uint8_t mac[6]={0};
  esp_wifi_get_mac(WIFI_IF_AP, mac);
  memcpy(frame+10,mac,6);
  memset(frame+16,0xFF,6);
  frame[24]=0; frame[25]=0;
  esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), true);
  totalProbes++;
}

// ================= 网页基础 =================
String encBadge(const String& enc) {
  if (enc=="开放") return "<span style='color:#ff7b72;font-weight:600'>开放!</span>";
  return enc;
}
String pageHeader(const char* title, const char* ver, bool refresh) {
  String h = "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  if (refresh) h += "<meta http-equiv='refresh' content='5'>";
  h += "<title>";
  h += title;
  h += "</title><style>";
  h += ":root{--bg:#0b0e17;--panel:#12182b;--panel2:#1a2238;--line:#273050;--txt:#dbe4f5;--dim:#7e8aa8;--acc:#34d399;--acc2:#0ea5e9;--blue:#93b4f8;--yellow:#ffd166;--red:#ff7b72}";
  h += "*{box-sizing:border-box}body{margin:0;font-family:system-ui,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:radial-gradient(1200px 500px at 20% -10%,#141d3a 0%,var(--bg) 55%);color:var(--txt);min-height:100vh}";
  h += ".wrap{max-width:1120px;margin:0 auto;padding:12px 14px 26px}";
  h += ".top{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:linear-gradient(135deg,#111a33,#0d1224);border:1px solid var(--line);border-radius:16px;padding:12px 16px;margin-bottom:12px}";
  h += ".logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,#10b981,#0ea5e9);color:#04121c;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;letter-spacing:.5px;box-shadow:0 4px 14px rgba(16,185,129,.25)}";
  h += ".ttl{font-size:17px;font-weight:800;letter-spacing:.3px}.ttl em{font-style:normal;color:var(--acc)}.sub{font-size:11px;color:var(--dim);margin-top:2px}";
  h += ".sp{flex:1}.pill{font-size:11px;border:1px solid var(--line);border-radius:99px;padding:4px 10px;color:var(--dim);background:#0e1426;white-space:nowrap}";
  h += ".pill.ok{color:#9ff0cd;border-color:#1c5c43;background:#0e241b}.pill.warn{color:#ffe1a0;border-color:#6b4d14;background:#241c0c}";
  h += "nav.tabs{display:flex;flex-wrap:wrap;gap:5px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:7px;margin-bottom:14px}";
  h += "nav.tabs a{display:block;padding:7px 13px;border-radius:9px;color:var(--dim);text-decoration:none;font-size:13px;font-weight:600;border:1px solid transparent}";
  h += "nav.tabs a:hover{color:#fff;background:var(--panel2)}nav.tabs a.on{color:#04120c;background:var(--acc)}";
  h += ".pagepanel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px 18px;margin-bottom:16px;box-shadow:0 6px 24px rgba(0,0,0,.22)}";
  h += "section.panel{background:#0e1426;border:1px solid var(--line);border-radius:14px;padding:14px 16px;margin:0 0 16px}";
  h += "h2{font-size:15px;margin:20px 0 12px;color:var(--blue);display:flex;align-items:center;gap:8px;letter-spacing:.3px}h2::before{content:'';width:4px;height:16px;border-radius:2px;background:linear-gradient(180deg,var(--acc),var(--acc2));display:inline-block;flex:none}";
  h += ".grid,.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-bottom:14px}";
  h += ".stat,.card{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px 14px}.stat b,.card b{display:block;font-size:22px;font-variant-numeric:tabular-nums;color:#fff;line-height:1.25}.stat span,.card span{font-size:11px;color:var(--dim)}";
  h += ".alert,.ok{border-radius:12px;padding:10px 14px;margin:0 0 14px;font-size:13px;border:1px solid}.alert{background:rgba(255,123,114,.08);border-color:rgba(255,123,114,.45);color:#ffb4ae;border-left:4px solid var(--red)}.ok{background:rgba(52,211,153,.07);border-color:rgba(52,211,153,.4);color:#a7f3d4;border-left:4px solid var(--acc)}";
  h += ".ops{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin:0 0 16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--dim)}.ops .lbl{font-weight:700;color:var(--txt);margin-right:4px}";
  h += "table{width:100%;border-collapse:collapse;font-size:13px;background:#0f1526;border-radius:12px;overflow:hidden;border:1px solid var(--line)}";
  h += "th{background:#1c2440;color:#9fb0d8;text-align:left;padding:9px 11px;font-weight:700;white-space:nowrap;border-bottom:1px solid var(--line)}td{padding:8px 11px;border-top:1px solid #1c2440;vertical-align:middle}tr:hover td{background:#182036}";
  h += ".badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px}.b-red{background:rgba(255,123,114,.15);color:#ff8f88}.b-green{background:rgba(52,211,153,.15);color:#6ee7b7}.b-yellow{background:rgba(255,209,102,.15);color:#ffd166}.b-blue{background:rgba(147,184,248,.15);color:#93b4f8}.b-dim{background:rgba(126,138,168,.15);color:#9aa5c0}";
  h += ".rssi-good{color:#6ee7b7}.rssi-mid{color:#ffd166}.rssi-bad{color:#ff7b72}.stranger{color:#ff9d95;font-weight:700}.rogue{color:#ff7b72;font-weight:800}";
  h += ".dim{color:var(--dim);font-size:12px}.mono{font-family:Consolas,Menlo,monospace;font-size:12px}";
  h += ".btn{display:inline-block;padding:7px 15px;border-radius:9px;font-size:13px;font-weight:600;text-decoration:none;cursor:pointer;border:0;color:#04120c;background:linear-gradient(135deg,#34d399,#0ea5e9);box-shadow:0 3px 10px rgba(16,185,129,.2)}";
  h += ".btn:hover{filter:brightness(1.1)}.btn.sec{background:#2b3452;color:#c9d4ef;box-shadow:none}.btn.danger{background:linear-gradient(135deg,#f87171,#dc2626);color:#fff}";
  h += "input,select,textarea{padding:7px 10px;border:1px solid #33406b;border-radius:9px;background:#0d1326;color:var(--txt);font-size:13px}input:focus{outline:none;border-color:var(--acc2)}button{font-family:inherit}";
  h += "form.inline{display:inline}.frow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:4px 0}label{font-size:12px;color:var(--dim)}";
  h += "canvas{background:#0f1526;border-radius:12px;width:100%;height:140px;border:1px solid var(--line);margin-top:4px}";
  h += ".foot{text-align:center;color:#59658a;font-size:11px;margin-top:10px;line-height:1.9}.foot a{color:#7f93c9;text-decoration:none;margin:0 6px}";
  h += "@media(max-width:640px){.wrap{padding:8px}.ttl{font-size:15px}.stat b,.card b{font-size:19px}.top{padding:10px 12px}}";
  h += "</style></head><body><div class='wrap'>";
  h += "<header class='top'><div class='logo'>C3</div><div><div class='ttl'>ESP32-C3 <em>Sniffer</em> " + String(ver) + "</div><div class='sub'>无线嗅探 · 信道体检 · 安全巡检 · 事件告警</div></div><div class='sp'></div>";
  if (WiFi.status()==WL_CONNECTED) h += "<span class='pill ok'>局域网 http://" + WiFi.localIP().toString() + "</span>";
  h += "<span class='pill'>热点 192.168.4.1</span></header>";
  String cur="";
  String t=String(title);
  if (t=="实时状态") cur="/";
  else if (t=="信任与防钓鱼") cur="/protect";
  else if (t=="设备命名（白名单）") cur="/names";
  else if (t=="事件时间线") cur="/events";
  else if (t=="信道体检") cur="/survey";
  else if (t=="体检报告") cur="/report";
  else if (t=="信号打点") cur="/qtest";
  else if (t=="打点记录") cur="/qpoints";
  else if (t=="主动测速") cur="/aptest";
  else if (t.indexOf("Webhook")>=0) cur="/hook";
  else if (t=="局域网配网") cur="/config";
  auto oncls=[&](const char* p){ return String(cur==p?"on":""); };
  h += "<nav class='tabs'><a href='/' class='"+oncls("/")+"'>状态</a>";
  h += "<a href='/protect' class='"+oncls("/protect")+"'>防钓鱼</a>";
  h += "<a href='/names' class='"+oncls("/names")+"'>设备命名</a>";
  h += "<a href='/events' class='"+oncls("/events")+"'>事件</a>";
  h += "<a href='/survey' class='"+oncls("/survey")+"'>信道体检</a>";
  h += "<a href='/report' class='"+oncls("/report")+"'>体检报告</a>";
  h += "<a href='/qtest' class='"+oncls("/qtest")+"'>信号打点</a>";
  h += "<a href='/qpoints' class='"+oncls("/qpoints")+"'>打点记录</a>";
  h += "<a href='/aptest' class='"+oncls("/aptest")+"'>主动测速</a>";
  h += "<a href='/hook' class='"+oncls("/hook")+"'>Webhook</a>";
  h += "<a href='/config' class='"+oncls("/config")+"'>配网</a></nav><main><div class='pagepanel'>";
  return h;
}
String pageOps() {
  String o = "<div class='ops'><span class='lbl'>快捷操作</span>";
  o += "<a class='btn' href='/survey?start=1'>开始信道体检</a>";
  o += autoHop ? "<a class='btn sec' href='/set?ch=0'>信道自动轮换中</a>" : "<a class='btn sec' href='/set?ch=0'>自动轮换信道</a>";
  o += activeScan ? "<a class='btn sec' href='/scan?on=0'>关闭主动扫描</a>" : "<a class='btn sec' href='/scan?on=1'>开启主动扫描</a>";
  o += "<span style='flex:1'></span><span>当前信道 CH"+String(curChannel)+" · 收包 "+String((unsigned long)totalPackets)+"</span>";
  return o + "</div>";
}
String pageFoot() {
  String f = "</div></main><div class='foot'>ESP32-C3 Sniffer v2.3 · MAC " + WiFi.macAddress() + " · 运行 " + String((unsigned long)(millis()/60000)) + " 分钟<br>";
  f += "REST API: <a href='/api/stats'>stats</a> <a href='/api/aps'>aps</a> <a href='/api/devs'>devs</a> <a href='/api/events'>events</a> <a href='/api/survey'>survey</a> <a href='/api/topo'>topo</a> <a href='/api/hist'>hist</a> <a href='/api/metrics'>metrics</a> · <a href='/dump'>pcap 导出</a>";
  f += "</div></body></html>";
  return f;
}

String jsonEscape(String s) {
  s.replace("\\","\\\\"); s.replace("\"","\\\""); s.replace("\n"," "); s.replace("\r"," ");
  return s;
}

// ---------------- 实时图表数据 ----------------
String histJson() {
  String j="[";
  for (int i=0;i<HIST_N;i++) {
    if (i) j+=",";
    j += String((unsigned long)rateHist[(rateIdx+i)%HIST_N]);
  }
  return j+"]";
}

// ================= 主页面 =================
String buildHTML() {
  String html = pageHeader("实时状态", "ESP32-C3 Sniffer v2.3", false);
  if (deauthAlert) html += "<div class='alert'>⚠ 疑似 deauth/disassoc 风暴！历史 " + String((unsigned long)deauthStormTimes) + " 次 <a href='/clearalert' style='color:#a5b4fc'>清除告警</a></div>";

  html += "<div class='cards'>";
  char tmp[64];
  auto card=[&](const char* v,const char* l){ html += "<div class='card'><b>"+String(v)+"</b><span>"+String(l)+"</span></div>"; };
  snprintf(tmp,sizeof(tmp),"%lu",(unsigned long)totalPackets); card(tmp,"收包总数");
  snprintf(tmp,sizeof(tmp),"%d",curChannel); card(tmp,"信道");
  snprintf(tmp,sizeof(tmp),"%d",(int)aps.size()); card(tmp,"附近WiFi");
  snprintf(tmp,sizeof(tmp),"%d",(int)devs.size()); card(tmp,"活跃设备");
  snprintf(tmp,sizeof(tmp),"%lu",(unsigned long)cntEapol); card(tmp,"WPA握手");
  snprintf(tmp,sizeof(tmp),"%lu",(unsigned long)deauthStormTimes); card(tmp,"风暴次数");
  html += "</div>";

  int rogueN=0,openN=0,secureN=0;
  for (size_t i=0;i<aps.size();i++) { if(aps[i].rogue)rogueN++; if(String(aps[i].enc)=="开放")openN++; else if(String(aps[i].enc)!="未知")secureN++; }
  if (rogueN>0) html += "<div class='alert'>⚠ 发现 <b>" + String(rogueN) + "</b> 个疑似钓鱼 AP（与信任 SSID 同名但 BSSID 不在白名单）</div>";
  if (openN>0 && rogueN==0) html += "<div class='alert'>注意：附近有 <b>" + String(openN) + "</b> 个开放网络（无加密）</div>";

  html += pageOps();

  // 实时速率图
  html += "<section class='panel'><h2>收包速率（pps，最近 60 秒）</h2><canvas id='cv'></canvas></section>";

  html += "<section class='panel'><h2>附近 WiFi（AP）</h2><table><tr><th>SSID</th><th>加密</th><th>厂商</th><th>BSSID</th><th>信道</th><th>信号</th><th>包</th><th>状态</th></tr>";
  for (size_t i=0;i<aps.size();i++) {
    String s=String(aps[i].ssid); if(s.length()==0)s="(隐藏)";
    html += "<tr><td>"+s+"</td><td>"+encBadge(aps[i].enc)+"</td><td class='dim'>"+String(aps[i].oui)+"</td><td class='dim'>"+macStr(aps[i].bssid)+"</td><td>"+String(aps[i].channel)+"</td><td class='";
    html += (aps[i].rssi>=-60?"rssi-good":(aps[i].rssi>=-75?"rssi-mid":"rssi-bad"));
    html += "'>"+String(aps[i].rssi)+" dBm</td><td>"+String(aps[i].packets)+"</td><td>";
    if (aps[i].rogue) html += "<span class='rogue'>钓鱼!</span>";
    else if (String(aps[i].enc)=="开放") html += "<span class='stranger'>开放</span>";
    else html += "<span class='rssi-good'>正常</span>";
    html += "</td></tr>";
  }
  html += "</table></section>";

  html += "<section class='panel'><h2>活跃设备（关联拓扑）</h2><table><tr><th>名称</th><th>MAC</th><th>厂商</th><th>信号</th><th>包</th><th>连接</th><th>探测</th><th>最近</th></tr>";
  for (size_t i=0;i<devs.size();i++) {
    String name=devName(devs[i].mac);
    uint32_t age=millis()-devs[i].lastSeen;
    html += "<tr><td>"+(name.length()?name:"<span class='stranger'>未识别</span>")+"</td><td>"+macStr(devs[i].mac)+"</td><td class='dim'>"+String(devs[i].oui)+"</td><td class='";
    html += (devs[i].rssi>=-60?"rssi-good":(devs[i].rssi>=-75?"rssi-mid":"rssi-bad"));
    html += "'>"+String(devs[i].rssi)+"</td><td>"+String(devs[i].packets)+"</td><td>";
    if (devs[i].apIdx>=0 && devs[i].apIdx<(int)aps.size()) html += String(aps[devs[i].apIdx].ssid)+" <span class='dim'>ch"+String(aps[devs[i].apIdx].channel)+"</span>";
    else html += "<span class='dim'>未关联</span>";
    html += "</td><td class='dim'>"+(String(devs[i].lastProbeSsid).length()?String(devs[i].lastProbeSsid):"-")+"</td><td class='dim'>";
    if (age<5000) html += "刚刚"; else if (age<30000) html += String(age/1000)+"秒前"; else html += String(age/60000)+"分钟前";
    html += "</td></tr>";
  }
  html += "</table></section>";
  html += "<script>const cv=document.getElementById('cv'),ctx=cv.getContext('2d');async function draw(){try{const r=await fetch('/api/hist');const a=await r.json();cv.width=cv.clientWidth*2;cv.height=240;ctx.clearRect(0,0,cv.width,cv.height);const w=cv.width/a.length;const m=Math.max(...a,1);ctx.strokeStyle='#7ee787';ctx.beginPath();a.forEach((v,i)=>{const y=230-(v/m)*220;if(i)ctx.lineTo(i*w+w/2,y);else ctx.moveTo(i*w+w/2,y);});ctx.stroke();}catch(e){}}draw();setInterval(draw,2000);</script>";
  html += pageFoot();
  return html;
}

// ================= 事件页 =================
String eventsHTML() {
  String h = pageHeader("事件时间线", "ESP32-C3 Sniffer v2.3", true);
  h += pageOps();
  h += "<h2>最近事件（最多100条）</h2><table><tr><th>类型</th><th>时间</th><th>MAC</th><th>描述</th></tr>";
  for (size_t i=events.size(); i-- > 0;) {
    h += "<tr><td>"+String(evTypeName(events[i].type))+"</td><td class='dim'>"+String(events[i].tMs/1000)+"s</td><td class='dim'>"+String(events[i].mac)+"</td><td>"+String(events[i].desc)+"</td></tr>";
  }
  h += "</table>";
  h += pageFoot();
  return h;
}

// ================= 信任/防钓鱼 =================
String protectHTML() {
  String h = pageHeader("信任与防钓鱼", "ESP32-C3 Sniffer v2.3", false);
  h += pageOps();
  h += "<div class='ok'>机制：在下方登记本家路由器 SSID（如 TP-LINK_5G）+ BSSID 白名单。此后若出现 <b>同名但 BSSID 不同</b> 的热点，将被标记为疑似钓鱼 AP 并推事件。</div>";
  h += "<h2>当前配置</h2><table><tr><th>信任 SSID</th><th>信任 BSSID（逗号分隔）</th></tr>";
  h += "<tr><td>"+jsonEscape(getTrustSsid())+"</td><td class='dim'>"+jsonEscape(getTrustBssid())+"</td></tr></table>";
  h += "<h2>登记</h2><form method='GET' action='/trust'><table style='max-width:520px'><tr><th>本家 SSID</th><th>本家 BSSID</th></tr>";
  h += "<tr><td><input name='ssid' value='"+jsonEscape(getTrustSsid())+"' style='width:150px'></td>";
  h += "<td><input name='bssid' value='"+jsonEscape(getTrustBssid())+"' style='width:220px'></td></tr></table>";
  h += "<button type='submit'>保存白名单</button></form>";
  h += "<h2>把当前看到的 AP 加入信任（需先填 SSID）</h2><table><tr><th>SSID</th><th>BSSID</th><th>加密</th><th>操作</th></tr>";
  for (size_t i=0;i<aps.size();i++) {
    h += "<tr><td>"+String(aps[i].ssid)+"</td><td>"+macStr(aps[i].bssid)+"</td><td>"+encBadge(aps[i].enc)+"</td><td><a href='/trustone?ssid="+String(aps[i].ssid)+"&bssid="+macStr(aps[i].bssid)+"' style='color:#a5b4fc'>加入信任</a></td></tr>";
  }
  h += "</table>";
  h += pageFoot();
  return h;
}
void handleTrust() {
  String ssid=server.arg("ssid"), bssid=server.arg("bssid");
  ssid.trim(); bssid.trim();
  if (ssid.length()) prefs.putString("tssid", ssid);
  if (bssid.length()) prefs.putString("tbssid", bssid);
  // 复查所有 AP：白名单内去掉 rogue
  for (size_t i=0;i<aps.size();i++) {
    if (aps[i].rogue && ssidInTrust(aps[i].ssid) && bssidInTrust(aps[i].bssid)) aps[i].rogue=false;
  }
  pushEvent(8,NULL,"白名单已更新: SSID=[%s] BSSID=[%s]", ssid.c_str(), bssid.c_str());
  server.send(200,"text/html; charset=utf-8","<html><body style='background:#0f1220;color:#d8e0f0;padding:30px'><h2>已保存</h2><p><a href='/protect'>返回</a></p></body></html>");
}
void handleTrustOne() {
  String ssid=server.arg("ssid"), bssid=server.arg("bssid");
  ssid.trim(); bssid.trim();
  if (bssid.length()<17) { server.send(400,"text/plain","need valid bssid"); return; }
  // 解析 MAC 字符串 XX:XX:XX:XX:XX:XX
  uint8_t mac[6]; bool ok=true;
  for (int i=0;i<6;i++) {
    unsigned int b;
    if (sscanf(bssid.c_str()+i*3, "%2x", &b)!=1) { ok=false; break; }
    mac[i]=(uint8_t)b;
  }
  if (!ok) { server.send(400,"text/plain","bad bssid format"); return; }
  String tss=getTrustSsid(), tbs=getTrustBssid();
  if (ssid.length() && !ssidInTrust(ssid.c_str())) { if(tss.length())tss+=","; tss+=ssid; prefs.putString("tssid",tss); }
  if (!bssidInTrust(mac)) { if(tbs.length())tbs+=","; tbs+=macStr(mac); prefs.putString("tbssid",tbs); }
  for (size_t i=0;i<aps.size();i++) if (aps[i].rogue && ssidInTrust(aps[i].ssid) && bssidInTrust(aps[i].bssid)) aps[i].rogue=false;
  pushEvent(8,NULL,"加入信任: %s / %s", ssid.c_str(), macStr(mac).c_str());
  server.sendHeader("Location","/protect"); server.send(302,"text/plain","ok");
}

// ================= 信道体检 =================
void startSurvey() {
  if (surveyActive) return;
  if (sig.running || apt.running) { pushEvent(0,NULL,"体检暂缓：信号打点/主动测速进行中"); return; }
  surveyActive = true; surveyRunning = true;
  surveyCur = 1; surveyChStart = millis(); surveyStartMs = millis();
  memset(survey,0,sizeof(survey));
  surveyAccPkt=0; surveyAccBeacon=0; surveyAccDeauth=0;
  curChannel = 1;
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  pushEvent(7,NULL,"信道体检开始（13 信道 × %d 秒）", SURVEY_CH_MS/1000);
}
void surveyTick() {
  if (!surveyActive) return;
  uint32_t now=millis();
  if (now - surveyChStart >= SURVEY_CH_MS) {
    survey[surveyCur].pkt = surveyAccPkt;
    survey[surveyCur].beacon = surveyAccBeacon;
    survey[surveyCur].deauth = surveyAccDeauth;
    surveyAccPkt=0; surveyAccBeacon=0; surveyAccDeauth=0;
    surveyCur++;
    if (surveyCur > 13) {
      // 完成
      surveyActive=false; surveyRunning=false;
      // 统计 AP 数（按信道）
      for (size_t i=0;i<aps.size();i++) { int c=aps[i].channel; if(c>=1&&c<=13) survey[c].apCnt++; }
      // 推荐信道：空闲（包少、AP少、deauth少）
      int best=1; uint32_t bestScore=0xFFFFFFFF;
      for (int c=1;c<=13;c++) {
        uint32_t score = survey[c].pkt*4 + survey[c].apCnt*40 + survey[c].deauth*30;
        if (score<bestScore) { bestScore=score; best=c; }
      }
      surveySummary = "推荐信道: CH"+String(best)+"（该信道最近流量最空闲）";
      pushEvent(7,NULL,"体检完成 13 信道，%s", surveySummary.c_str());
      return;
    }
    esp_wifi_set_channel(surveyCur, WIFI_SECOND_CHAN_NONE);
    curChannel = surveyCur;
    surveyChStart = now;
  }
}
String surveyHTML() {
  String h = pageHeader("信道体检", "ESP32-C3 Sniffer v2.3", true);
  h += pageOps();
  if (surveyActive) h += "<div class='alert'>正在体检：信道 "+String(surveyCur)+"/13（每信道 "+String(SURVEY_CH_MS/1000)+" 秒）...</div>";
  else if (surveySummary.length()) h += "<div class='ok'>"+surveySummary+"</div>";
  h += "<h2>13 信道占用（最近一次体检）</h2><table><tr><th>信道</th><th>包数</th><th>Beacon</th><th>Deauth</th><th>AP数</th><th>空闲度</th></tr>";
  for (int c=1;c<=13;c++) {
    uint32_t score = survey[c].pkt*4 + survey[c].apCnt*40 + survey[c].deauth*30;
    const char* cls = (score<2000?"rssi-good":(score<6000?"rssi-mid":"rssi-bad"));
    h += "<tr><td>"+String(c)+"</td><td>"+String((unsigned long)survey[c].pkt)+"</td><td>"+String((unsigned long)survey[c].beacon)+"</td><td>"+String((unsigned long)survey[c].deauth)+"</td><td>"+String((int)survey[c].apCnt)+"</td><td class='"+cls+"'>"+String(score<2000?"空闲":(score<6000?"一般":"拥挤"))+"</td></tr>";
  }
  h += "</table>";
  h += "<p style='margin-top:12px'><a class='btn' href='/survey?start=1'>立即开始体检</a></p>";
  h += pageFoot();
  return h;
}
void handleSurvey() {
  if (server.hasArg("start")) { startSurvey(); server.sendHeader("Location","/survey"); server.send(302,"text/plain","start"); return; }
  server.send(200,"text/html; charset=utf-8", surveyHTML());
}

// ================= 体检报告 =================
String reportHTML() {
  String h = pageHeader("体检报告", "ESP32-C3 Sniffer v2.3", true);
  h += pageOps();
  int rogueN=0,openN=0,wpa2=0,wpa3=0,wpa=0;
  for (size_t i=0;i<aps.size();i++) {
    if(aps[i].rogue)rogueN++;
    if(String(aps[i].enc)=="开放")openN++;
    else if(String(aps[i].enc)=="WPA3")wpa3++;
    else if(String(aps[i].enc)=="WPA2")wpa2++;
    else if(String(aps[i].enc)=="WPA")wpa++;
  }
  h += "<h2>概要</h2><div class='cards'>";
  char tmp[64];
  snprintf(tmp,sizeof(tmp),"%lu",(unsigned long)(millis()/60000)); h += "<div class='card'><b>"+String(tmp)+"</b><span>运行(分钟)</span></div>";
  snprintf(tmp,sizeof(tmp),"%d",(int)aps.size()); h += "<div class='card'><b>"+String(tmp)+"</b><span>AP</span></div>";
  snprintf(tmp,sizeof(tmp),"%d",(int)devs.size()); h += "<div class='card'><b>"+String(tmp)+"</b><span>设备</span></div>";
  snprintf(tmp,sizeof(tmp),"%d",rogueN); h += "<div class='card'><b>"+String(tmp)+"</b><span>钓鱼AP</span></div>";
  snprintf(tmp,sizeof(tmp),"%d",openN); h += "<div class='card'><b>"+String(tmp)+"</b><span>开放网络</span></div>";
  h += "</div>";
  h += "<h2>加密分布（可见 AP）</h2><table><tr><th>开放</th><th>WPA</th><th>WPA2</th><th>WPA3</th><th>未知</th></tr><tr><td>"+String(openN)+"</td><td>"+String(wpa)+"</td><td>"+String(wpa2)+"</td><td>"+String(wpa3)+"</td><td>"+String((int)aps.size()-openN-wpa-wpa2-wpa3)+"</td></tr></table>";
  h += "<h2>帧统计</h2><table><tr><th>总包</th><th>管理</th><th>数据</th><th>控制</th><th>Beacon</th><th>ProbeReq</th><th>ProbeResp</th><th>Deauth</th><th>Disassoc</th><th>Auth</th><th>Assoc</th><th>EAPOL</th></tr>";
  h += "<tr><td>"+String((unsigned long)totalPackets)+"</td><td>"+String((unsigned long)cntMgmt)+"</td><td>"+String((unsigned long)cntData)+"</td><td>"+String((unsigned long)cntCtrl)+"</td><td>"+String((unsigned long)cntBeacon)+"</td><td>"+String((unsigned long)cntProbeReq)+"</td><td>"+String((unsigned long)cntProbeResp)+"</td><td>"+String((unsigned long)cntDeauth)+"</td><td>"+String((unsigned long)cntDisassoc)+"</td><td>"+String((unsigned long)cntAuth)+"</td><td>"+String((unsigned long)cntAssoc)+"</td><td>"+String((unsigned long)cntEapol)+"</td></tr></table>";
  h += "<h2>结论与建议</h2><ul>";
  if (surveySummary.length()) h += "<li>"+surveySummary+"</li>";
  if (rogueN>0) h += "<li>⚠ 发现 "+String(rogueN)+" 个疑似钓鱼 AP，请检查并加入白名单或忽略。</li>";
  else h += "<li>✓ 未发现疑似钓鱼 AP（信任 SSID 同名检测）</li>";
  if (openN>0) h += "<li>⚠ 附近存在 "+String(openN)+" 个开放网络，注意不要误连。</li>";
  if (deauthStormTimes>0) h += "<li>⚠ 累计发生 "+String((unsigned long)deauthStormTimes)+" 次 Deauth 风暴，建议检查是否有干扰器。</li>";
  else h += "<li>✓ 未检测到 Deauth 风暴。</li>";
  int unknown=0; for (size_t i=0;i<devs.size();i++) if(devName(devs[i].mac).length()==0) unknown++;
  if (unknown>0) h += "<li>⚠ 有 "+String(unknown)+" 个未识别设备，建议到设备命名页登记。</li>";
  else h += "<li>✓ 所有设备已登记。</li>";
  if (String(getHook()).length()>0) h += "<li>✓ Webhook 已配置："+jsonEscape(getHook())+"</li>";
  else h += "<li>未配置 Webhook（可选 /hook 页）</li>";
  h += "</ul>";
  h += pageFoot();
  return h;
}
String hookHTML() {
  String h = pageHeader("Webhook 配置", "ESP32-C3 Sniffer v2.3", false);
  h += pageOps();
  h += "<h2>Webhook URL</h2><p class='dim'>事件（陌生人/deauth风暴/钓鱼AP/AP掉线）发生时 POST JSON 到该地址。需 STA 已连网；仅支持 http:// 80 端口。</p>";
  h += "<form method='GET' action='/hooksave'><input name='url' value='"+jsonEscape(getHook())+"' style='width:80%' placeholder='http://192.168.1.100:8080/hook'><button type='submit'>保存</button></form>";
  h += "<p style='margin-top:12px'><a class='btn sec' href='/hooktest'>发送测试事件</a></p>";
  h += pageFoot();
  return h;
}
void handleHookSave() {
  String u=server.arg("url"); u.trim();
  prefs.putString("hook", u);
  server.send(200,"text/plain","hook saved");
}

// ================= JSON API =================
void apiStats() {
  String j="{\"ver\":\"v2.3\",\"uptime_s\":"+String((unsigned long)(millis()/1000))+",\"total_packets\":"+String((unsigned long)totalPackets);
  j+=",\"mgmt\":"+String((unsigned long)cntMgmt)+",\"data\":"+String((unsigned long)cntData)+",\"ctrl\":"+String((unsigned long)cntCtrl);
  j+=",\"beacon\":"+String((unsigned long)cntBeacon)+",\"probe_req\":"+String((unsigned long)cntProbeReq)+",\"probe_resp\":"+String((unsigned long)cntProbeResp);
  j+=",\"deauth\":"+String((unsigned long)cntDeauth)+",\"disassoc\":"+String((unsigned long)cntDisassoc)+",\"auth\":"+String((unsigned long)cntAuth)+",\"assoc\":"+String((unsigned long)cntAssoc);
  j+=",\"eapol\":"+String((unsigned long)cntEapol)+",\"deauth_storm\":"+String((unsigned long)deauthStormTimes);
  j+=",\"channel\":"+String(curChannel)+",\"auto_hop\":"+String(autoHop?"true":"false")+",\"active_scan\":"+String(activeScan?"true":"false");
  j+=",\"ap_count\":"+String((int)aps.size())+",\"dev_count\":"+String((int)devs.size());
  j+=",\"rogue_count\":"+String((int)([&](){int n=0;for(auto&a:aps)if(a.rogue)n++;return n;}()));
  j+=",\"sta\":"+String(WiFi.status()==WL_CONNECTED?"true":"false")+",\"ip\":\""+(WiFi.status()==WL_CONNECTED?WiFi.localIP().toString():"")+"\"}";
  server.send(200,"application/json",j);
}
void apiAps() {
  String j="{\"aps\":[";
  for (size_t i=0;i<aps.size();i++) {
    if(i)j+=",";
    j+="{\"bssid\":\""+macStr(aps[i].bssid)+"\",\"ssid\":\""+jsonEscape(String(aps[i].ssid))+"\",\"enc\":\""+String(aps[i].enc)+"\",\"oui\":\""+String(aps[i].oui)+"\",\"ch\":"+String(aps[i].channel)+",\"rssi\":"+String(aps[i].rssi)+",\"packets\":"+String(aps[i].packets)+",\"rogue\":"+String(aps[i].rogue?"true":"false")+"}";
  }
  j+="]}"; server.send(200,"application/json",j);
}
void apiDevs() {
  String j="{\"devs\":[";
  for (size_t i=0;i<devs.size();i++) {
    if(i)j+=",";
    String nm=devName(devs[i].mac);
    j+="{\"mac\":\""+macStr(devs[i].mac)+"\",\"name\":\""+jsonEscape(nm)+"\",\"oui\":\""+String(devs[i].oui)+"\",\"rssi\":"+String(devs[i].rssi)+",\"packets\":"+String(devs[i].packets);
    j+=",\"ap\":"+String(devs[i].apIdx)+",\"last_probe\":\""+jsonEscape(String(devs[i].lastProbeSsid))+"\",\"last_seen_ms\":"+String((unsigned long)(millis()-devs[i].lastSeen))+"}";
  }
  j+="]}"; server.send(200,"application/json",j);
}
void apiEvents() {
  String j="{\"events\":[";
  for (size_t i=events.size(); i-- > 0;) {
    if(i<events.size()-1) j+=",";
    j+="{\"type\":"+String(events[i].type)+",\"type_name\":\""+evTypeName(events[i].type)+"\",\"t_ms\":"+String((unsigned long)events[i].tMs)+",\"mac\":\""+String(events[i].mac)+"\",\"desc\":\""+jsonEscape(String(events[i].desc))+"\"}";
  }
  j+="]}"; server.send(200,"application/json",j);
}
void apiSurvey() {
  String j="{\"active\":"+String(surveyActive?"true":"false")+",\"summary\":\""+jsonEscape(surveySummary)+"\",\"channels\":[";
  bool first=true;
  for (int c=1;c<=13;c++) {
    if(!first)j+=","; first=false;
    j+="{\"ch\":"+String(c)+",\"pkt\":"+String((unsigned long)survey[c].pkt)+",\"beacon\":"+String((unsigned long)survey[c].beacon)+",\"deauth\":"+String((unsigned long)survey[c].deauth)+",\"ap\":"+String((int)survey[c].apCnt)+"}";
  }
  j+="]}"; server.send(200,"application/json",j);
}
void apiTopo() {
  String j="{\"nodes\":[";
  bool first=true;
  for (size_t i=0;i<devs.size();i++) {
    if(!first)j+=","; first=false;
    j+="{\"mac\":\""+macStr(devs[i].mac)+"\",\"name\":\""+jsonEscape(devName(devs[i].mac))+"\",\"ap\":"+String(devs[i].apIdx)+"}";
  }
  j+="]}"; server.send(200,"application/json",j);
}
void apiHist() { server.send(200,"application/json", histJson()); }

// Prometheus
void apiMetrics() {
  String m="# HELP esp_sniffer 汇总指标\n";
  m+="# TYPE esp_sniffer_packets_total counter\n";
  m+="esp_sniffer_packets_total{type=\"total\"} "+String((unsigned long)totalPackets)+"\n";
  m+="esp_sniffer_packets_total{type=\"mgmt\"} "+String((unsigned long)cntMgmt)+"\n";
  m+="esp_sniffer_packets_total{type=\"data\"} "+String((unsigned long)cntData)+"\n";
  m+="esp_sniffer_packets_total{type=\"ctrl\"} "+String((unsigned long)cntCtrl)+"\n";
  m+="esp_sniffer_packets_total{type=\"beacon\"} "+String((unsigned long)cntBeacon)+"\n";
  m+="esp_sniffer_packets_total{type=\"probe_req\"} "+String((unsigned long)cntProbeReq)+"\n";
  m+="esp_sniffer_packets_total{type=\"deauth\"} "+String((unsigned long)cntDeauth)+"\n";
  m+="esp_sniffer_packets_total{type=\"disassoc\"} "+String((unsigned long)cntDisassoc)+"\n";
  m+="esp_sniffer_packets_total{type=\"eapol\"} "+String((unsigned long)cntEapol)+"\n";
  m+="# TYPE esp_sniffer_deauth_storm_total counter\n";
  m+="esp_sniffer_deauth_storm_total "+String((unsigned long)deauthStormTimes)+"\n";
  m+="# TYPE esp_sniffer_ap_count gauge\nesp_sniffer_ap_count "+String((int)aps.size())+"\n";
  m+="# TYPE esp_sniffer_dev_count gauge\nesp_sniffer_dev_count "+String((int)devs.size())+"\n";
  m+="# TYPE esp_sniffer_rogue_ap_count gauge\nesp_sniffer_rogue_ap_count "+String((int)([&](){int n=0;for(auto&a:aps)if(a.rogue)n++;return n;}()))+"\n";
  m+="# TYPE esp_sniffer_channel gauge\nesp_sniffer_channel "+String(curChannel)+"\n";
  m+="# TYPE esp_sniffer_uptime_seconds gauge\nesp_sniffer_uptime_seconds "+String((unsigned long)(millis()/1000))+"\n";
  server.send(200,"text/plain; version=0.0.4",m);
}

// pcap 导出（流式 chunked 发送，避免大 String 撑爆内存）
void handleDump() {
  if (pcapCount==0) { server.send(200,"text/plain","暂无 pcap 数据（设备刚启动或抓帧缓存为空）"); return; }
  server.sendHeader("Content-Disposition","attachment; filename=sniffer.pcap");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200,"application/vnd.tcpdump.pcap","");
  // 全局头
  uint8_t gh[24];
  uint32_t magic=0xa1b2c3d4; memcpy(gh,&magic,4);
  uint16_t verMaj=2, verMin=4; memcpy(gh+4,&verMaj,2); memcpy(gh+6,&verMin,2);
  int32_t thiszone=0; memcpy(gh+8,&thiszone,4);
  uint32_t sigfigs=0; memcpy(gh+12,&sigfigs,4);
  uint32_t snaplen=PCAP_MAXLEN; memcpy(gh+16,&snaplen,4);
  uint32_t network=105; // LINKTYPE_IEEE802_11
  memcpy(gh+20,&network,4);
  server.sendContent(String((const char*)gh,24));
  uint16_t idx = (pcapHead + PCAP_SLOTS - pcapCount) % PCAP_SLOTS;
  for (uint16_t k=0;k<pcapCount;k++) {
    PcapSlot& s = pcap[idx];
    uint8_t ph[16];
    uint32_t sec = s.tsMs/1000, usec = (s.tsMs%1000)*1000;
    memcpy(ph,&sec,4); memcpy(ph+4,&usec,4);
    uint32_t ilen = s.len, olen = s.len; memcpy(ph+8,&ilen,4); memcpy(ph+12,&olen,4);
    String chunk((const char*)ph,16);
    chunk.concat((const char*)s.data, s.len);
    server.sendContent(chunk);
    idx = (idx+1)%PCAP_SLOTS;
  }
}
// ================= Webhook =================
static uint32_t webhookPushedTs = 0;  // 已成功推送过的事件时间戳（去重）

String hookJsonForEvent(const EvInfo& e) {
  char buf[300];
  snprintf(buf,sizeof(buf),
    "{\"event\":\"%s\",\"type\":%d,\"mac\":\"%s\",\"desc\":\"%s\",\"ts_ms\":%lu,\"uptime_s\":%lu,\"ip\":\"%s\"}",
    evTypeName(e.type), e.type, e.mac, e.desc, (unsigned long)e.tMs,
    (unsigned long)(millis()/1000), (WiFi.status()==WL_CONNECTED?WiFi.localIP().toString().c_str():""));
  return String(buf);
}
// 尝试推送关键事件（type 1/2/3/4），每次最多一条
bool webhookPost(const String& body) {
  String hook = getHook();
  if (hook.length()==0 || WiFi.status()!=WL_CONNECTED) return false;
  if (!hook.startsWith("http://")) return false;
  String rest = hook.substring(7);
  int slash = rest.indexOf('/');
  String hostport = (slash<0?rest:rest.substring(0,slash));
  String path = (slash<0?"/":rest.substring(slash));
  int colon = hostport.indexOf(':');
  String host = (colon<0?hostport:hostport.substring(0,colon));
  int port = (colon<0?80:hostport.substring(colon+1).toInt());
  WiFiClient c;
  if (!c.connect(host.c_str(), port, 3000)) return false;
  c.print(String("POST ")+path+" HTTP/1.1\r\nHost: "+host+":"+port+"\r\nContent-Type: application/json\r\nContent-Length: "+body.length()+"\r\nConnection: close\r\n\r\n"+body);
  unsigned long t0=millis();
  bool gotResp=false;
  while(c.connected() && millis()-t0<2500) { if(c.available()){gotResp=true;break;} delay(1); }
  c.stop();
  return gotResp;
}
void tryWebhook() {
  for (size_t i=events.size(); i-->0;) {
    uint8_t t = events[i].type;
    if ((t==1||t==2||t==3||t==4) && events[i].tMs>webhookPushedTs) {
      if (webhookPost(hookJsonForEvent(events[i]))) webhookPushedTs = events[i].tMs;
      return;
    }
  }
}
void handleHookTest() {
  if (WiFi.status()!=WL_CONNECTED) { server.send(200,"text/plain","未连网，无法推送测试"); return; }
  pushEvent(9,NULL,"Webhook 测试（来自浏览器）");
  EvInfo e; memset(&e,0,sizeof(e)); e.type=9; e.tMs=millis();
  strncpy(e.mac,"--",sizeof(e.mac)-1); e.mac[sizeof(e.mac)-1]=0;
  snprintf(e.desc,sizeof(e.desc),"Webhook 测试");
  bool ok = webhookPost(hookJsonForEvent(e));
  server.send(200,"text/plain", String("test webhook ")+(ok?"delivered":"failed")+" -> "+getHook());
}

// ================= 其它页面 handler =================
String namesHTML() {
  String html = pageHeader("设备命名（白名单）", "ESP32-C3 Sniffer v2.3", true);
  html += pageOps();
  html += "<p class='dim'>给自家设备起名后它不再算陌生人。名字存板子 Preferences，掉电不丢。</p>";
  html += "<table><tr><th>当前名称</th><th>MAC</th><th>厂商</th><th>关联</th><th>操作</th></tr>";
  for (size_t i=0;i<devs.size();i++) {
    String m=macStr(devs[i].mac);
    String name=devName(devs[i].mac);
    html += "<tr><td>"+(name.length()?name:"<span class='dim'>未命名</span>")+"</td><td>"+m+"</td><td class='dim'>"+String(devs[i].oui)+"</td><td class='dim'>";
    if (devs[i].apIdx>=0 && devs[i].apIdx<(int)aps.size()) html += String(aps[devs[i].apIdx].ssid);
    else html += "-";
    html += "</td><td><form method='GET' action='/name' style='display:inline'><input type='hidden' name='mac' value='"+m+"'><input type='text' name='name' placeholder='例如 老板手机' value='"+name+"' style='width:120px'><button type='submit'>保存</button></form> ";
    html += "<form method='GET' action='/name' style='display:inline'><input type='hidden' name='mac' value='"+m+"'><input type='hidden' name='name' value=''><button type='submit' style='background:#3b3f55'>清除</button></form></td></tr>";
  }
  html += "</table>";
  html += pageFoot();
  return html;
}
String configHTML() {
  String html = pageHeader("局域网配网", "ESP32-C3 Sniffer v2.3", false);
  html += "<p class='dim'>填写自家路由器 WiFi，板子连上后可通过局域网 IP 访问。当前已保存配置：</p>";
  html += "<form method='POST' action='/save'><label>WiFi 名称 (SSID)</label><br><input name='ssid' value='"+jsonEscape(prefs.getString("ssid",""))+"' style='width:90%'><br><br>";
  html += "<label>WiFi 密码（留空=不修改/开放网络）</label><br><input type='password' name='pass' style='width:90%'><br><br><button type='submit'>保存并连接</button></form>";
  html += "<p class='dim'>清除配置改回纯热点：访问 /forget 后断电重启</p>";
  html += pageFoot();
  return html;
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nESP32-C3 Sniffer v2.3 starting...");

  prefs.begin("sniffer", false);
  qtNext = prefs.getInt("qtN", 0);
  String savedSSID = prefs.getString("ssid","");
  aps.reserve(MAX_APS);
  devs.reserve(MAX_DEVS);
  events.reserve(MAX_EVENTS);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID);
  if (savedSSID.length()>0) {
    String savedPass = prefs.getString("pass","");
    WiFi.begin(savedSSID.c_str(), savedPass.c_str());
    Serial.print("Connecting LAN: "); Serial.println(savedSSID);
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  if (WiFi.status()==WL_CONNECTED) { curChannel = WiFi.channel(); }
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  server.on("/", handleRoot);
  server.on("/set", handleSet);
  server.on("/scan", handleScan);
  server.on("/clearalert", handleClearAlert);
  server.on("/names", handleNames);
  server.on("/name", handleName);
  server.on("/config", handleConfig);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/forget", handleForget);
  server.on("/protect", handleProtect);
  server.on("/trust", handleTrust);
  server.on("/trustone", handleTrustOne);
  server.on("/events", handleEventsPage);
  server.on("/survey", handleSurvey);
  server.on("/report", handleReport);
  server.on("/hook", handleHook);
  server.on("/hooksave", handleHookSave);
  server.on("/hooktest", handleHookTest);
  server.on("/api/stats", apiStats);
  server.on("/api/aps", apiAps);
  server.on("/api/devs", apiDevs);
  server.on("/api/events", apiEvents);
  server.on("/api/survey", apiSurvey);
  server.on("/api/topo", apiTopo);
  server.on("/api/hist", apiHist);
  server.on("/qtest", handleQtest);
  server.on("/qstart", handleQstart);
  server.on("/qstop", handleQstop);
  server.on("/qstatus", handleQstatus);
  server.on("/qpoints", handleQpoints);
  server.on("/qcsv", handleQcsv);
  server.on("/qclear", handleQclear);
  server.on("/aptest", handleAptest);
  server.on("/astart", handleAstart);
  server.on("/astop", handleAstop);
  server.on("/astatus", handleAstatus);
  server.on("/metrics", apiMetrics);
  server.on("/dump", handleDump);
  server.onNotFound(handleNotFound);
  server.begin();

  pushEvent(0,NULL,"系统启动 v2.3, MAC %s", WiFi.macAddress().c_str());
  Serial.println("AP: ESP32C3-Sniffer -> http://192.168.4.1");
}

void loop() {
  server.handleClient();
  uint32_t now = millis();

  // STA 连上后锁信道
  if (savedSSIDMode() && !surveyActive) {
    if (WiFi.status()==WL_CONNECTED) {
      if (!lanAnnounced) {
        lanAnnounced = true;
        curChannel = WiFi.channel();
        autoHop = false;
        Serial.print("LAN IP: http://"); Serial.println(WiFi.localIP());
        Serial.print("Locked ch="); Serial.println(curChannel);
      }
    }
  }

  // 巡检状态机（优先于自动跳频）
  if (surveyActive) { surveyTick(); }
  else if (autoHop && WiFi.status()!=WL_CONNECTED && now-lastHop>=HOP_INTERVAL_MS) {
    lastHop = now;
    curChannel++; if (curChannel>13) curChannel=1;
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }

  if (activeScan && !surveyActive && now-lastProbe>=PROBE_INTERVAL_MS) {
    lastProbe = now;
    sendProbeRequest();
  }

  // Deauth 风暴检测
  if (now-burstWindowStart>=DEAUTH_BURST_MS) {
    if (burstCnt>=DEAUTH_BURST_N) {
      deauthAlert = true; deauthStormTimes++;
      pushEvent(2,NULL,"Deauth 风暴 %lu 帧/秒", (unsigned long)burstCnt);
    }
    burstCnt = 0;
    burstWindowStart = now;
  }

  // 清理过期 + Beacon 消失监控
  if (now-lastStat>=5000) {
    lastStat = now;
    uint32_t t = millis();
    for (size_t i=aps.size(); i-->0;) {
      if (t-aps[i].lastSeen > AP_TIMEOUT_MS) {
        if (aps[i].ssid[0]) pushEvent(4, macStr(aps[i].bssid).c_str(), "AP 消失: %s (%s)", aps[i].ssid, macStr(aps[i].bssid).c_str());
        else pushEvent(4, macStr(aps[i].bssid).c_str(), "AP 消失: %s", macStr(aps[i].bssid).c_str());
        // 该 AP 下设备解绑，索引大于 i 的前移
        for (size_t d=0;d<devs.size();d++) {
          if (devs[d].apIdx==(int)i) devs[d].apIdx = -1;
          else if (devs[d].apIdx>(int)i) devs[d].apIdx--;
        }
        aps.erase(aps.begin()+i);
      }
    }
    for (size_t i=devs.size(); i-->0;) {
      if (t-devs[i].lastSeen > DEVICE_TIMEOUT_MS) devs.erase(devs.begin()+i);
    }
  }

  // 实时速率采样
  if (now-lastRateTick>=1000) {
    lastRateTick = now;
    rateHist[rateIdx] = totalPackets - lastSecPkt;
    lastSecPkt = totalPackets;
    rateIdx = (rateIdx+1)%HIST_N;
  }

  // v2.3 信号打点 / 主动测速状态机
  sigTick();
  aptTick();

  // Webhook 推送（每 5 秒尝试一次）
  if (now-lastWebhook>=5000) {
    lastWebhook = now;
    tryWebhook();
  }

  // 串口周期状态
  static uint32_t lastLog=0;
  if (now-lastLog>=15000) {
    lastLog = now;
    char buf[140];
    snprintf(buf,sizeof(buf),"[%02d] pkts=%lu ap=%d dev=%d mgmt=%lu data=%lu deauth=%lu eapol=%lu rogue=%d survey=%s sta=%s",
      curChannel,(unsigned long)totalPackets,(int)aps.size(),(int)devs.size(),
      (unsigned long)cntMgmt,(unsigned long)cntData,(unsigned long)cntDeauth,(unsigned long)cntEapol,
      (int)([&](){int n=0;for(auto&a:aps)if(a.rogue)n++;return n;}()),
      surveyActive?"Y":"N",(WiFi.status()==WL_CONNECTED?WiFi.localIP().toString().c_str():"off"));
    Serial.println(buf);
  }
}

bool savedSSIDMode() { return prefs.getString("ssid","").length()>0; }

void handleRoot() { server.send(200,"text/html; charset=utf-8", buildHTML()); }
void handleClearAlert() { deauthAlert=false; server.send(200,"text/plain","alert cleared"); }
void handleSet() {
  if (server.hasArg("ch")) {
    int ch=server.arg("ch").toInt();
    if (WiFi.status()==WL_CONNECTED && !surveyActive) { server.send(200,"text/plain","LAN mode: channel locked by router"); return; }
    if (ch==0) { autoHop=true; server.send(200,"text/plain","auto hop ON"); return; }
    if (ch>=1&&ch<=13) { autoHop=false; curChannel=(uint8_t)ch; esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE); server.send(200,"text/plain","fixed ch="+String(ch)); return; }
  }
  server.send(400,"text/plain","usage: /set?ch=1..13 or ch=0");
}
void handleScan() {
  if (server.hasArg("on")) { activeScan = (server.arg("on")=="1"); server.send(200,"text/plain", activeScan?"active scan ON":"active scan OFF"); return; }
  server.send(400,"text/plain","usage: /scan?on=1|0");
}
void handleNames() { server.send(200,"text/html; charset=utf-8", namesHTML()); }
void handleName() {
  String mac=server.arg("mac"), name=server.arg("name");
  mac.toUpperCase();
  if (mac.length()==0) { server.send(400,"text/plain","need mac"); return; }
  String key="d_"+mac;
  if (name.length()==0) prefs.remove(key.c_str());
  else prefs.putString(key.c_str(), name);
  pushEvent(8,mac.c_str(),"命名: %s -> %s", mac.c_str(), name.length()?name.c_str():"(清除)");
  server.send(200,"text/plain","ok: "+mac+" -> "+(name.length()?name:"(清除)"));
}
void handleConfig() { server.send(200,"text/html; charset=utf-8", configHTML()); }
void handleSave() {
  String ssid=server.arg("ssid"); ssid.trim();
  if (ssid.length()==0) { server.send(400,"text/plain","SSID 不能为空"); return; }
  String pass=server.arg("pass");
  prefs.putString("ssid",ssid); prefs.putString("pass",pass);
  autoHop=false;
  server.send(200,"text/html; charset=utf-8","<html><body style='font-family:system-ui;background:#0f1220;color:#d8e0f0;padding:30px'><h2>已保存，正在连接 "+ssid+" ...</h2><p><a href='/' style='color:#a5b4fc'>返回</a></p></body></html>");
  delay(300);
  WiFi.disconnect(); WiFi.begin(ssid.c_str(), pass.c_str());
}
void handleForget() { prefs.remove("ssid"); prefs.remove("pass"); server.send(200,"text/plain","已清除局域网配置，重启后为纯热点模式"); }
void handleProtect() { server.send(200,"text/html; charset=utf-8", protectHTML()); }
void handleEventsPage() { server.send(200,"text/html; charset=utf-8", eventsHTML()); }
void handleReport() { server.send(200,"text/html; charset=utf-8", reportHTML()); }
void handleHook() { server.send(200,"text/html; charset=utf-8", hookHTML()); }
void handleNotFound() { server.send(404,"text/plain","Not Found"); }


// ================= v2.3 信号质量功能 =================
// ---- 槽存储与解析 ----
String slotKey(int i) { return "qt" + String(i); }
void slotSave(const String& rec) {
  prefs.putString(slotKey(qtNext).c_str(), rec);
  qtNext = (qtNext + 1) % QT_SLOTS;
  prefs.putInt("qtN", qtNext);
}
String slotGet(int i) { return prefs.getString(slotKey(i).c_str(), ""); }
String jv(const String& j, const char* k) {
  String pat = String("\"") + k + "\":";
  int p = j.indexOf(pat);
  if (p < 0) return "";
  p += pat.length();
  if (p >= (int)j.length()) return "";
  if (j[p] == '"') {
    String r; p++;
    while (p < (int)j.length() && j[p] != '"') {
      if (j[p] == '\\' && p + 1 < (int)j.length()) { r += j[p+1]; p += 2; }
      else r += j[p++];
    }
    return r;
  }
  int e = j.indexOf(',', p); if (e < 0) e = j.indexOf('}', p);
  return j.substring(p, e < 0 ? (int)j.length() : e);
}
bool strToMac(const String& s, uint8_t* mac) {
  int h[6];
  if (sscanf(s.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x", &h[0], &h[1], &h[2], &h[3], &h[4], &h[5]) != 6) return false;
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)h[i];
  return true;
}
String sigGrade(int16_t avg, int missPct) {
  if (missPct > 50) return "信号中断";
  if (avg >= -50) return "优秀";
  if (avg >= -62) return "良好";
  if (avg >= -70) return "一般";
  if (avg >= -80) return "较差";
  return "很差";
}
String grdCls(const String& g) {
  if (g == "优秀" || g == "良好") return "rssi-good";
  if (g == "一般") return "rssi-mid";
  return "rssi-bad";
}

// ---- RSSI 被动打点 ----
int sigStartRun(const String& bssidStr, String name, int sec) {
  if (sig.running || apt.running || surveyActive) return 1;
  uint8_t mac[6];
  if (!strToMac(bssidStr, mac)) return 2;
  int idx = findApIdx(mac);
  if (idx < 0) return 3;
  if (WiFi.status() == WL_CONNECTED && aps[idx].channel != curChannel) return 4;
  if (sec < 5) sec = 10;
  if (sec > 60) sec = 60;
  memset(&sig, 0, sizeof(sig));
  memcpy(sig.bssid, mac, 6);
  snprintf(sig.ssid, sizeof(sig.ssid), "%s", aps[idx].ssid);
  sig.ch = aps[idx].channel;
  name.trim();
  snprintf(sig.name, sizeof(sig.name), "%s", name.length() ? name.c_str() : "未命名点位");
  sig.durMs = (uint32_t)sec * 1000;
  sig.startMs = millis();
  sig.lastTick = sig.startMs;
  sig.lastRssi = aps[idx].rssi;
  sig.priorAutoHop = autoHop;
  if (sig.priorAutoHop) {
    autoHop = false;
    curChannel = aps[idx].channel;
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  }
  sig.running = true;
  return 0;
}
void sigTick() {
  if (!sig.running) return;
  uint32_t now = millis();
  if (now - sig.lastTick < SIG_TICK_MS) return;
  sig.lastTick = now;
  if (now - sig.startMs >= sig.durMs) { sigFinishRun(); return; }
  int idx = findApIdx(sig.bssid);
  if (idx < 0) { sig.missN++; return; }
  if (sig.n < SIG_SAMPLE_MAX) sig.samples[sig.n++] = aps[idx].rssi;
  sig.lastRssi = aps[idx].rssi;
}
void sigFinishRun() {
  if (!sig.running) return;
  sig.running = false;
  if (sig.priorAutoHop && WiFi.status() != WL_CONNECTED) autoHop = true;
  if (sig.n == 0) {
    pushEvent(0, NULL, "信号打点结束：未采到有效样本（AP 不在当前信道/已消失）");
    return;
  }
  long sum = 0; int16_t mn = 127, mx = -127;
  for (uint16_t i = 0; i < sig.n; i++) {
    int16_t s = sig.samples[i];
    sum += s; if (s < mn) mn = s; if (s > mx) mx = s;
  }
  int16_t avg = (int16_t)(sum / sig.n);
  double var = 0;
  for (uint16_t i = 0; i < sig.n; i++) { long d = sig.samples[i] - avg; var += (double)(d * d); }
  int sd = (int)sqrt(var / sig.n);
  uint32_t durS = sig.durMs / 1000;
  int denom = (int)durS * (1000 / SIG_TICK_MS); if (denom <= 0) denom = 1;
  int missPct = (int)((long)sig.missN * 100 / denom);
  if (missPct > 100) missPct = 100;
  String rec = "{\"ts\":" + String((unsigned long)(millis() / 1000));
  rec += ",\"p\":\"" + jsonEscape(String(sig.name)) + "\"";
  rec += ",\"b\":\"" + macStr(sig.bssid) + "\"";
  rec += ",\"s\":\"" + jsonEscape(String(sig.ssid)) + "\"";
  rec += ",\"ch\":" + String(sig.ch);
  rec += ",\"n\":" + String(sig.n) + ",\"miss\":" + String(sig.missN);
  rec += ",\"a\":" + String(avg) + ",\"m\":" + String(mn) + ",\"x\":" + String(mx) + ",\"sd\":" + String(sd);
  rec += ",\"sec\":" + String(durS) + "}";
  slotSave(rec);
  pushEvent(0, NULL, "信号打点完成 %s(%s): 均值 %ddBm 最差 %d 评级 %s 样本 %d", sig.name, sig.ssid, avg, mn, sigGrade(avg, missPct).c_str(), sig.n);
}

// ---- 打点页面 / 历史 / CSV ----
String qtestHTML() {
  String h = pageHeader("信号打点", "ESP32-C3 Sniffer v2.3", false);
  h += "<div class='pagepanel'><h2>新建信号打点</h2>";
  h += "<p class='dim'>板子嗅探目标 AP 的信标/数据帧，按 200ms 采样 RSSI；开始后若正在自动轮换信道会自动锁定到该 AP。结束自动计算均值/最差/标准差与评级，保留最近 12 条并支持 CSV 导出。若板子当前已连局域网（STA 锁定信道），只能测当前信道可见的 AP。</p>";
  if (sig.running) {
    h += "<div class='alert'>正在打点中... <a class='btn danger' href='/qstop'>停止并保存当前样本</a></div>";
  } else {
    if (aps.size() == 0) h += "<div class='alert'>嗅探列表中暂无 AP，请稍候刷新或开启主动扫描。</div>";
    h += "<div class='frow'><label>目标 AP</label><select id='q_bssid'>";
    for (size_t i = 0; i < aps.size(); i++) {
      h += "<option value='" + macStr(aps[i].bssid) + "'>" + jsonEscape(String(aps[i].ssid)) + "（CH" + String(aps[i].channel) + " · " + String(aps[i].rssi) + " dBm）</option>";
    }
    h += "</select></div>";
    h += "<div class='frow'><label>点位名称</label><input id='q_name' placeholder='例如 书房门口 / 卧室床头'>";
    h += "<label>时长</label><select id='q_sec'><option>10</option><option>20</option><option selected>30</option><option>60</option></select>";
    h += "<button class='btn' onclick='qstart()'>开始打点</button></div>";
  }
  h += "<div id='qst' style='margin-top:10px'></div>";
  h += "<p><a class='btn sec' href='/qpoints'>查看历史记录与导出 CSV</a></p></div>";
  h += "<script>function qstart(){var b=document.getElementById('q_bssid');if(!b||!b.value){alert('先选择目标 AP');return;}var nm=encodeURIComponent(document.getElementById('q_name').value);var sc=document.getElementById('q_sec').value;fetch('/qstart?bssid='+b.value+'&name='+nm+'&sec='+sc).then(function(r){return r.text();}).then(function(t){if(t!=='ok')alert(t);});setTimeout(poll,800);}function poll(){fetch('/qstatus').then(function(r){return r.json();}).then(function(j){var e=document.getElementById('qst');if(j.running){e.innerHTML='<div class=\"ok\">打点中：'+j.name+'（'+j.ssid+'） '+j.el+'/'+j.dur+'s · 样本 '+j.n+' · 中断 '+j.miss+' · 当前 RSSI '+j.rssi+' dBm</div>';}else{e.innerHTML='';}});}setInterval(poll,1000);poll();</script>";
  h += pageFoot();
  return h;
}
int collectSlots() {
  int cnt = 0;
  for (int i = 0; i < QT_SLOTS; i++) {
    String r = slotGet(i);
    if (r.length() > 0) { slotsCache[cnt].ts = (uint32_t)jv(r, "ts").toInt(); slotsCache[cnt].raw = r; cnt++; }
  }
  for (int a = 0; a < cnt - 1; a++) for (int b = 0; b < cnt - 1 - a; b++) if (slotsCache[b].ts > slotsCache[b+1].ts) { SigSlot t = slotsCache[b]; slotsCache[b] = slotsCache[b+1]; slotsCache[b+1] = t; }
  return cnt;
}
String missPctOf(const String& r) {
  int miss = jv(r, "miss").toInt();
  int sec = jv(r, "sec").toInt(); if (sec <= 0) sec = 1;
  int d = sec * 5; if (d <= 0) d = 1;
  int p = (int)(100L * miss / d); if (p > 100) p = 100;
  return String(p);
}
String qpointsHTML() {
  String h = pageHeader("打点记录", "ESP32-C3 Sniffer v2.3", false);
  h += "<div class='pagepanel'><h2>信号打点历史（最近 " + String(QT_SLOTS) + " 条）</h2>";
  h += "<p class='frow' style='gap:10px'><a class='btn' href='/qcsv'>导出 CSV</a> <a class='btn danger' href='javascript:if(confirm(\"确认清空全部打点记录？\"))location.href=\"/qclear\"'>清空历史</a></p>";
  int cnt = collectSlots();
  if (cnt == 0) {
    h += "<p class='dim'>暂无记录。前往「信号打点」页开始第一次采样。</p>";
  } else {
    uint32_t nowS = millis() / 1000;
    h += "<table><tr><th>时间</th><th>点位</th><th>SSID (BSSID)</th><th>信道</th><th>样本</th><th>中断</th><th>均值</th><th>最差</th><th>最好</th><th>标准差</th><th>评级</th></tr>";
    for (int i = 0; i < cnt; i++) {
      String r = slotsCache[i].raw;
      uint32_t ago = (nowS > slotsCache[i].ts) ? (nowS - slotsCache[i].ts) / 60 : 0;
      String tm = (ago == 0) ? "刚刚" : "运行 " + String(ago) + " 分钟前";
      int avg = jv(r, "a").toInt();
      String mp = missPctOf(r);
      String grd = sigGrade((int16_t)avg, mp.toInt());
      h += "<tr><td class='dim'>" + tm + "</td><td><b>" + jv(r, "p") + "</b></td><td>" + jv(r, "s") + " <span class='dim mono'>" + jv(r, "b") + "</span></td>";
      h += "<td>" + jv(r, "ch") + "</td><td>" + jv(r, "n") + "</td><td class='dim'>" + jv(r, "miss") + "</td>";
      h += "<td class='" + grdCls(grd) + "'><b>" + jv(r, "a") + "</b></td><td class='rssi-bad'>" + jv(r, "m") + "</td><td class='rssi-good'>" + jv(r, "x") + "</td>";
      h += "<td>" + jv(r, "sd") + "</td><td><span class='badge " + (mp.toInt() > 50 ? "b-red" : (grd=="优秀"||grd=="良好" ? "b-green" : (grd=="一般" ? "b-yellow" : "b-red"))) + "'>" + grd + "</span></td></tr>";
    }
    h += "</table>";
  }
  h += pageFoot();
  return h;
}
void handleQtest() { server.send(200, "text/html; charset=utf-8", qtestHTML()); }
void handleQstart() {
  if (!server.hasArg("bssid")) { server.send(400, "text/plain", "need bssid"); return; }
  String name = server.hasArg("name") ? server.arg("name") : "";
  int sec = server.hasArg("sec") ? server.arg("sec").toInt() : 30;
  int r = sigStartRun(server.arg("bssid"), name, sec);
  switch (r) {
    case 0: server.send(200, "text/plain", "ok"); break;
    case 1: server.send(200, "text/plain", "busy: 打点/体检/测速进行中"); break;
    case 2: server.send(400, "text/plain", "bad bssid format"); break;
    case 3: server.send(404, "text/plain", "AP 不在嗅探列表"); break;
    case 4: server.send(200, "text/plain", "当前 STA 锁定 CH" + String(curChannel) + "，目标 AP 在不同信道，请先断开局域网或更换目标"); break;
  }
}
void handleQstop() { sigFinishRun(); server.send(200, "text/plain", "stopped"); }
void handleQstatus() {
  String j = "{\"running\":" + String(sig.running ? "true" : "false");
  if (sig.running) {
    uint32_t el = (millis() - sig.startMs) / 1000;
    j += ",\"name\":\"" + jsonEscape(String(sig.name)) + "\",\"ssid\":\"" + jsonEscape(String(sig.ssid)) + "\"";
    j += ",\"el\":" + String(el) + ",\"dur\":" + String(sig.durMs / 1000);
    j += ",\"n\":" + String(sig.n) + ",\"miss\":" + String(sig.missN) + ",\"rssi\":" + String(sig.lastRssi);
  }
  int li = (qtNext + QT_SLOTS - 1) % QT_SLOTS;
  String last = slotGet(li);
  j += ",\"last\":\"" + jsonEscape(last) + "\"}";
  server.send(200, "application/json", j);
}
void handleQpoints() { server.send(200, "text/html; charset=utf-8", qpointsHTML()); }
String csvF(String v) { v.replace("\"", "\"\""); return "\"" + v + "\""; }
void handleQcsv() {
  String csv = "\xEF\xBB\xBF时间,点位,BSSID,SSID,信道,样本,中断次数,均值dBm,最差dBm,最好dBm,标准差,评级\r\n";
  int cnt = collectSlots();
  for (int i = 0; i < cnt; i++) {
    String r = slotsCache[i].raw;
    int avg = jv(r, "a").toInt();
    String mp = missPctOf(r);
    String grd = sigGrade((int16_t)avg, mp.toInt());
    csv += csvF(String((unsigned long)slotsCache[i].ts)) + "," + csvF(jv(r, "p")) + "," + csvF(jv(r, "b")) + "," + csvF(jv(r, "s")) + ",";
    csv += csvF(jv(r, "ch")) + "," + csvF(jv(r, "n")) + "," + csvF(jv(r, "miss")) + "," + csvF(jv(r, "a")) + "," + csvF(jv(r, "m")) + "," + csvF(jv(r, "x")) + "," + csvF(jv(r, "sd")) + "," + csvF(grd) + "\r\n";
  }
  server.sendHeader("Content-Disposition", "attachment; filename=qpoints.csv");
  server.send(200, "text/csv; charset=utf-8", csv);
}
void handleQclear() {
  for (int i = 0; i < QT_SLOTS; i++) prefs.remove(slotKey(i).c_str());
  prefs.putInt("qtN", 0); qtNext = 0;
  server.sendHeader("Location", "/qpoints");
  server.send(302, "text/plain", "cleared");
}


// ================= v2.3 主动测速（STA 连被测 AP -> TCP 探测网关） =================
String astepName(uint8_t s) {
  if (s == 1) return "正在连接被测 WiFi...";
  if (s == 2) return "测速进行中...";
  if (s == 3) return "完成";
  if (s == 4) return "正在恢复原局域网 WiFi...";
  return "空闲";
}
bool tcpProbe(const IPAddress& ip, uint16_t port, uint16_t* rtt) {
  WiFiClient c;
  unsigned long t0 = millis();
  bool ok = c.connect(ip, port, 2000);
  *rtt = (uint16_t)(millis() - t0);
  if (ok) c.stop();
  return ok;
}
int aptStartRun(const String& ssid, const String& pass, int n) {
  if (apt.running || sig.running || surveyActive) return 1;
  if (ssid.length() == 0 || ssid.length() > 32) return 2;
  if (n < 1) n = 1;
  if (n > APTEST_MAX_N) n = APTEST_MAX_N;
  memset(&apt, 0, sizeof(apt));
  snprintf(apt.ssid, sizeof(apt.ssid), "%s", ssid.c_str());
  snprintf(apt.pass, sizeof(apt.pass), "%s", pass.c_str());
  apt.totalN = (uint8_t)n;
  for (uint8_t i = 0; i < apt.totalN; i++) apt.rttMs[i] = -1;
  apt.rssi = -127;
  apt.stMs = millis();
  apt.lastTick = apt.stMs;
  if (WiFi.status() == WL_CONNECTED && WiFi.SSID() == ssid) {
    apt.stage = 2;
    apt.localIp = WiFi.localIP().toString();
    apt.gwIp = WiFi.gatewayIP().toString();
    apt.ch = WiFi.channel();
    apt.rssi = WiFi.RSSI();
    apt.lastProbeMs = 0;
  } else {
    apt.stage = 1;
    WiFi.disconnect();
    WiFi.begin(apt.ssid, apt.pass);
  }
  apt.running = true;
  pushEvent(0, NULL, "主动测速开始: %s（%d 次）", apt.ssid, n);
  return 0;
}
void aptStoreLast(int okN, int failN, long avg, int loss) {
  String j = "{\"ts\":" + String((unsigned long)(millis() / 1000)) + ",\"ssid\":\"" + jsonEscape(String(apt.ssid)) + "\",\"ok\":" + String(okN) + ",\"fail\":" + String(failN) + ",\"avg\":" + String(avg) + ",\"loss\":" + String(loss) + "}";
  prefs.putString("atLast", j);
}
void aptRecoverSta() {
  String s = prefs.getString("ssid", "");
  if (s.length() && s != String(apt.ssid)) {
    String p = prefs.getString("pass", "");
    WiFi.disconnect();
    WiFi.begin(s.c_str(), p.c_str());
    lanAnnounced = false;
    apt.stMs = millis();
    apt.stage = 4;
    apt.running = true;
  } else {
    lanAnnounced = false;
    apt.stage = 3;
    apt.running = false;
  }
}
void aptFinishMid() {
  int okN = 0, failN = 0;
  long sum = 0;
  for (uint8_t i = 0; i < apt.totalN; i++) {
    if (apt.rttMs[i] >= 0) { okN++; sum += apt.rttMs[i]; }
    else failN++;
  }
  int loss = apt.totalN ? (int)(100L * failN / apt.totalN) : 100;
  long avg = okN ? sum / okN : -1;
  aptStoreLast(okN, failN, avg, loss);
  if (okN) pushEvent(0, NULL, "测速完成 %s: %d/%d 成功 平均RTT %dms 丢包 %d%%", apt.ssid, okN, apt.totalN, (int)avg, loss);
  else pushEvent(0, NULL, "测速完成 %s: 全部失败 丢包 %d%%", apt.ssid, loss);
  aptRecoverSta();
}
void aptTick() {
  uint32_t now = millis();
  if (now - apt.lastTick < 100) return;
  apt.lastTick = now;
  if (apt.stage == 3) {
    if (now - apt.stMs > 120000) { apt.stage = 0; apt.err[0] = 0; apt.gwIp = ""; apt.localIp = ""; }
    return;
  }
  if (!apt.running) return;
  if (apt.stage == 1) {
    if (WiFi.status() == WL_CONNECTED) {
      apt.stage = 2;
      apt.localIp = WiFi.localIP().toString();
      apt.gwIp = WiFi.gatewayIP().toString();
      apt.ch = WiFi.channel();
      apt.rssi = WiFi.RSSI();
      apt.lastProbeMs = 0;
    } else if (now - apt.stMs >= 12000) {
      snprintf(apt.err, sizeof(apt.err), "连接超时（12s）");
      aptStoreLast(0, 0, -1, 100);
      pushEvent(0, NULL, "主动测速失败 %s: 无法连接 WiFi（密码错误/AP 不可达）", apt.ssid);
      aptRecoverSta();
    }
    return;
  }
  if (apt.stage == 2) {
    apt.rssi = WiFi.RSSI();
    if (WiFi.status() != WL_CONNECTED) {
      snprintf(apt.err, sizeof(apt.err), "测速中连接中断，已完成 %d/%d 次", apt.probeIdx, apt.totalN);
      aptFinishMid();
      return;
    }
    if (now - apt.lastProbeMs < 500) return;
    if (apt.probeIdx >= apt.totalN) { aptFinishMid(); return; }
    apt.lastProbeMs = now;
    uint16_t rtt = 0;
    bool ok = false;
    IPAddress gw = WiFi.gatewayIP();
    if ((uint32_t)gw != 0 && tcpProbe(gw, 80, &rtt)) ok = true;
    else if ((uint32_t)gw != 0 && tcpProbe(gw, 443, &rtt)) ok = true;
    apt.rttMs[apt.probeIdx] = ok ? (int16_t)rtt : -1;
    apt.probeIdx++;
    return;
  }
  if (apt.stage == 4) {
    if (WiFi.status() == WL_CONNECTED) {
      apt.stage = 3;
      apt.running = false;
    } else if (now - apt.stMs >= 15000) {
      snprintf(apt.err, sizeof(apt.err), "恢复原 WiFi 超时，请到「配网」页手动重连");
      apt.stage = 3;
      apt.running = false;
    }
    return;
  }
}
String aptestHTML() {
  String h = pageHeader("主动测速", "ESP32-C3 Sniffer v2.3", false);
  h += "<div class='pagepanel'><h2>主动测速</h2>";
  h += "<p class='dim'>板子以 STA 模式连接被测 WiFi（热点 ESP32C3-Sniffer 全程保持），连上后取网关 IP，对网关 80/443 端口做 TCP 握手计时，统计平均延迟与丢包。结束后自动恢复配网中保存的局域网 WiFi（如与被测网相同则不断开）。</p>";
  if (apt.stage >= 1 && apt.stage <= 2) {
    h += "<div class='alert'>测速进行中，请勿关闭页面。</div>";
  }
  h += "<div class='frow'><label>WiFi 名称 SSID</label><input id='a_ssid' placeholder='输入要测的 WiFi 名称'></div>";
  h += "<div class='frow'><label>密码</label><input id='a_pass' type='password' placeholder='open 网络可留空'></div>";
  h += "<div class='frow'><label>探测次数</label><select id='a_n'><option>5</option><option>10</option><option selected>20</option></select>";
  h += "<button class='btn' onclick='astart()'>开始测速</button> <button class='btn danger' onclick='astop()'>停止</button></div>";
  h += "<div id='ast' style='margin-top:12px'></div></div>";
  h += "<script>function astart(){var s=document.getElementById('a_ssid').value;var p=document.getElementById('a_pass').value;var n=document.getElementById('a_n').value;if(!s){alert('填写 WiFi 名称');return;}fetch('/astart?ssid='+encodeURIComponent(s)+'&pass='+encodeURIComponent(p)+'&n='+n).then(function(r){return r.text();}).then(function(t){if(t!=='started')alert(t);});setTimeout(poll,800);}function astop(){fetch('/astop');}function poll(){fetch('/astatus').then(function(r){return r.json();}).then(function(j){var e=document.getElementById('ast');var s=j.stage;if(s===0&&!j.last){e.innerHTML='<p class=\"dim\">当前无测速任务。</p>';return;}var t='<div class=\"ok\"><b>'+j.step+'</b> '+j.ssid+'<br/>';if(j.err)t+='<span class=\"rssi-bad\">'+j.err+'</span><br/>';if(s>=2){t+='信号 '+j.rssi+' dBm · 信道 CH'+j.ch+' · IP '+j.ip+' · 网关 '+j.gw+'<br/>进度 '+j.done+'/'+j.total+' · 成功 '+j.ok+' · 失败 '+j.fail+' · 丢包 '+j.loss+'%';if(j.avg>=0)t+=' · 平均RTT <b>'+j.avg+'ms</b>（min '+j.min+' / max '+j.max+'）';t+='<br/>RTT序列: '+j.rtts;}if(j.last&&s===3){t+='<hr/><span class=\"dim\">最近一次结果:</span> '+j.last;}t+='</div>';e.innerHTML=t;});}setInterval(poll,700);poll();</script>";
  h += pageFoot();
  return h;
}
void handleAptest() { server.send(200, "text/html; charset=utf-8", aptestHTML()); }
void handleAstart() {
  String ssid = server.hasArg("ssid") ? server.arg("ssid") : "";
  ssid.trim();
  String pass = server.hasArg("pass") ? server.arg("pass") : "";
  int n = server.hasArg("n") ? server.arg("n").toInt() : 20;
  int r = aptStartRun(ssid, pass, n);
  if (r == 0) server.send(200, "text/plain", "started");
  else if (r == 1) server.send(200, "text/plain", "busy: 测速/打点/体检进行中");
  else server.send(200, "text/plain", "SSID 无效");
}
void handleAstop() {
  if (!apt.running) { server.send(200, "text/plain", "当前无运行中测速"); return; }
  if (apt.stage == 2) {
    if (apt.err[0] == 0) snprintf(apt.err, sizeof(apt.err), "用户停止，已完成 %d/%d 次", apt.probeIdx, apt.totalN);
    aptFinishMid();
  } else if (apt.stage == 1) {
    snprintf(apt.err, sizeof(apt.err), "用户取消连接");
    aptStoreLast(0, 0, -1, 100);
    pushEvent(0, NULL, "主动测速已取消: %s", apt.ssid);
    aptRecoverSta();
  } else if (apt.stage == 4) {
    server.send(200, "text/plain", "正在恢复原 WiFi，请稍候");
    return;
  }
  server.send(200, "text/plain", "stopped");
}
void handleAstatus() {
  String j = "{\"running\":" + String(apt.running ? "true" : "false") + ",\"stage\":" + String(apt.stage);
  j += ",\"step\":\"" + astepName(apt.stage) + "\"";
  j += ",\"ssid\":\"" + jsonEscape(String(apt.ssid)) + "\"";
  j += ",\"err\":\"" + jsonEscape(String(apt.err)) + "\"";
  j += ",\"done\":" + String(apt.probeIdx) + ",\"total\":" + String(apt.totalN);
  j += ",\"rssi\":" + String(apt.rssi) + ",\"ch\":" + String(apt.ch);
  j += ",\"ip\":\"" + apt.localIp + "\",\"gw\":\"" + apt.gwIp + "\"";
  int okN = 0;
  long sum = 0;
  int16_t mn = 30000, mx = -1;
  for (uint8_t i = 0; i < apt.totalN; i++) {
    if (apt.rttMs[i] >= 0) { okN++; sum += apt.rttMs[i]; if (apt.rttMs[i] < mn) mn = apt.rttMs[i]; if (apt.rttMs[i] > mx) mx = apt.rttMs[i]; }
  }
  int failN = apt.totalN - okN;
  j += ",\"ok\":" + String(okN) + ",\"fail\":" + String(failN);
  j += ",\"avg\":" + String(okN ? sum / okN : -1) + ",\"min\":" + String(mn == 30000 ? -1 : mn) + ",\"max\":" + String(mx == -1 ? -1 : mx);
  j += ",\"loss\":" + String(apt.totalN ? 100L * failN / apt.totalN : 0);
  j += ",\"rtts\":\"";
  for (uint8_t i = 0; i < apt.totalN; i++) { if (i) j += ","; j += String(apt.rttMs[i]); }
  j += "\"";
  String last = prefs.getString("atLast", "");
  j += ",\"last\":\"" + jsonEscape(last) + "\"}";
  server.send(200, "application/json", j);
}
