#include "FileServe.h"
#include "WiFiScan.h"   // wifi_scan_obj, WIFI_SCAN_OFF

extern WiFiScan wifi_scan_obj;

// FileServe: read-only HTTP file server for the SD card.
// Runs its own AsyncWebServer on port 8080 so it never conflicts with
// EvilPortal's global server on port 80 (they never run simultaneously,
// but separate ports keep handler ownership unambiguous).
//
// Endpoints:
//   GET /health            -> "OK free_heap=<n>" (no auth; pipeline readiness poll)
//   GET /list?key=<key>    -> text/plain, one "path<TAB>size" per line
//   GET /get?key=<key>&file=/<path>  -> application/octet-stream download
//
// Refuses paths containing ".." or not starting with "/".

static AsyncWebServer filesrv(8080);

bool FileServe::authorized(AsyncWebServerRequest* request) {
  if (this->auth_key.length() == 0)
    return true;
  if (!request->hasParam("key"))
    return false;
  return request->getParam("key")->value() == this->auth_key;
}

bool FileServe::pathSafe(const String& path) {
  if (!path.startsWith("/")) return false;
  if (path.indexOf("..") != -1) return false;
  if (path.length() > 128) return false;
  return true;
}

bool FileServe::begin(const char* ap_ssid, const char* ap_pass, const char* key) {
  #ifdef HAS_SD
    if (!sd_obj.supported) {
      Serial.println(F("FileServe: no SD card, refusing to start"));
      return false;
    }
  #endif

  // Never serve while a sniff is writing to the card.
  if (wifi_scan_obj.currentScanMode != WIFI_SCAN_OFF) {
    Serial.println(F("FileServe: scan/sniff active, refusing to start (stopscan first)"));
    return false;
  }

  this->auth_key = String(key);

  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap_ssid, ap_pass);
  Serial.print(F("FileServe AP up: "));
  Serial.print(ap_ssid);
  Serial.print(F("  ip: "));
  Serial.println(WiFi.softAPIP());

  filesrv.on("/health", HTTP_GET, [this](AsyncWebServerRequest* request) {
    String body = "OK free_heap=" + String(ESP.getFreeHeap()) + "\n";
    request->send(200, "text/plain", body);
  });

  filesrv.on("/list", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!this->authorized(request)) {
      request->send(403, "text/plain", "bad key\n");
      return;
    }
    String out = "";
    #ifdef HAS_SD
      LinkedList<String>* names = new LinkedList<String>();
      sd_obj.listDirToLinkedList(names, "/", "");
      for (int i = 0; i < names->size(); i++) {
        String p = names->get(i);
        if (!p.startsWith("/")) p = "/" + p;
        File f = sd_obj.getFile(p);
        out += p + "\t" + String(f.size()) + "\n";
        f.close();
      }
      while (names->size() > 0) names->remove(0);
      delete names;
    #else
      out = "no sd support\n";
    #endif
    request->send(200, "text/plain", out);
  });

  filesrv.on("/get", HTTP_GET, [this](AsyncWebServerRequest* request) {
    if (!this->authorized(request)) {
      request->send(403, "text/plain", "bad key\n");
      return;
    }
    if (!request->hasParam("file")) {
      request->send(400, "text/plain", "missing file param\n");
      return;
    }
    String path = request->getParam("file")->value();
    if (!FileServe::pathSafe(path)) {
      request->send(400, "text/plain", "unsafe path\n");
      return;
    }
    #ifdef HAS_SD
      if (!SD.exists(path)) {
        request->send(404, "text/plain", "not found\n");
        return;
      }
      request->send(SD, path, "application/octet-stream", true);
      Serial.println("FileServe served: " + path);
    #else
      request->send(500, "text/plain", "no sd support\n");
    #endif
  });

  filesrv.onNotFound([](AsyncWebServerRequest* request) {
    request->send(404, "text/plain", "not found\n");
  });

  filesrv.begin();
  this->is_running = true;
  Serial.println(F("FileServe listening on :8080 (/health /list /get)"));
  return true;
}

void FileServe::end() {
  if (!this->is_running)
    return;
  filesrv.end();
  WiFi.softAPdisconnect(true);
  this->is_running = false;
  Serial.println(F("FileServe stopped"));
}
