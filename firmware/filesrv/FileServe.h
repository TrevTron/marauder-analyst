#ifndef FileServe_h
#define FileServe_h

// FileServe: read-only HTTP file server for the SD card.
// Part of the marauder-automated-analyst custom build.
// Serves /health, /list, /get from SD over a softAP so captures can be
// pulled wirelessly without removing the card. Read-only by design.

#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include "SDInterface.h"
#include "configs.h"

extern SDInterface sd_obj;

class FileServe {
  public:
    // key: optional shared token. If non-empty, /list and /get require ?key=<key>.
    // ap_ssid: softAP name. ap_pass: softAP password (min 8 chars, WPA2).
    bool begin(const char* ap_ssid, const char* ap_pass, const char* key = "");
    void end();
    bool running() { return this->is_running; }

  private:
    bool is_running = false;
    String auth_key;
    bool authorized(AsyncWebServerRequest* request);
    static bool pathSafe(const String& path);
};

#endif
