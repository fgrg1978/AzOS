/// ESP32-C3 WiFi Bridge Firmware — UART ↔ TCP transparent relay.
///
/// Wiring (3 cables):
///   VF2 UART1 TX (GPIO) → ESP32-C3 RX (GPIO20)
///   VF2 UART1 RX (GPIO) → ESP32-C3 TX (GPIO21)
///   VF2 GND              → ESP32-C3 GND
///
/// The ESP32 connects to WiFi, then opens a TCP connection to the
/// brain server.  All bytes received on UART are forwarded to TCP,
/// and all bytes received from TCP are forwarded to UART.
///
/// Brain protocol packets ("BR" + type + len + payload + CRC8) flow
/// transparently — no parsing needed on the ESP32 side.
///
/// Build: Arduino IDE or PlatformIO with ESP32-C3 board support.
///        Board: "ESP32C3 Dev Module"
///        Upload speed: 921600

#include <WiFi.h>

// ── Configuration ─────────────────────────────────────────────────────────────

// WiFi credentials
const char* WIFI_SSID     = "ROBOT_NET";
const char* WIFI_PASSWORD = "robot12345";

// Brain server (macOS running server.py)
const char* BRAIN_HOST = "192.168.1.100";
const uint16_t BRAIN_PORT = 9000;

// UART to VF2
const int UART_BAUD = 115200;
const int PIN_RX = 20;  // ESP32-C3 RX ← VF2 TX
const int PIN_TX = 21;  // ESP32-C3 TX → VF2 RX

// Reconnection
const unsigned long RECONNECT_INTERVAL_MS = 3000;

// ── Globals ───────────────────────────────────────────────────────────────────

WiFiClient tcp;
unsigned long last_reconnect = 0;
bool was_connected = false;

// Statistics
uint32_t uart_to_tcp_bytes = 0;
uint32_t tcp_to_uart_bytes = 0;

// Transfer buffer
const int BUF_SIZE = 256;
uint8_t buf[BUF_SIZE];

// ── Status LED ────────────────────────────────────────────────────────────────
// ESP32-C3 built-in LED (GPIO8 on most boards, active LOW)
const int LED_PIN = 8;

void led_on()  { digitalWrite(LED_PIN, LOW);  }
void led_off() { digitalWrite(LED_PIN, HIGH); }

// Blink patterns:
//   Fast blink = connecting WiFi
//   Slow blink = WiFi OK, no TCP
//   Solid ON   = bridge active
//   OFF        = error

// ── Setup ─────────────────────────────────────────────────────────────────────

void setup() {
    pinMode(LED_PIN, OUTPUT);
    led_off();

    // Init UART to VF2
    Serial1.begin(UART_BAUD, SERIAL_8N1, PIN_RX, PIN_TX);

    // Init debug console (USB CDC)
    Serial.begin(115200);
    Serial.println("[BRIDGE] ESP32-C3 WiFi Bridge starting");

    // Connect to WiFi
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    Serial.printf("[BRIDGE] Connecting to WiFi '%s'", WIFI_SSID);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 60) {
        delay(500);
        Serial.print(".");
        // Fast blink while connecting
        digitalWrite(LED_PIN, attempts % 2 == 0 ? LOW : HIGH);
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("\n[BRIDGE] WiFi connected — IP: %s\n",
                      WiFi.localIP().toString().c_str());
    } else {
        Serial.println("\n[BRIDGE] WiFi FAILED — will retry in loop");
    }
}

// ── Main loop ─────────────────────────────────────────────────────────────────

void loop() {
    // Reconnect WiFi if needed
    if (WiFi.status() != WL_CONNECTED) {
        led_off();
        if (millis() - last_reconnect > RECONNECT_INTERVAL_MS) {
            last_reconnect = millis();
            WiFi.reconnect();
        }
        delay(100);
        return;
    }

    // Connect TCP to brain server if needed
    if (!tcp.connected()) {
        if (was_connected) {
            Serial.println("[BRIDGE] TCP disconnected — reconnecting");
            was_connected = false;
        }

        // Slow blink: WiFi OK but no TCP
        digitalWrite(LED_PIN, (millis() / 500) % 2 == 0 ? LOW : HIGH);

        if (millis() - last_reconnect > RECONNECT_INTERVAL_MS) {
            last_reconnect = millis();
            Serial.printf("[BRIDGE] Connecting to %s:%d...\n", BRAIN_HOST, BRAIN_PORT);

            if (tcp.connect(BRAIN_HOST, BRAIN_PORT)) {
                Serial.println("[BRIDGE] TCP connected — bridge active");
                tcp.setNoDelay(true);  // disable Nagle for low latency
                was_connected = true;
                uart_to_tcp_bytes = 0;
                tcp_to_uart_bytes = 0;
            } else {
                Serial.println("[BRIDGE] TCP connect failed");
            }
        }
        return;
    }

    // ── Bridge active: relay bytes both directions ────────────────────────

    led_on();  // solid ON = bridge active

    // UART → TCP (VF2 sensor packets → brain server)
    int uart_avail = Serial1.available();
    if (uart_avail > 0) {
        int to_read = (uart_avail < BUF_SIZE) ? uart_avail : BUF_SIZE;
        int n = Serial1.readBytes(buf, to_read);
        if (n > 0) {
            tcp.write(buf, n);
            uart_to_tcp_bytes += n;
        }
    }

    // TCP → UART (brain server actuator cmds → VF2)
    int tcp_avail = tcp.available();
    if (tcp_avail > 0) {
        int to_read = (tcp_avail < BUF_SIZE) ? tcp_avail : BUF_SIZE;
        int n = tcp.read(buf, to_read);
        if (n > 0) {
            Serial1.write(buf, n);
            tcp_to_uart_bytes += n;
        }
    }

    // Periodic stats (every 10 seconds)
    static unsigned long last_stats = 0;
    if (millis() - last_stats > 10000) {
        last_stats = millis();
        Serial.printf("[BRIDGE] Stats: UART→TCP %u B, TCP→UART %u B, RSSI %d dBm\n",
                      uart_to_tcp_bytes, tcp_to_uart_bytes, WiFi.RSSI());
    }
}
