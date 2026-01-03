/*
 * M5Stack Tab5 WiFi Scanner via UART
 * Communicates with ESP32C5 over UART to scan WiFi networks
 * Also supports native WiFi scanning via ESP32C6 (SDIO)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "bsp/m5stack_tab5.h"
#include "lvgl.h"

// ESP-Hosted includes for WiFi via ESP32C6 SDIO
#include "esp_hosted.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"

static const char *TAG = "wifi_scanner";

// UART Configuration for ESP32C5 communication
#define UART_NUM          UART_NUM_1
#define UART_TX_PIN       GPIO_NUM_53//38
#define UART_RX_PIN       GPIO_NUM_54//37
#define UART_BAUD_RATE    115200
#define UART_BUF_SIZE     4096
#define UART_RX_TIMEOUT   30000  // 30 seconds timeout for scan

// ESP Modem configuration (configurable pins for future external ESP32C5)
#define ESP_MODEM_UART_TX_PIN  GPIO_NUM_38
#define ESP_MODEM_UART_RX_PIN  GPIO_NUM_37

// ESP Modem scan settings
#define ESP_MODEM_MAX_NETWORKS  50

// INA226 Power Monitor Configuration (for battery voltage)
#define INA226_I2C_ADDR         0x40    // Default I2C address for INA226
#define INA226_REG_CONFIG       0x00    // Configuration register
#define INA226_REG_SHUNT_VOLT   0x01    // Shunt voltage register
#define INA226_REG_BUS_VOLT     0x02    // Bus voltage register
#define INA226_REG_POWER        0x03    // Power register
#define INA226_REG_CURRENT      0x04    // Current register
#define INA226_REG_CALIB        0x05    // Calibration register
#define INA226_REG_MASK_EN      0x06    // Mask/Enable register
#define INA226_REG_ALERT_LIM    0x07    // Alert limit register
#define INA226_REG_MFG_ID       0xFE    // Manufacturer ID (0x5449)
#define INA226_REG_DIE_ID       0xFF    // Die ID (0x2260)
#define INA226_BUS_VOLT_LSB     1.25f   // 1.25mV per LSB for bus voltage
#define BATTERY_UPDATE_MS       2000    // Update battery status every 2 seconds

// Maximum networks to display
#define MAX_NETWORKS      50
#define MAX_CLIENTS_PER_NETWORK  20
#define OBSERVER_POLL_INTERVAL_MS  20000  // 20 seconds
#define OBSERVER_LINE_BUFFER_SIZE  512

// Material Design Colors
#define COLOR_MATERIAL_BG       lv_color_make(18, 18, 18)      // #121212 - dark background
#define COLOR_MATERIAL_BLUE     lv_color_make(33, 150, 243)    // #2196F3
#define COLOR_MATERIAL_RED      lv_color_make(244, 67, 54)     // #F44336
#define COLOR_MATERIAL_PURPLE   lv_color_make(156, 39, 176)    // #9C27B0
#define COLOR_MATERIAL_GREEN    lv_color_make(76, 175, 80)     // #4CAF50
#define COLOR_MATERIAL_AMBER    lv_color_make(255, 193, 7)     // #FFC107
#define COLOR_MATERIAL_CYAN     lv_color_make(0, 188, 212)     // #00BCD4
#define COLOR_MATERIAL_TEAL     lv_color_make(0, 150, 136)     // #009688 - Kismet-style teal

// WiFi network info structure
typedef struct {
    int index;
    char ssid[33];
    char bssid[18];
    int rssi;
    char band[8];  // "2.4GHz" or "5GHz"
    char security[24];
} wifi_network_t;

// Observer network info structure (for sniffer results)
typedef struct {
    char ssid[33];
    char bssid[18];      // MAC address of AP
    int scan_index;      // 1-based index from scan_networks (for select_networks command)
    int channel;
    int rssi;            // Signal strength in dBm
    char band[8];        // "2.4GHz" or "5GHz"
    int client_count;
    char clients[MAX_CLIENTS_PER_NETWORK][18];  // MAC addresses of clients
} observer_network_t;

// Global variables
static wifi_network_t networks[MAX_NETWORKS];
static int network_count = 0;
static bool scan_in_progress = false;

// Observer global variables (large arrays in PSRAM)
static observer_network_t *observer_networks = NULL;  // Allocated in PSRAM
static int observer_network_count = 0;
static bool observer_running = false;
static TimerHandle_t observer_timer = NULL;
static TaskHandle_t observer_task_handle = NULL;

// Popup state
static bool popup_open = false;
static int popup_network_idx = -1;  // Index of network being viewed in popup
static lv_obj_t *popup_obj = NULL;
static lv_obj_t *popup_clients_container = NULL;
static TimerHandle_t popup_timer = NULL;  // 10s timer for popup polling
#define POPUP_POLL_INTERVAL_MS  10000  // 10 seconds

// Deauth popup state
static bool deauth_active = false;
static int deauth_network_idx = -1;
static int deauth_client_idx = -1;
static lv_obj_t *deauth_popup_obj = NULL;
static lv_obj_t *deauth_btn = NULL;
static lv_obj_t *deauth_btn_label = NULL;

// PSRAM buffers for observer (allocated once)
static char *observer_rx_buffer = NULL;
static char *observer_line_buffer = NULL;

// LVGL UI elements - pages
static lv_obj_t *tiles_container = NULL;
static lv_obj_t *scan_page = NULL;
static lv_obj_t *observer_page = NULL;
static lv_obj_t *esp_modem_page = NULL;

// ESP Modem global variables
static wifi_ap_record_t *esp_modem_networks = NULL;  // Allocated in PSRAM
static uint16_t esp_modem_network_count = 0;
static bool esp_modem_scan_in_progress = false;
static bool esp_modem_wifi_initialized = false;

// INA226 Power Monitor
static i2c_master_dev_handle_t ina226_dev_handle = NULL;
static bool ina226_initialized = false;

// Battery status bar
static lv_obj_t *status_bar = NULL;
static lv_obj_t *battery_voltage_label = NULL;
static lv_obj_t *charging_status_label = NULL;
static lv_timer_t *battery_update_timer = NULL;
static float current_battery_voltage = 0.0f;
static bool current_charging_status = false;

// LVGL UI elements - scan page
static lv_obj_t *scan_btn = NULL;
static lv_obj_t *status_label = NULL;
static lv_obj_t *network_list = NULL;
static lv_obj_t *spinner = NULL;

// LVGL UI elements - observer page
static lv_obj_t *observer_start_btn = NULL;
static lv_obj_t *observer_stop_btn = NULL;
static lv_obj_t *observer_table = NULL;
static lv_obj_t *observer_status_label = NULL;

// LVGL UI elements - ESP Modem page
static lv_obj_t *esp_modem_scan_btn = NULL;
static lv_obj_t *esp_modem_status_label = NULL;
static lv_obj_t *esp_modem_network_list = NULL;
static lv_obj_t *esp_modem_spinner = NULL;

// Forward declarations
static void show_main_tiles(void);
static void show_scan_page(void);
static void show_observer_page(void);
static void show_esp_modem_page(void);
static void main_tile_event_cb(lv_event_t *e);
static void back_btn_event_cb(lv_event_t *e);
static void observer_back_btn_event_cb(lv_event_t *e);
static void esp_modem_back_btn_event_cb(lv_event_t *e);
static void esp_modem_scan_btn_click_cb(lv_event_t *e);
static esp_err_t esp_modem_wifi_init(void);
static void network_row_click_cb(lv_event_t *e);
static void client_row_click_cb(lv_event_t *e);
static void show_network_popup(int network_idx);
static void close_network_popup(void);
static void show_deauth_popup(int network_idx, int client_idx);
static void close_deauth_popup(void);
static void deauth_btn_click_cb(lv_event_t *e);
static void update_observer_table(void);
static bool parse_sniffer_network_line(const char *line, observer_network_t *net);
static bool parse_sniffer_client_line(const char *line, char *mac_out, size_t mac_size);

//==================================================================================
// INA226 Power Monitor Driver
//==================================================================================

static esp_err_t ina226_init(void)
{
    if (ina226_initialized) {
        return ESP_OK;
    }
    
    i2c_master_bus_handle_t i2c_bus = bsp_i2c_get_handle();
    if (i2c_bus == NULL) {
        ESP_LOGE(TAG, "I2C bus not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    // Probe for INA226 at default address
    esp_err_t ret = i2c_master_probe(i2c_bus, INA226_I2C_ADDR, 100);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "INA226 not found at address 0x%02X", INA226_I2C_ADDR);
        return ret;
    }
    
    // Add INA226 device to I2C bus
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = INA226_I2C_ADDR,
        .scl_speed_hz = 100000,  // 100kHz
    };
    
    ret = i2c_master_bus_add_device(i2c_bus, &dev_cfg, &ina226_dev_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add INA226 device: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Verify manufacturer ID (should be 0x5449 for TI)
    uint8_t reg = INA226_REG_MFG_ID;
    uint8_t data[2];
    ret = i2c_master_transmit_receive(ina226_dev_handle, &reg, 1, data, 2, 100);
    if (ret == ESP_OK) {
        uint16_t mfg_id = (data[0] << 8) | data[1];
        ESP_LOGI(TAG, "INA226 Manufacturer ID: 0x%04X (expected 0x5449)", mfg_id);
    }
    
    // Configure INA226: default config, averaging, conversion times
    // Default config: 0x4127 (continuous shunt and bus, 1.1ms conversion, 1 average)
    uint8_t config_cmd[3] = {INA226_REG_CONFIG, 0x41, 0x27};
    ret = i2c_master_transmit(ina226_dev_handle, config_cmd, 3, 100);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to configure INA226: %s", esp_err_to_name(ret));
    }
    
    ina226_initialized = true;
    ESP_LOGI(TAG, "INA226 Power Monitor initialized successfully");
    return ESP_OK;
}

static float ina226_read_bus_voltage(void)
{
    if (!ina226_initialized || ina226_dev_handle == NULL) {
        return 0.0f;
    }
    
    uint8_t reg = INA226_REG_BUS_VOLT;
    uint8_t data[2];
    
    esp_err_t ret = i2c_master_transmit_receive(ina226_dev_handle, &reg, 1, data, 2, 100);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to read INA226 bus voltage: %s", esp_err_to_name(ret));
        return 0.0f;
    }
    
    // Bus voltage register is 16-bit, 1.25mV per LSB
    uint16_t raw_voltage = (data[0] << 8) | data[1];
    float voltage_mv = raw_voltage * INA226_BUS_VOLT_LSB;
    float voltage_v = voltage_mv / 1000.0f;
    
    return voltage_v;
}

//==================================================================================
// Battery Status Functions
//==================================================================================

static bool get_charging_status(void)
{
    // Use USB-C detection as proxy for charging status
    // When USB-C is connected and charging is enabled, device is charging
    return bsp_usb_c_detect();
}

static void update_battery_status(void)
{
    current_battery_voltage = ina226_read_bus_voltage();
    current_charging_status = get_charging_status();
}

static void battery_status_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    
    // Read new values
    update_battery_status();
    
    // Update UI labels
    if (battery_voltage_label) {
        if (current_battery_voltage > 0.1f) {
            lv_label_set_text_fmt(battery_voltage_label, "%.2fV", current_battery_voltage);
        } else {
            lv_label_set_text(battery_voltage_label, "-- V");
        }
    }
    
    if (charging_status_label) {
        if (current_charging_status) {
            lv_label_set_text(charging_status_label, LV_SYMBOL_CHARGE " Charging");
            lv_obj_set_style_text_color(charging_status_label, lv_color_make(76, 175, 80), 0);  // Green
        } else {
            lv_label_set_text(charging_status_label, LV_SYMBOL_BATTERY_FULL);
            lv_obj_set_style_text_color(charging_status_label, lv_color_make(255, 255, 255), 0);  // White
        }
    }
}

// UART initialization
static void uart_init(void)
{
    const uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM, UART_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM, UART_TX_PIN, UART_RX_PIN, 
                                  UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    
    ESP_LOGI(TAG, "UART%d initialized: TX=%d, RX=%d, baud=%d", 
             UART_NUM, UART_TX_PIN, UART_RX_PIN, UART_BAUD_RATE);
}

// Send command over UART
static void uart_send_command(const char *cmd)
{
    uart_write_bytes(UART_NUM, cmd, strlen(cmd));
    uart_write_bytes(UART_NUM, "\r\n", 2);
    ESP_LOGI(TAG, "Sent command: %s", cmd);
}

// Parse a single network line like: "1","SSID","","C4:2B:44:12:29:21","1","WPA2","-53","2.4GHz"
static bool parse_network_line(const char *line, wifi_network_t *net)
{
    // Check if line starts with quote and number
    if (line[0] != '"') return false;
    
    char temp[256];
    strncpy(temp, line, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    
    // Parse CSV with quoted fields
    char *fields[8] = {NULL};
    int field_idx = 0;
    char *p = temp;
    
    while (*p && field_idx < 8) {
        if (*p == '"') {
            p++;  // Skip opening quote
            fields[field_idx] = p;
            // Find closing quote
            while (*p && *p != '"') p++;
            if (*p == '"') {
                *p = '\0';
                p++;
            }
            field_idx++;
            // Skip comma
            if (*p == ',') p++;
        } else {
            p++;
        }
    }
    
    if (field_idx < 8) return false;
    
    // fields[0] = index, fields[1] = SSID, fields[3] = BSSID, fields[5] = security, fields[6] = RSSI, fields[7] = band
    net->index = atoi(fields[0]);
    if (net->index <= 0) return false;
    
    strncpy(net->ssid, fields[1], sizeof(net->ssid) - 1);
    net->ssid[sizeof(net->ssid) - 1] = '\0';
    
    strncpy(net->bssid, fields[3], sizeof(net->bssid) - 1);
    net->bssid[sizeof(net->bssid) - 1] = '\0';
    
    strncpy(net->security, fields[5], sizeof(net->security) - 1);
    net->security[sizeof(net->security) - 1] = '\0';
    
    net->rssi = atoi(fields[6]);
    
    strncpy(net->band, fields[7], sizeof(net->band) - 1);
    net->band[sizeof(net->band) - 1] = '\0';
    
    return true;
}

// WiFi scan task
static void wifi_scan_task(void *arg)
{
    ESP_LOGI(TAG, "Starting WiFi scan task");
    
    // Clear previous results
    network_count = 0;
    memset(networks, 0, sizeof(networks));
    
    // Flush UART buffer
    uart_flush(UART_NUM);
    
    // Send scan command
    uart_send_command("scan_networks");
    
    // Buffer for receiving data
    static char rx_buffer[UART_BUF_SIZE];
    static char line_buffer[512];
    int line_pos = 0;
    bool scan_complete = false;
    
    TickType_t start_time = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(UART_RX_TIMEOUT);
    
    while (!scan_complete && (xTaskGetTickCount() - start_time) < timeout_ticks) {
        int len = uart_read_bytes(UART_NUM, rx_buffer, UART_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        
        if (len > 0) {
            rx_buffer[len] = '\0';
            ESP_LOGD(TAG, "Received %d bytes", len);
            
            // Process received data character by character
            for (int i = 0; i < len; i++) {
                char c = rx_buffer[i];
                
                if (c == '\n' || c == '\r') {
                    if (line_pos > 0) {
                        line_buffer[line_pos] = '\0';
                        ESP_LOGD(TAG, "Line: %s", line_buffer);
                        
                        // Check for scan complete marker
                        if (strstr(line_buffer, "Scan results printed") != NULL) {
                            scan_complete = true;
                            ESP_LOGI(TAG, "Scan complete marker received");
                            break;
                        }
                        
                        // Try to parse network line
                        if (line_buffer[0] == '"' && network_count < MAX_NETWORKS) {
                            wifi_network_t net;
                            if (parse_network_line(line_buffer, &net)) {
                                networks[network_count] = net;
                                network_count++;
                                ESP_LOGI(TAG, "Parsed network %d: %s (%s) %s", 
                                         net.index, net.ssid, net.bssid, net.band);
                            }
                        }
                        
                        line_pos = 0;
                    }
                } else if (line_pos < sizeof(line_buffer) - 1) {
                    line_buffer[line_pos++] = c;
                }
            }
        }
    }
    
    if (!scan_complete) {
        ESP_LOGW(TAG, "Scan timed out");
    }
    
    ESP_LOGI(TAG, "Scan finished. Found %d networks", network_count);
    
    // Update UI on main thread
    bsp_display_lock(0);
    
    // Hide spinner
    if (spinner) {
        lv_obj_add_flag(spinner, LV_OBJ_FLAG_HIDDEN);
    }
    
    // Update status
    if (status_label) {
        if (scan_complete) {
            lv_label_set_text_fmt(status_label, "Found %d networks", network_count);
        } else {
            lv_label_set_text(status_label, "Scan timed out");
        }
    }
    
    // Update network list
    if (network_list) {
        lv_obj_clean(network_list);
        
        for (int i = 0; i < network_count; i++) {
            wifi_network_t *net = &networks[i];
            
            // Create list item
            lv_obj_t *item = lv_obj_create(network_list);
            lv_obj_set_size(item, lv_pct(100), LV_SIZE_CONTENT);
            lv_obj_set_style_pad_all(item, 8, 0);
            lv_obj_set_style_bg_color(item, lv_color_hex(0x2D2D2D), 0);
            lv_obj_set_style_border_width(item, 0, 0);
            lv_obj_set_style_radius(item, 8, 0);
            lv_obj_set_flex_flow(item, LV_FLEX_FLOW_COLUMN);
            lv_obj_set_style_pad_row(item, 4, 0);
            
            // SSID (or "Hidden" if empty)
            lv_obj_t *ssid_label = lv_label_create(item);
            if (strlen(net->ssid) > 0) {
                lv_label_set_text(ssid_label, net->ssid);
            } else {
                lv_label_set_text(ssid_label, "(Hidden)");
            }
            lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_18, 0);
            lv_obj_set_style_text_color(ssid_label, lv_color_hex(0xFFFFFF), 0);
            
            // BSSID and Band
            lv_obj_t *info_label = lv_label_create(item);
            lv_label_set_text_fmt(info_label, "%s  |  %s  |  %d dBm", 
                                  net->bssid, net->band, net->rssi);
            lv_obj_set_style_text_font(info_label, &lv_font_montserrat_12, 0);
            lv_obj_set_style_text_color(info_label, lv_color_hex(0x888888), 0);
        }
    }
    
    // Re-enable scan button
    if (scan_btn) {
        lv_obj_clear_state(scan_btn, LV_STATE_DISABLED);
    }
    
    scan_in_progress = false;
    
    bsp_display_unlock();
    
    // Delete this task
    vTaskDelete(NULL);
}

// Scan button click handler
static void scan_btn_click_cb(lv_event_t *e)
{
    if (scan_in_progress) {
        ESP_LOGW(TAG, "Scan already in progress");
        return;
    }
    
    scan_in_progress = true;
    
    // Disable button during scan
    lv_obj_add_state(scan_btn, LV_STATE_DISABLED);
    
    // Show spinner
    if (spinner) {
        lv_obj_clear_flag(spinner, LV_OBJ_FLAG_HIDDEN);
    }
    
    // Update status
    if (status_label) {
        lv_label_set_text(status_label, "Scanning...");
    }
    
    // Clear previous results
    if (network_list) {
        lv_obj_clean(network_list);
    }
    
    // Start scan task
    xTaskCreate(wifi_scan_task, "wifi_scan", 8192, NULL, 5, NULL);
}

// Create a single tile button with icon, text, color
static lv_obj_t *create_tile(lv_obj_t *parent, const char *icon, const char *text, lv_color_t bg_color, lv_event_cb_t callback, const char *user_data)
{
    lv_obj_t *tile = lv_btn_create(parent);
    lv_obj_set_size(tile, 230, 140);  // Large tile size for 3 columns
    lv_obj_set_style_bg_color(tile, bg_color, LV_STATE_DEFAULT);
    // Pressed state: lighten the color
    lv_obj_set_style_bg_color(tile, lv_color_lighten(bg_color, 50), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(tile, 0, 0);  // No border for Material look
    lv_obj_set_style_radius(tile, 16, 0);  // Rounded corners
    lv_obj_set_style_shadow_width(tile, 12, 0);  // Material shadow
    lv_obj_set_style_shadow_color(tile, lv_color_make(0, 0, 0), 0);
    lv_obj_set_style_shadow_opa(tile, LV_OPA_30, 0);
    lv_obj_set_flex_flow(tile, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(tile, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(tile, 12, 0);
    
    if (icon) {
        lv_obj_t *icon_label = lv_label_create(tile);
        lv_label_set_text(icon_label, icon);
        lv_obj_set_style_text_font(icon_label, &lv_font_montserrat_44, 0);  // Large icon
        lv_obj_set_style_text_color(icon_label, lv_color_make(255, 255, 255), 0);  // White icon
    }
    
    if (text) {
        lv_obj_t *text_label = lv_label_create(tile);
        lv_label_set_text(text_label, text);
        lv_obj_set_style_text_font(text_label, &lv_font_montserrat_18, 0);  // Larger text
        lv_obj_set_style_text_color(text_label, lv_color_make(255, 255, 255), 0);  // White text
        lv_obj_set_style_text_align(text_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(text_label, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(text_label, 210);
    }
    
    if (callback && user_data) {
        lv_obj_add_event_cb(tile, callback, LV_EVENT_CLICKED, (void*)user_data);
    }
    
    return tile;
}

// Main tile click handler
static void main_tile_event_cb(lv_event_t *e)
{
    const char *tile_name = (const char *)lv_event_get_user_data(e);
    ESP_LOGI(TAG, "Tile clicked: %s", tile_name);
    
    if (strcmp(tile_name, "WiFi Scan & Attack") == 0) {
        show_scan_page();
    } else if (strcmp(tile_name, "Network Observer") == 0) {
        show_observer_page();
    } else if (strcmp(tile_name, "Internal C6") == 0) {
        show_esp_modem_page();
    } else {
        // Placeholder for other tiles - show a message
        ESP_LOGI(TAG, "Feature '%s' not implemented yet", tile_name);
    }
}

// Back button click handler
static void back_btn_event_cb(lv_event_t *e)
{
    (void)e;
    ESP_LOGI(TAG, "Back button clicked");
    show_main_tiles();
}

// Show main tiles screen (7 tiles)
static void show_main_tiles(void)
{
    // Delete scan page if present
    if (scan_page) {
        lv_obj_del(scan_page);
        scan_page = NULL;
        // Reset scan page child pointers
        scan_btn = NULL;
        status_label = NULL;
        network_list = NULL;
        spinner = NULL;
    }
    
    // Delete observer page if present
    if (observer_page) {
        lv_obj_del(observer_page);
        observer_page = NULL;
        // Reset observer page child pointers
        observer_start_btn = NULL;
        observer_stop_btn = NULL;
        observer_table = NULL;
        observer_status_label = NULL;
    }
    
    // Delete ESP Modem page if present
    if (esp_modem_page) {
        lv_obj_del(esp_modem_page);
        esp_modem_page = NULL;
        // Reset ESP Modem page child pointers
        esp_modem_scan_btn = NULL;
        esp_modem_status_label = NULL;
        esp_modem_network_list = NULL;
        esp_modem_spinner = NULL;
    }
    
    // Delete existing tiles container if present
    if (tiles_container) {
        lv_obj_del(tiles_container);
        tiles_container = NULL;
    }
    
    // Delete existing status bar if present
    if (status_bar) {
        lv_obj_del(status_bar);
        status_bar = NULL;
        battery_voltage_label = NULL;
        charging_status_label = NULL;
    }
    
    lv_obj_t *scr = lv_scr_act();
    
    // Set dark background
    lv_obj_set_style_bg_color(scr, COLOR_MATERIAL_BG, 0);
    
    // Create status bar at top of screen
    status_bar = lv_obj_create(scr);
    lv_obj_set_size(status_bar, lv_pct(100), 40);
    lv_obj_align(status_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(status_bar, lv_color_make(30, 30, 30), 0);  // Slightly lighter than background
    lv_obj_set_style_border_width(status_bar, 0, 0);
    lv_obj_set_style_radius(status_bar, 0, 0);
    lv_obj_set_style_pad_hor(status_bar, 16, 0);
    lv_obj_clear_flag(status_bar, LV_OBJ_FLAG_SCROLLABLE);
    
    // App title on the left
    lv_obj_t *app_title = lv_label_create(status_bar);
    lv_label_set_text(app_title, "M5Stack Tab5");
    lv_obj_set_style_text_font(app_title, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_color(app_title, COLOR_MATERIAL_BLUE, 0);
    lv_obj_align(app_title, LV_ALIGN_LEFT_MID, 0, 0);
    
    // Battery status container on the right
    lv_obj_t *battery_cont = lv_obj_create(status_bar);
    lv_obj_set_size(battery_cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(battery_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(battery_cont, 0, 0);
    lv_obj_set_style_pad_all(battery_cont, 0, 0);
    lv_obj_align(battery_cont, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_flex_flow(battery_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(battery_cont, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(battery_cont, 12, 0);
    
    // Battery voltage label
    battery_voltage_label = lv_label_create(battery_cont);
    lv_label_set_text(battery_voltage_label, "-- V");
    lv_obj_set_style_text_font(battery_voltage_label, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_color(battery_voltage_label, lv_color_make(255, 255, 255), 0);
    
    // Charging status label
    charging_status_label = lv_label_create(battery_cont);
    lv_label_set_text(charging_status_label, LV_SYMBOL_BATTERY_FULL);
    lv_obj_set_style_text_font(charging_status_label, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_color(charging_status_label, lv_color_make(255, 255, 255), 0);
    
    // Create tiles container below the status bar
    tiles_container = lv_obj_create(scr);
    lv_obj_set_size(tiles_container, lv_pct(100), lv_pct(100) - 40);  // Subtract status bar height
    lv_obj_align(tiles_container, LV_ALIGN_TOP_MID, 0, 40);  // Position below status bar
    lv_obj_set_style_bg_color(tiles_container, COLOR_MATERIAL_BG, 0);
    lv_obj_set_style_border_width(tiles_container, 0, 0);
    lv_obj_set_style_radius(tiles_container, 0, 0);
    lv_obj_set_style_pad_all(tiles_container, 20, 0);
    lv_obj_set_style_pad_gap(tiles_container, 20, 0);
    lv_obj_set_flex_flow(tiles_container, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(tiles_container, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(tiles_container, LV_OBJ_FLAG_SCROLLABLE);
    
    // Create 8 main tiles with Material colors
    create_tile(tiles_container, LV_SYMBOL_WIFI, "WiFi Scan\n& Attack", COLOR_MATERIAL_BLUE, main_tile_event_cb, "WiFi Scan & Attack");
    create_tile(tiles_container, LV_SYMBOL_WARNING, "Global WiFi\nAttacks", COLOR_MATERIAL_RED, main_tile_event_cb, "Global WiFi Attacks");
    create_tile(tiles_container, LV_SYMBOL_EYE_OPEN, "WiFi Sniff\n& Karma", COLOR_MATERIAL_PURPLE, main_tile_event_cb, "WiFi Sniff & Karma");
    create_tile(tiles_container, LV_SYMBOL_SETTINGS, "WiFi\nMonitor", COLOR_MATERIAL_GREEN, main_tile_event_cb, "WiFi Monitor");
    create_tile(tiles_container, LV_SYMBOL_GPS, "Deauth\nMonitor", COLOR_MATERIAL_AMBER, main_tile_event_cb, "Deauth Monitor");
    create_tile(tiles_container, LV_SYMBOL_BLUETOOTH, "Bluetooth", COLOR_MATERIAL_CYAN, main_tile_event_cb, "Bluetooth");
    create_tile(tiles_container, LV_SYMBOL_LOOP, "Network\nObserver", COLOR_MATERIAL_TEAL, main_tile_event_cb, "Network Observer");
    create_tile(tiles_container, LV_SYMBOL_CHARGE, "Internal\nC6", lv_color_make(255, 87, 34), main_tile_event_cb, "Internal C6");  // Deep Orange
    
    // Initialize INA226 if not already done
    if (!ina226_initialized) {
        ina226_init();
    }
    
    // Create battery status update timer
    if (battery_update_timer == NULL) {
        battery_update_timer = lv_timer_create(battery_status_timer_cb, BATTERY_UPDATE_MS, NULL);
    }
    
    // Immediately update battery status
    update_battery_status();
    battery_status_timer_cb(NULL);
}

// Show WiFi Scanner page with Back button
static void show_scan_page(void)
{
    // Delete tiles container if present
    if (tiles_container) {
        lv_obj_del(tiles_container);
        tiles_container = NULL;
    }
    
    // Delete status bar if present
    if (status_bar) {
        lv_obj_del(status_bar);
        status_bar = NULL;
        battery_voltage_label = NULL;
        charging_status_label = NULL;
    }
    
    // Stop battery update timer when leaving main tiles
    if (battery_update_timer) {
        lv_timer_del(battery_update_timer);
        battery_update_timer = NULL;
    }
    
    // Delete existing scan page if present
    if (scan_page) {
        lv_obj_del(scan_page);
        scan_page = NULL;
    }
    
    lv_obj_t *scr = lv_scr_act();
    
    // Set dark background
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1A1A), 0);
    
    // Create scan page container
    scan_page = lv_obj_create(scr);
    lv_obj_set_size(scan_page, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(scan_page, lv_color_hex(0x1A1A1A), 0);
    lv_obj_set_style_border_width(scan_page, 0, 0);
    lv_obj_set_style_pad_all(scan_page, 16, 0);
    lv_obj_set_flex_flow(scan_page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(scan_page, 12, 0);
    
    // Header container
    lv_obj_t *header = lv_obj_create(scan_page);
    lv_obj_set_size(header, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(header, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_pad_all(header, 0, 0);
    lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(header, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Left side: Back button + Title
    lv_obj_t *left_cont = lv_obj_create(header);
    lv_obj_set_size(left_cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(left_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(left_cont, 0, 0);
    lv_obj_set_style_pad_all(left_cont, 0, 0);
    lv_obj_set_flex_flow(left_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(left_cont, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(left_cont, 12, 0);
    
    // Back button
    lv_obj_t *back_btn = lv_btn_create(left_cont);
    lv_obj_set_size(back_btn, 48, 40);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x333333), 0);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x444444), LV_STATE_PRESSED);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_add_event_cb(back_btn, back_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(back_icon, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(back_icon);
    
    // Title
    lv_obj_t *title = lv_label_create(left_cont);
    lv_label_set_text(title, "WiFi Scanner");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(title, COLOR_MATERIAL_BLUE, 0);
    
    // Scan button container (for button + spinner)
    lv_obj_t *btn_cont = lv_obj_create(header);
    lv_obj_set_size(btn_cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(btn_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_cont, 0, 0);
    lv_obj_set_style_pad_all(btn_cont, 0, 0);
    lv_obj_set_flex_flow(btn_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_cont, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(btn_cont, 12, 0);
    
    // Spinner (hidden by default)
    spinner = lv_spinner_create(btn_cont);
    lv_obj_set_size(spinner, 32, 32);
    lv_spinner_set_anim_params(spinner, 1000, 200);
    lv_obj_add_flag(spinner, LV_OBJ_FLAG_HIDDEN);
    
    // Scan button
    scan_btn = lv_btn_create(btn_cont);
    lv_obj_set_size(scan_btn, 120, 40);
    lv_obj_set_style_bg_color(scan_btn, COLOR_MATERIAL_BLUE, 0);
    lv_obj_set_style_bg_color(scan_btn, lv_color_lighten(COLOR_MATERIAL_BLUE, 30), LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(scan_btn, lv_color_hex(0x444444), LV_STATE_DISABLED);
    lv_obj_set_style_radius(scan_btn, 8, 0);
    lv_obj_add_event_cb(scan_btn, scan_btn_click_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *btn_label = lv_label_create(scan_btn);
    lv_label_set_text(btn_label, "SCAN");
    lv_obj_set_style_text_font(btn_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(btn_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(btn_label);
    
    // Status label
    status_label = lv_label_create(scan_page);
    lv_label_set_text(status_label, "Press SCAN to search for networks");
    lv_obj_set_style_text_font(status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(status_label, lv_color_hex(0x888888), 0);
    
    // Network list container (scrollable)
    network_list = lv_obj_create(scan_page);
    lv_obj_set_size(network_list, lv_pct(100), lv_pct(100));
    lv_obj_set_flex_grow(network_list, 1);
    lv_obj_set_style_bg_color(network_list, lv_color_hex(0x1A1A1A), 0);
    lv_obj_set_style_border_color(network_list, lv_color_hex(0x333333), 0);
    lv_obj_set_style_border_width(network_list, 1, 0);
    lv_obj_set_style_radius(network_list, 12, 0);
    lv_obj_set_style_pad_all(network_list, 8, 0);
    lv_obj_set_flex_flow(network_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(network_list, 8, 0);
    lv_obj_set_scroll_dir(network_list, LV_DIR_VER);
    
    // Auto-start scan when entering the page
    lv_obj_send_event(scan_btn, LV_EVENT_CLICKED, NULL);
}

// ======================= Network Observer Page =======================

// Forward declare popup poll task
static void popup_poll_task(void *arg);

// Popup timer callback - triggers poll task every 10s
static void popup_timer_callback(TimerHandle_t xTimer)
{
    (void)xTimer;
    
    if (!popup_open || !observer_running) return;
    
    // Only start new poll if previous one finished
    if (observer_task_handle == NULL) {
        xTaskCreate(popup_poll_task, "popup_poll", 8192, NULL, 5, &observer_task_handle);
    }
}

// Update popup content with current network data
static void update_popup_content(void)
{
    if (!popup_obj || popup_network_idx < 0 || popup_network_idx >= observer_network_count) return;
    
    observer_network_t *net = &observer_networks[popup_network_idx];
    
    // Update clients container
    if (popup_clients_container) {
        lv_obj_clean(popup_clients_container);
        
        if (net->client_count == 0) {
            lv_obj_t *no_clients = lv_label_create(popup_clients_container);
            lv_label_set_text(no_clients, "No clients detected yet...");
            lv_obj_set_style_text_color(no_clients, lv_color_hex(0x666666), 0);
        } else {
            for (int j = 0; j < net->client_count && j < MAX_CLIENTS_PER_NETWORK; j++) {
                if (net->clients[j][0] != '\0') {
                    lv_obj_t *client_label = lv_label_create(popup_clients_container);
                    lv_label_set_text_fmt(client_label, "  %s", net->clients[j]);
                    lv_obj_set_style_text_font(client_label, &lv_font_montserrat_14, 0);
                    lv_obj_set_style_text_color(client_label, lv_color_hex(0xAAAAAA), 0);
                }
            }
        }
    }
}

// Popup close button click handler
static void popup_close_btn_cb(lv_event_t *e)
{
    (void)e;
    ESP_LOGI(TAG, "Popup close button clicked");
    close_network_popup();
}

// Close network popup and resume normal monitoring
static void close_network_popup(void)
{
    if (!popup_open) return;
    
    ESP_LOGI(TAG, "Closing network popup");
    
    // Stop popup timer
    if (popup_timer != NULL) {
        xTimerStop(popup_timer, 0);
    }
    
    // Send unselect_networks to monitor all networks again
    uart_send_command("unselect_networks");
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Restart sniffer for all networks (without new scan)
    uart_send_command("start_sniffer_noscan");
    
    // Close popup UI
    if (popup_obj) {
        lv_obj_del(popup_obj);
        popup_obj = NULL;
        popup_clients_container = NULL;
    }
    
    popup_open = false;
    popup_network_idx = -1;
    
    // Restart main observer timer (20s)
    if (observer_timer != NULL && observer_running) {
        xTimerStart(observer_timer, 0);
        ESP_LOGI(TAG, "Resumed main observer timer (20s)");
    }
    
    // Refresh main table
    if (observer_table) {
        update_observer_table();
    }
}

// Show network popup for detailed view
static void show_network_popup(int network_idx)
{
    if (network_idx < 0 || network_idx >= observer_network_count) return;
    if (popup_open) return;  // Already showing a popup
    
    observer_network_t *net = &observer_networks[network_idx];
    ESP_LOGI(TAG, "Opening popup for network: %s (scan_index=%d)", net->ssid, net->scan_index);
    
    popup_open = true;
    popup_network_idx = network_idx;
    
    // Stop main observer timer
    if (observer_timer != NULL) {
        xTimerStop(observer_timer, 0);
        ESP_LOGI(TAG, "Stopped main observer timer");
    }
    
    // Send commands to focus on this network
    uart_send_command("stop");
    vTaskDelay(pdMS_TO_TICKS(200));
    
    // Send select_networks with the scan index
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "select_networks %d", net->scan_index);
    uart_send_command(cmd);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Start sniffer for selected network only
    uart_send_command("start_sniffer");
    
    // Create popup overlay
    lv_obj_t *scr = lv_scr_act();
    popup_obj = lv_obj_create(scr);
    lv_obj_set_size(popup_obj, 600, 400);
    lv_obj_center(popup_obj);
    lv_obj_set_style_bg_color(popup_obj, lv_color_hex(0x1A2A2A), 0);
    lv_obj_set_style_border_color(popup_obj, COLOR_MATERIAL_TEAL, 0);
    lv_obj_set_style_border_width(popup_obj, 2, 0);
    lv_obj_set_style_radius(popup_obj, 16, 0);
    lv_obj_set_style_shadow_width(popup_obj, 30, 0);
    lv_obj_set_style_shadow_color(popup_obj, lv_color_hex(0x000000), 0);
    lv_obj_set_style_shadow_opa(popup_obj, LV_OPA_50, 0);
    lv_obj_set_style_pad_all(popup_obj, 16, 0);
    lv_obj_set_flex_flow(popup_obj, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(popup_obj, 8, 0);
    
    // Header with title and close button
    lv_obj_t *header = lv_obj_create(popup_obj);
    lv_obj_set_size(header, lv_pct(100), 40);
    lv_obj_set_style_bg_opa(header, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_pad_all(header, 0, 0);
    lv_obj_clear_flag(header, LV_OBJ_FLAG_SCROLLABLE);
    
    // Title
    lv_obj_t *title = lv_label_create(header);
    const char *ssid_display = strlen(net->ssid) > 0 ? net->ssid : "Unknown";
    lv_label_set_text_fmt(title, "Scanning only %s", ssid_display);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(title, COLOR_MATERIAL_TEAL, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);
    
    // Close button (X)
    lv_obj_t *close_btn = lv_btn_create(header);
    lv_obj_set_size(close_btn, 40, 40);
    lv_obj_align(close_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(close_btn, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_bg_color(close_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(close_btn, 8, 0);
    lv_obj_add_event_cb(close_btn, popup_close_btn_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *close_icon = lv_label_create(close_btn);
    lv_label_set_text(close_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(close_icon, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(close_icon);
    
    // Network info section
    lv_obj_t *info_container = lv_obj_create(popup_obj);
    lv_obj_set_size(info_container, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(info_container, lv_color_hex(0x0A1A1A), 0);
    lv_obj_set_style_border_width(info_container, 0, 0);
    lv_obj_set_style_radius(info_container, 8, 0);
    lv_obj_set_style_pad_all(info_container, 12, 0);
    lv_obj_set_flex_flow(info_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(info_container, 4, 0);
    lv_obj_clear_flag(info_container, LV_OBJ_FLAG_SCROLLABLE);
    
    // SSID
    lv_obj_t *ssid_label = lv_label_create(info_container);
    lv_label_set_text_fmt(ssid_label, "SSID: %s", ssid_display);
    lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(ssid_label, lv_color_hex(0xFFFFFF), 0);
    
    // BSSID
    lv_obj_t *bssid_label = lv_label_create(info_container);
    lv_label_set_text_fmt(bssid_label, "BSSID: %s", net->bssid);
    lv_obj_set_style_text_font(bssid_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(bssid_label, lv_color_hex(0xCCCCCC), 0);
    
    // Channel + Band + RSSI
    lv_obj_t *channel_label = lv_label_create(info_container);
    lv_label_set_text_fmt(channel_label, "Channel: %d  |  %s  |  %d dBm", net->channel, net->band, net->rssi);
    lv_obj_set_style_text_font(channel_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(channel_label, lv_color_hex(0xCCCCCC), 0);
    
    // Clients section header
    lv_obj_t *clients_header = lv_label_create(popup_obj);
    lv_label_set_text_fmt(clients_header, "Clients (%d):", net->client_count);
    lv_obj_set_style_text_font(clients_header, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(clients_header, COLOR_MATERIAL_TEAL, 0);
    
    // Clients scrollable container
    popup_clients_container = lv_obj_create(popup_obj);
    lv_obj_set_size(popup_clients_container, lv_pct(100), lv_pct(100));
    lv_obj_set_flex_grow(popup_clients_container, 1);
    lv_obj_set_style_bg_color(popup_clients_container, lv_color_hex(0x0A1A1A), 0);
    lv_obj_set_style_border_width(popup_clients_container, 0, 0);
    lv_obj_set_style_radius(popup_clients_container, 8, 0);
    lv_obj_set_style_pad_all(popup_clients_container, 8, 0);
    lv_obj_set_flex_flow(popup_clients_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(popup_clients_container, 4, 0);
    lv_obj_set_scroll_dir(popup_clients_container, LV_DIR_VER);
    
    // Initial client list
    update_popup_content();
    
    // Create and start popup timer (10s polling)
    if (popup_timer == NULL) {
        popup_timer = xTimerCreate("popup_timer", 
                                   pdMS_TO_TICKS(POPUP_POLL_INTERVAL_MS),
                                   pdTRUE,  // Auto-reload
                                   NULL,
                                   popup_timer_callback);
    }
    
    if (popup_timer != NULL) {
        xTimerStart(popup_timer, 0);
        ESP_LOGI(TAG, "Started popup timer (10s polling)");
        
        // Do first poll after a short delay
        vTaskDelay(pdMS_TO_TICKS(2000));
        if (popup_open && observer_task_handle == NULL) {
            xTaskCreate(popup_poll_task, "popup_poll", 8192, NULL, 5, &observer_task_handle);
        }
    }
}

// Helper: Check if MAC already exists in network's client list
static bool client_mac_exists(observer_network_t *net, const char *mac)
{
    for (int i = 0; i < MAX_CLIENTS_PER_NETWORK; i++) {
        if (net->clients[i][0] != '\0' && strcmp(net->clients[i], mac) == 0) {
            return true;
        }
    }
    return false;
}

// Helper: Add client MAC to network if not already present, returns true if added
static bool add_client_mac(observer_network_t *net, const char *mac)
{
    // Check if already exists
    if (client_mac_exists(net, mac)) {
        return false;
    }
    
    // Find empty slot
    for (int i = 0; i < MAX_CLIENTS_PER_NETWORK; i++) {
        if (net->clients[i][0] == '\0') {
            strncpy(net->clients[i], mac, sizeof(net->clients[i]) - 1);
            net->clients[i][sizeof(net->clients[i]) - 1] = '\0';
            net->client_count++;
            return true;
        }
    }
    return false;  // No room
}

// Popup poll task - similar to observer_poll_task but updates popup content
static void popup_poll_task(void *arg)
{
    ESP_LOGI(TAG, "Popup poll task started for network idx %d", popup_network_idx);
    
    if (!observer_rx_buffer || !observer_line_buffer || !observer_networks) {
        ESP_LOGE(TAG, "PSRAM buffers not allocated!");
        observer_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    uart_flush(UART_NUM);
    uart_send_command("show_sniffer_results");
    
    char *rx_buffer = observer_rx_buffer;
    char *line_buffer = observer_line_buffer;
    int line_pos = 0;
    int current_network_idx = -1;
    
    // DON'T clear client data - accumulate clients over time
    
    TickType_t start_time = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(5000);
    
    while ((xTaskGetTickCount() - start_time) < timeout_ticks) {
        int len = uart_read_bytes(UART_NUM, rx_buffer, UART_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        
        if (len > 0) {
            rx_buffer[len] = '\0';
            
            for (int i = 0; i < len; i++) {
                char c = rx_buffer[i];
                
                if (c == '\n' || c == '\r') {
                    if (line_pos > 0) {
                        line_buffer[line_pos] = '\0';
                        
                        ESP_LOGD(TAG, "POPUP SNIFFER LINE: '%s'", line_buffer);
                        
                        // Check for network line (doesn't start with space)
                        if (line_buffer[0] != ' ' && line_buffer[0] != '\t') {
                            observer_network_t parsed_net = {0};
                            if (parse_sniffer_network_line(line_buffer, &parsed_net)) {
                                // Find this network in our existing list by SSID
                                current_network_idx = -1;
                                for (int n = 0; n < observer_network_count; n++) {
                                    if (strcmp(observer_networks[n].ssid, parsed_net.ssid) == 0) {
                                        current_network_idx = n;
                                        // Don't overwrite client_count - we track it via add_client_mac
                                        break;
                                    }
                                }
                            } else {
                                current_network_idx = -1;
                            }
                        }
                        // Check for client MAC line (starts with space)
                        else if ((line_buffer[0] == ' ' || line_buffer[0] == '\t') && current_network_idx >= 0) {
                            observer_network_t *net = &observer_networks[current_network_idx];
                            char mac[18];
                            if (parse_sniffer_client_line(line_buffer, mac, sizeof(mac))) {
                                // Add client if not already present (accumulate)
                                if (add_client_mac(net, mac)) {
                                    ESP_LOGI(TAG, "  -> NEW client: %s for '%s'", mac, net->ssid);
                                }
                            }
                        }
                        
                        line_pos = 0;
                    }
                } else if (line_pos < OBSERVER_LINE_BUFFER_SIZE - 1) {
                    line_buffer[line_pos++] = c;
                }
            }
        }
        
        if (!popup_open) {
            ESP_LOGI(TAG, "Popup closed during poll");
            break;
        }
    }
    
    // Update popup UI
    if (popup_open) {
        bsp_display_lock(0);
        update_popup_content();
        bsp_display_unlock();
    }
    
    ESP_LOGI(TAG, "Popup poll task finished");
    observer_task_handle = NULL;
    vTaskDelete(NULL);
}

// Update observer table UI with current data
static void update_observer_table(void)
{
    if (!observer_table) return;
    
    lv_obj_clean(observer_table);
    
    for (int i = 0; i < observer_network_count; i++) {
        observer_network_t *net = &observer_networks[i];
        
        // Create network row (darker background, clickable) - 2 lines like WiFi Scanner
        lv_obj_t *net_row = lv_obj_create(observer_table);
        lv_obj_set_size(net_row, lv_pct(100), LV_SIZE_CONTENT);
        lv_obj_set_style_pad_all(net_row, 8, 0);
        lv_obj_set_style_bg_color(net_row, lv_color_hex(0x2D2D2D), 0);
        lv_obj_set_style_bg_color(net_row, lv_color_hex(0x3D3D3D), LV_STATE_PRESSED);
        lv_obj_set_style_border_width(net_row, 0, 0);
        lv_obj_set_style_radius(net_row, 8, 0);
        lv_obj_set_flex_flow(net_row, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_row(net_row, 4, 0);
        lv_obj_clear_flag(net_row, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_flag(net_row, LV_OBJ_FLAG_CLICKABLE);
        
        // Add click event with network index as user data
        lv_obj_add_event_cb(net_row, network_row_click_cb, LV_EVENT_CLICKED, (void*)(intptr_t)i);
        
        // First row: SSID (or "Hidden") + client count
        lv_obj_t *ssid_label = lv_label_create(net_row);
        if (strlen(net->ssid) > 0) {
            if (net->client_count > 0) {
                lv_label_set_text_fmt(ssid_label, "%s  (%d clients)", net->ssid, net->client_count);
            } else {
                lv_label_set_text(ssid_label, net->ssid);
            }
        } else {
            if (net->client_count > 0) {
                lv_label_set_text_fmt(ssid_label, "(Hidden)  (%d clients)", net->client_count);
            } else {
                lv_label_set_text(ssid_label, "(Hidden)");
            }
        }
        lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_18, 0);
        lv_obj_set_style_text_color(ssid_label, lv_color_hex(0xFFFFFF), 0);
        
        // Second row: BSSID | Band | RSSI
        lv_obj_t *info_label = lv_label_create(net_row);
        lv_label_set_text_fmt(info_label, "%s  |  %s  |  %d dBm", 
                              net->bssid, net->band, net->rssi);
        lv_obj_set_style_text_font(info_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(info_label, lv_color_hex(0x888888), 0);
        
        // Create client rows (indented, lighter background, clickable)
        for (int j = 0; j < MAX_CLIENTS_PER_NETWORK; j++) {
            if (net->clients[j][0] == '\0') continue;
            
            lv_obj_t *client_row = lv_obj_create(observer_table);
            lv_obj_set_size(client_row, lv_pct(100), LV_SIZE_CONTENT);
            lv_obj_set_style_pad_all(client_row, 6, 0);
            lv_obj_set_style_pad_left(client_row, 32, 0);  // Indent
            lv_obj_set_style_bg_color(client_row, lv_color_hex(0x1E2828), 0);
            lv_obj_set_style_bg_color(client_row, lv_color_hex(0x2E3838), LV_STATE_PRESSED);
            lv_obj_set_style_border_width(client_row, 0, 0);
            lv_obj_set_style_radius(client_row, 4, 0);
            lv_obj_clear_flag(client_row, LV_OBJ_FLAG_SCROLLABLE);
            lv_obj_add_flag(client_row, LV_OBJ_FLAG_CLICKABLE);
            
            // Pack network_idx and client_idx into user_data: (network_idx << 16) | client_idx
            intptr_t packed_data = ((intptr_t)i << 16) | (intptr_t)j;
            lv_obj_add_event_cb(client_row, client_row_click_cb, LV_EVENT_CLICKED, (void*)packed_data);
            
            lv_obj_t *mac_label = lv_label_create(client_row);
            lv_label_set_text(mac_label, net->clients[j]);
            lv_obj_set_style_text_font(mac_label, &lv_font_montserrat_14, 0);
            lv_obj_set_style_text_color(mac_label, COLOR_MATERIAL_TEAL, 0);
        }
    }
}

// Network row click handler
static void network_row_click_cb(lv_event_t *e)
{
    int network_idx = (int)(intptr_t)lv_event_get_user_data(e);
    ESP_LOGI(TAG, "Network row clicked: index %d", network_idx);
    
    if (network_idx >= 0 && network_idx < observer_network_count) {
        show_network_popup(network_idx);
    }
}

// Client row click handler - opens deauth popup
static void client_row_click_cb(lv_event_t *e)
{
    intptr_t packed_data = (intptr_t)lv_event_get_user_data(e);
    int network_idx = (int)(packed_data >> 16);
    int client_idx = (int)(packed_data & 0xFFFF);
    
    ESP_LOGI(TAG, "Client row clicked: network=%d, client=%d", network_idx, client_idx);
    
    if (network_idx >= 0 && network_idx < observer_network_count &&
        client_idx >= 0 && client_idx < MAX_CLIENTS_PER_NETWORK) {
        show_deauth_popup(network_idx, client_idx);
    }
}

// Show deauth popup for a specific client
static void show_deauth_popup(int network_idx, int client_idx)
{
    if (network_idx < 0 || network_idx >= observer_network_count) return;
    if (deauth_popup_obj != NULL) return;  // Already showing a popup
    
    observer_network_t *net = &observer_networks[network_idx];
    if (net->clients[client_idx][0] == '\0') return;
    
    const char *client_mac = net->clients[client_idx];
    ESP_LOGI(TAG, "Opening deauth popup for client: %s on network: %s", client_mac, net->ssid);
    
    deauth_network_idx = network_idx;
    deauth_client_idx = client_idx;
    deauth_active = false;  // Not yet deauthing
    
    // Stop main observer timer
    if (observer_timer != NULL) {
        xTimerStop(observer_timer, 0);
        ESP_LOGI(TAG, "Stopped main observer timer for deauth popup");
    }
    
    // Create popup overlay
    lv_obj_t *scr = lv_scr_act();
    deauth_popup_obj = lv_obj_create(scr);
    lv_obj_set_size(deauth_popup_obj, 550, 320);
    lv_obj_center(deauth_popup_obj);
    lv_obj_set_style_bg_color(deauth_popup_obj, lv_color_hex(0x1A1A2A), 0);
    lv_obj_set_style_border_color(deauth_popup_obj, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_border_width(deauth_popup_obj, 2, 0);
    lv_obj_set_style_radius(deauth_popup_obj, 16, 0);
    lv_obj_set_style_shadow_width(deauth_popup_obj, 30, 0);
    lv_obj_set_style_shadow_color(deauth_popup_obj, lv_color_hex(0x000000), 0);
    lv_obj_set_style_shadow_opa(deauth_popup_obj, LV_OPA_50, 0);
    lv_obj_set_style_pad_all(deauth_popup_obj, 16, 0);
    lv_obj_set_flex_flow(deauth_popup_obj, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(deauth_popup_obj, 12, 0);
    
    // Header with title and close button
    lv_obj_t *header = lv_obj_create(deauth_popup_obj);
    lv_obj_set_size(header, lv_pct(100), 40);
    lv_obj_set_style_bg_opa(header, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_pad_all(header, 0, 0);
    lv_obj_clear_flag(header, LV_OBJ_FLAG_SCROLLABLE);
    
    // Title
    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "Deauth Station");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(title, COLOR_MATERIAL_RED, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);
    
    // Close button (X)
    lv_obj_t *close_btn = lv_btn_create(header);
    lv_obj_set_size(close_btn, 40, 40);
    lv_obj_align(close_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(close_btn, lv_color_hex(0x444444), 0);
    lv_obj_set_style_bg_color(close_btn, lv_color_hex(0x555555), LV_STATE_PRESSED);
    lv_obj_set_style_radius(close_btn, 8, 0);
    lv_obj_add_event_cb(close_btn, deauth_btn_click_cb, LV_EVENT_CLICKED, (void*)(intptr_t)1);  // 1 = close button
    
    lv_obj_t *close_icon = lv_label_create(close_btn);
    lv_label_set_text(close_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(close_icon, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(close_icon);
    
    // Network info section
    lv_obj_t *info_container = lv_obj_create(deauth_popup_obj);
    lv_obj_set_size(info_container, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(info_container, lv_color_hex(0x0A0A1A), 0);
    lv_obj_set_style_border_width(info_container, 0, 0);
    lv_obj_set_style_radius(info_container, 8, 0);
    lv_obj_set_style_pad_all(info_container, 12, 0);
    lv_obj_set_flex_flow(info_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(info_container, 4, 0);
    lv_obj_clear_flag(info_container, LV_OBJ_FLAG_SCROLLABLE);
    
    // SSID
    const char *ssid_display = strlen(net->ssid) > 0 ? net->ssid : "(Hidden)";
    lv_obj_t *ssid_label = lv_label_create(info_container);
    lv_label_set_text_fmt(ssid_label, "Network: %s", ssid_display);
    lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(ssid_label, lv_color_hex(0xFFFFFF), 0);
    
    // BSSID + Channel
    lv_obj_t *bssid_label = lv_label_create(info_container);
    lv_label_set_text_fmt(bssid_label, "BSSID: %s  |  CH%d", net->bssid, net->channel);
    lv_obj_set_style_text_font(bssid_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(bssid_label, lv_color_hex(0xAAAAAA), 0);
    
    // Client MAC (highlighted)
    lv_obj_t *client_label = lv_label_create(info_container);
    lv_label_set_text_fmt(client_label, "Station: %s", client_mac);
    lv_obj_set_style_text_font(client_label, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_color(client_label, COLOR_MATERIAL_RED, 0);
    
    // Deauth button (red)
    deauth_btn = lv_btn_create(deauth_popup_obj);
    lv_obj_set_size(deauth_btn, lv_pct(100), 60);
    lv_obj_set_style_bg_color(deauth_btn, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_bg_color(deauth_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(deauth_btn, 12, 0);
    lv_obj_add_event_cb(deauth_btn, deauth_btn_click_cb, LV_EVENT_CLICKED, (void*)(intptr_t)0);  // 0 = deauth/stop button
    
    deauth_btn_label = lv_label_create(deauth_btn);
    lv_label_set_text(deauth_btn_label, "Deauth Station");
    lv_obj_set_style_text_font(deauth_btn_label, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(deauth_btn_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(deauth_btn_label);
}

// Close deauth popup and cleanup
static void close_deauth_popup(void)
{
    ESP_LOGI(TAG, "Closing deauth popup");
    
    // Send stop commands
    uart_send_command("stop");
    vTaskDelay(pdMS_TO_TICKS(100));
    uart_send_command("start_sniffer_noscan");
    
    // Delete popup UI
    if (deauth_popup_obj != NULL) {
        lv_obj_del(deauth_popup_obj);
        deauth_popup_obj = NULL;
    }
    deauth_btn = NULL;
    deauth_btn_label = NULL;
    deauth_active = false;
    deauth_network_idx = -1;
    deauth_client_idx = -1;
    
    // Resume main observer timer
    if (observer_timer != NULL) {
        xTimerStart(observer_timer, 0);
        ESP_LOGI(TAG, "Resumed main observer timer");
    }
}

// Deauth button click handler
static void deauth_btn_click_cb(lv_event_t *e)
{
    intptr_t btn_type = (intptr_t)lv_event_get_user_data(e);
    
    if (btn_type == 1) {
        // Close button (X) clicked
        close_deauth_popup();
        return;
    }
    
    // Deauth/Stop button clicked
    if (!deauth_active) {
        // Start deauth
        if (deauth_network_idx >= 0 && deauth_network_idx < observer_network_count &&
            deauth_client_idx >= 0 && deauth_client_idx < MAX_CLIENTS_PER_NETWORK) {
            
            observer_network_t *net = &observer_networks[deauth_network_idx];
            const char *client_mac = net->clients[deauth_client_idx];
            
            ESP_LOGI(TAG, "Starting deauth: network=%d (scan_idx=%d), client=%s", 
                     deauth_network_idx, net->scan_index, client_mac);
            
            // Send UART commands
            uart_send_command("stop");
            vTaskDelay(pdMS_TO_TICKS(100));
            
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "select_networks %d", net->scan_index);
            uart_send_command(cmd);
            vTaskDelay(pdMS_TO_TICKS(100));
            
            snprintf(cmd, sizeof(cmd), "select_stations %s", client_mac);
            uart_send_command(cmd);
            vTaskDelay(pdMS_TO_TICKS(100));
            
            uart_send_command("start_deauth");
            
            // Change button to STOP
            deauth_active = true;
            if (deauth_btn_label != NULL) {
                lv_label_set_text(deauth_btn_label, "STOP");
            }
            ESP_LOGI(TAG, "Deauth started");
        }
    } else {
        // Stop deauth and return to sniffer
        ESP_LOGI(TAG, "Stopping deauth");
        close_deauth_popup();
    }
}

// Parse sniffer output line - returns true if network line parsed
static bool parse_sniffer_network_line(const char *line, observer_network_t *net)
{
    // Format: "SSID, CHxx: count" or "Unknown_XXXX, CHxx: count"
    // Line should NOT start with space (those are client MACs)
    if (line[0] == ' ' || line[0] == '\t') return false;
    
    // Find ", CH" marker
    const char *ch_marker = strstr(line, ", CH");
    if (!ch_marker) return false;
    
    // Extract SSID (everything before ", CH")
    int ssid_len = ch_marker - line;
    if (ssid_len >= (int)sizeof(net->ssid)) ssid_len = sizeof(net->ssid) - 1;
    strncpy(net->ssid, line, ssid_len);
    net->ssid[ssid_len] = '\0';
    
    // Parse channel and client count: "CHxx: count"
    int channel = 0, count = 0;
    if (sscanf(ch_marker, ", CH%d: %d", &channel, &count) == 2) {
        net->channel = channel;
        net->client_count = count;
        return true;
    }
    
    return false;
}

// Parse client MAC line (starts with space)
static bool parse_sniffer_client_line(const char *line, char *mac_out, size_t mac_size)
{
    // Line starts with space followed by MAC address
    if (line[0] != ' ') return false;
    
    // Skip leading whitespace
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    
    // Check if it looks like a MAC address (XX:XX:XX:XX:XX:XX)
    if (strlen(p) >= 17 && p[2] == ':' && p[5] == ':') {
        strncpy(mac_out, p, mac_size - 1);
        mac_out[mac_size - 1] = '\0';
        // Trim trailing whitespace/newline
        char *end = mac_out + strlen(mac_out) - 1;
        while (end > mac_out && (*end == ' ' || *end == '\n' || *end == '\r')) {
            *end = '\0';
            end--;
        }
        return true;
    }
    
    return false;
}

// Observer poll task - runs show_sniffer_results and parses output
static void observer_poll_task(void *arg)
{
    ESP_LOGI(TAG, "Observer poll task started");
    
    // Check if PSRAM buffers are allocated
    if (!observer_rx_buffer || !observer_line_buffer || !observer_networks) {
        ESP_LOGE(TAG, "PSRAM buffers not allocated!");
        observer_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Flush UART buffer
    uart_flush(UART_NUM);
    
    // Send show_sniffer_results command
    uart_send_command("show_sniffer_results");
    
    // Use PSRAM-allocated buffers
    char *rx_buffer = observer_rx_buffer;
    char *line_buffer = observer_line_buffer;
    int line_pos = 0;
    
    // Track current network being updated (index into observer_networks)
    int current_network_idx = -1;
    
    // DON'T clear client data - accumulate clients over time
    
    TickType_t start_time = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(5000);  // 5 second timeout for response
    
    while ((xTaskGetTickCount() - start_time) < timeout_ticks) {
        int len = uart_read_bytes(UART_NUM, rx_buffer, UART_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        
        if (len > 0) {
            rx_buffer[len] = '\0';
            
            for (int i = 0; i < len; i++) {
                char c = rx_buffer[i];
                
                if (c == '\n' || c == '\r') {
                    if (line_pos > 0) {
                        line_buffer[line_pos] = '\0';
                        ESP_LOGD(TAG, "Observer line: %s", line_buffer);
                        
                        // Log every line received for debugging
                        ESP_LOGI(TAG, "SNIFFER LINE: '%s'", line_buffer);
                        
                        // Check for network line (doesn't start with space)
                        if (line_buffer[0] != ' ' && line_buffer[0] != '\t') {
                            observer_network_t parsed_net = {0};
                            if (parse_sniffer_network_line(line_buffer, &parsed_net)) {
                                // Find this network in our existing list by SSID
                                current_network_idx = -1;
                                for (int n = 0; n < observer_network_count; n++) {
                                    if (strcmp(observer_networks[n].ssid, parsed_net.ssid) == 0) {
                                        current_network_idx = n;
                                        // Don't overwrite client_count - we track it via add_client_mac
                                        ESP_LOGI(TAG, "  -> Found network '%s' at idx %d (our count: %d)", 
                                                 parsed_net.ssid, n, observer_networks[n].client_count);
                                        break;
                                    }
                                }
                                if (current_network_idx < 0) {
                                    ESP_LOGW(TAG, "  -> Network '%s' not in scan list, skipping", parsed_net.ssid);
                                }
                            } else {
                                // Not a network line (could be command echo, prompt, etc.)
                                current_network_idx = -1;
                            }
                        }
                        // Check for client MAC line (starts with space)
                        else if ((line_buffer[0] == ' ' || line_buffer[0] == '\t') && current_network_idx >= 0) {
                            observer_network_t *net = &observer_networks[current_network_idx];
                            char mac[18];
                            if (parse_sniffer_client_line(line_buffer, mac, sizeof(mac))) {
                                // Add client if not already present (accumulate)
                                if (add_client_mac(net, mac)) {
                                    ESP_LOGI(TAG, "  -> NEW client: %s for '%s' (total: %d)", mac, net->ssid, net->client_count);
                                }
                            } else {
                                ESP_LOGW(TAG, "  -> Failed to parse as client MAC");
                            }
                        }
                        
                        line_pos = 0;
                    }
                } else if (line_pos < OBSERVER_LINE_BUFFER_SIZE - 1) {
                    line_buffer[line_pos++] = c;
                }
            }
        }
        
        // Check if observer was stopped
        if (!observer_running) {
            ESP_LOGI(TAG, "Observer stopped during poll");
            break;
        }
    }
    
    // Log summary of parsed data
    ESP_LOGI(TAG, "=== SNIFFER UPDATE SUMMARY ===");
    ESP_LOGI(TAG, "Total networks: %d", observer_network_count);
    int networks_with_clients = 0;
    for (int i = 0; i < observer_network_count; i++) {
        if (observer_networks[i].client_count > 0) {
            networks_with_clients++;
            ESP_LOGI(TAG, "  Network %d: '%s' CH%d clients=%d", 
                     i, observer_networks[i].ssid, observer_networks[i].channel, observer_networks[i].client_count);
            for (int j = 0; j < MAX_CLIENTS_PER_NETWORK && observer_networks[i].clients[j][0] != '\0'; j++) {
                ESP_LOGI(TAG, "    Client %d: %s", j, observer_networks[i].clients[j]);
            }
        }
    }
    ESP_LOGI(TAG, "Networks with active clients: %d/%d", networks_with_clients, observer_network_count);
    ESP_LOGI(TAG, "==============================");
    
    // Update UI if observer is still running
    if (observer_running && observer_networks) {
        
        // Update UI
        bsp_display_lock(0);
        
        if (observer_status_label) {
            lv_label_set_text_fmt(observer_status_label, "Found %d networks", observer_network_count);
        }
        
        update_observer_table();
        
        bsp_display_unlock();
    }
    
    ESP_LOGI(TAG, "Observer poll task finished");
    observer_task_handle = NULL;
    vTaskDelete(NULL);
}

// Timer callback - triggers poll task
static void observer_timer_callback(TimerHandle_t xTimer)
{
    (void)xTimer;
    
    if (!observer_running) return;
    
    // Only start new poll if previous one finished
    if (observer_task_handle == NULL) {
        xTaskCreate(observer_poll_task, "obs_poll", 8192, NULL, 5, &observer_task_handle);
    }
}

// Observer start task - runs scan_networks first, then starts sniffer
// Parse scan network line: "1","SSID","","BSSID","channel","security","rssi","band"
// Parse scan network line: "index","SSID","","BSSID","channel","security","rssi","band"
static bool parse_scan_to_observer(const char *line, observer_network_t *net)
{
    if (line[0] != '"') return false;
    
    char temp[256];
    strncpy(temp, line, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    
    // Parse CSV with quoted fields
    char *fields[8] = {NULL};
    int field_idx = 0;
    char *p = temp;
    
    while (*p && field_idx < 8) {
        if (*p == '"') {
            p++;
            fields[field_idx] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') {
                *p = '\0';
                p++;
            }
            field_idx++;
            if (*p == ',') p++;
        } else {
            p++;
        }
    }
    
    if (field_idx < 8) return false;
    
    // fields[0] = index, fields[1] = SSID, fields[3] = BSSID, fields[4] = channel, fields[6] = RSSI, fields[7] = band
    net->scan_index = atoi(fields[0]);  // 1-based index for select_networks command
    
    strncpy(net->ssid, fields[1], sizeof(net->ssid) - 1);
    net->ssid[sizeof(net->ssid) - 1] = '\0';
    
    strncpy(net->bssid, fields[3], sizeof(net->bssid) - 1);
    net->bssid[sizeof(net->bssid) - 1] = '\0';
    
    net->channel = atoi(fields[4]);
    net->rssi = atoi(fields[6]);
    
    strncpy(net->band, fields[7], sizeof(net->band) - 1);
    net->band[sizeof(net->band) - 1] = '\0';
    
    net->client_count = 0;  // No clients initially
    memset(net->clients, 0, sizeof(net->clients));
    
    return true;
}

static void observer_start_task(void *arg)
{
    ESP_LOGI(TAG, "Observer start task - scanning networks first");
    
    // Check if PSRAM buffers are allocated
    if (!observer_rx_buffer || !observer_line_buffer || !observer_networks) {
        ESP_LOGE(TAG, "PSRAM buffers not allocated!");
        vTaskDelete(NULL);
        return;
    }
    
    // Update UI
    bsp_display_lock(0);
    if (observer_status_label) {
        lv_label_set_text(observer_status_label, "Scanning networks...");
    }
    bsp_display_unlock();
    
    // Clear previous results
    observer_network_count = 0;
    memset(observer_networks, 0, sizeof(observer_network_t) * MAX_NETWORKS);
    
    // Flush UART buffer
    uart_flush(UART_NUM);
    
    // Step 1: Run scan_networks
    uart_send_command("scan_networks");
    
    // Wait for scan to complete - use PSRAM buffers
    char *rx_buffer = observer_rx_buffer;
    char *line_buffer = observer_line_buffer;
    int line_pos = 0;
    bool scan_complete = false;
    int scanned_count = 0;
    
    TickType_t start_time = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(UART_RX_TIMEOUT);
    
    while (!scan_complete && (xTaskGetTickCount() - start_time) < timeout_ticks && observer_running) {
        int len = uart_read_bytes(UART_NUM, rx_buffer, UART_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        
        if (len > 0) {
            rx_buffer[len] = '\0';
            
            for (int i = 0; i < len; i++) {
                char c = rx_buffer[i];
                
                if (c == '\n' || c == '\r') {
                    if (line_pos > 0) {
                        line_buffer[line_pos] = '\0';
                        
                        // Log every line during scan for debugging
                        ESP_LOGI(TAG, "SCAN LINE: '%s'", line_buffer);
                        
                        if (strstr(line_buffer, "Scan results printed") != NULL) {
                            scan_complete = true;
                            ESP_LOGI(TAG, "Network scan complete marker found");
                            break;
                        }
                        
                        // Parse network line from scan
                        if (line_buffer[0] == '"' && scanned_count < MAX_NETWORKS) {
                            observer_network_t net = {0};
                            if (parse_scan_to_observer(line_buffer, &net)) {
                                observer_networks[scanned_count] = net;
                                scanned_count++;
                                ESP_LOGI(TAG, "  -> Parsed scan network #%d: '%s' BSSID=%s CH%d %s %ddBm", 
                                         net.scan_index, net.ssid, net.bssid, net.channel, net.band, net.rssi);
                            }
                        }
                        
                        line_pos = 0;
                    }
                } else if (line_pos < OBSERVER_LINE_BUFFER_SIZE - 1) {
                    line_buffer[line_pos++] = c;
                }
            }
        }
    }
    
    // Save count of scanned networks
    observer_network_count = scanned_count;
    ESP_LOGI(TAG, "Scan complete: %d networks added to observer list", observer_network_count);
    
    // Update UI immediately with scanned networks (all with 0 clients)
    bsp_display_lock(0);
    if (observer_status_label) {
        lv_label_set_text_fmt(observer_status_label, "Found %d networks, starting sniffer...", observer_network_count);
    }
    update_observer_table();
    bsp_display_unlock();
    
    if (!observer_running) {
        ESP_LOGI(TAG, "Observer stopped during scan");
        vTaskDelete(NULL);
        return;
    }
    
    // Step 2: Start sniffer
    ESP_LOGI(TAG, "Starting sniffer...");
    bsp_display_lock(0);
    if (observer_status_label) {
        lv_label_set_text_fmt(observer_status_label, "%d networks, waiting for clients...", observer_network_count);
    }
    bsp_display_unlock();
    
    vTaskDelay(pdMS_TO_TICKS(500));  // Short delay
    uart_flush(UART_NUM);
    uart_send_command("start_sniffer_noscan");
    
    vTaskDelay(pdMS_TO_TICKS(1000));  // Wait for sniffer to start
    
    // Step 3: Start periodic timer for polling sniffer results
    if (observer_running) {
        ESP_LOGI(TAG, "Starting observer timer (every %d ms)", OBSERVER_POLL_INTERVAL_MS);
        
        bsp_display_lock(0);
        if (observer_status_label) {
            lv_label_set_text(observer_status_label, "Observing... (updates every 20s)");
        }
        bsp_display_unlock();
        
        // Create and start timer
        if (observer_timer == NULL) {
            observer_timer = xTimerCreate("obs_timer", 
                                          pdMS_TO_TICKS(OBSERVER_POLL_INTERVAL_MS),
                                          pdTRUE,  // Auto-reload
                                          NULL,
                                          observer_timer_callback);
        }
        
        if (observer_timer != NULL) {
            xTimerStart(observer_timer, 0);
            
            // Do first poll immediately
            xTaskCreate(observer_poll_task, "obs_poll", 8192, NULL, 5, &observer_task_handle);
        }
    }
    
    ESP_LOGI(TAG, "Observer start task finished");
    vTaskDelete(NULL);
}

// Start button click handler
static void observer_start_btn_cb(lv_event_t *e)
{
    (void)e;
    
    if (observer_running) {
        ESP_LOGW(TAG, "Observer already running");
        return;
    }
    
    ESP_LOGI(TAG, "Starting Network Observer");
    observer_running = true;
    
    // Disable start button, enable stop button
    lv_obj_add_state(observer_start_btn, LV_STATE_DISABLED);
    lv_obj_clear_state(observer_stop_btn, LV_STATE_DISABLED);
    
    // Clear table
    if (observer_table) {
        lv_obj_clean(observer_table);
    }
    
    // Start observer task
    xTaskCreate(observer_start_task, "obs_start", 8192, NULL, 5, NULL);
}

// Stop button click handler
static void observer_stop_btn_cb(lv_event_t *e)
{
    (void)e;
    
    if (!observer_running) {
        ESP_LOGW(TAG, "Observer not running");
        return;
    }
    
    ESP_LOGI(TAG, "Stopping Network Observer");
    observer_running = false;
    
    // Stop timer
    if (observer_timer != NULL) {
        xTimerStop(observer_timer, 0);
    }
    
    // Send stop command
    uart_send_command("stop");
    
    // Update UI
    lv_obj_clear_state(observer_start_btn, LV_STATE_DISABLED);
    lv_obj_add_state(observer_stop_btn, LV_STATE_DISABLED);
    
    if (observer_status_label) {
        lv_label_set_text(observer_status_label, "Stopped");
    }
}

// Observer page back button handler
static void observer_back_btn_event_cb(lv_event_t *e)
{
    (void)e;
    ESP_LOGI(TAG, "Observer back button clicked");
    
    // Stop observer if running
    if (observer_running) {
        observer_running = false;
        if (observer_timer != NULL) {
            xTimerStop(observer_timer, 0);
        }
        uart_send_command("stop");
    }
    
    show_main_tiles();
}

// Show Network Observer page
static void show_observer_page(void)
{
    // Delete tiles container if present
    if (tiles_container) {
        lv_obj_del(tiles_container);
        tiles_container = NULL;
    }
    
    // Delete status bar if present
    if (status_bar) {
        lv_obj_del(status_bar);
        status_bar = NULL;
        battery_voltage_label = NULL;
        charging_status_label = NULL;
    }
    
    // Stop battery update timer when leaving main tiles
    if (battery_update_timer) {
        lv_timer_del(battery_update_timer);
        battery_update_timer = NULL;
    }
    
    // Delete scan page if present
    if (scan_page) {
        lv_obj_del(scan_page);
        scan_page = NULL;
        scan_btn = NULL;
        status_label = NULL;
        network_list = NULL;
        spinner = NULL;
    }
    
    // Delete existing observer page if present
    if (observer_page) {
        lv_obj_del(observer_page);
        observer_page = NULL;
    }
    
    lv_obj_t *scr = lv_scr_act();
    
    // Set dark background
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x0A1A1A), 0);  // Dark teal-tinted
    
    // Create observer page container
    observer_page = lv_obj_create(scr);
    lv_obj_set_size(observer_page, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(observer_page, lv_color_hex(0x0A1A1A), 0);
    lv_obj_set_style_border_width(observer_page, 0, 0);
    lv_obj_set_style_pad_all(observer_page, 16, 0);
    lv_obj_set_flex_flow(observer_page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(observer_page, 10, 0);
    
    // Header container - fixed height, row layout
    lv_obj_t *header = lv_obj_create(observer_page);
    lv_obj_set_size(header, lv_pct(100), 50);
    lv_obj_set_style_bg_opa(header, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_pad_all(header, 0, 0);
    lv_obj_clear_flag(header, LV_OBJ_FLAG_SCROLLABLE);
    
    // Back button - positioned left
    lv_obj_t *back_btn = lv_btn_create(header);
    lv_obj_set_size(back_btn, 48, 40);
    lv_obj_align(back_btn, LV_ALIGN_LEFT_MID, 0, 0);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x1A3333), 0);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x2A4444), LV_STATE_PRESSED);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_add_event_cb(back_btn, observer_back_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(back_icon, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(back_icon);
    
    // Title - positioned after back button
    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "Network Observer");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(title, COLOR_MATERIAL_TEAL, 0);
    lv_obj_align_to(title, back_btn, LV_ALIGN_OUT_RIGHT_MID, 12, 0);
    
    // Stop button (red) - positioned right
    observer_stop_btn = lv_btn_create(header);
    lv_obj_set_size(observer_stop_btn, 100, 40);
    lv_obj_align(observer_stop_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(observer_stop_btn, COLOR_MATERIAL_RED, 0);
    lv_obj_set_style_bg_color(observer_stop_btn, lv_color_lighten(COLOR_MATERIAL_RED, 30), LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(observer_stop_btn, lv_color_hex(0x444444), LV_STATE_DISABLED);
    lv_obj_set_style_radius(observer_stop_btn, 8, 0);
    lv_obj_add_event_cb(observer_stop_btn, observer_stop_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_state(observer_stop_btn, LV_STATE_DISABLED);  // Initially disabled
    
    lv_obj_t *stop_label = lv_label_create(observer_stop_btn);
    lv_label_set_text(stop_label, "Stop");
    lv_obj_set_style_text_font(stop_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(stop_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(stop_label);
    
    // Start button (green) - positioned left of stop button
    observer_start_btn = lv_btn_create(header);
    lv_obj_set_size(observer_start_btn, 100, 40);
    lv_obj_align_to(observer_start_btn, observer_stop_btn, LV_ALIGN_OUT_LEFT_MID, -12, 0);
    lv_obj_set_style_bg_color(observer_start_btn, COLOR_MATERIAL_GREEN, 0);
    lv_obj_set_style_bg_color(observer_start_btn, lv_color_lighten(COLOR_MATERIAL_GREEN, 30), LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(observer_start_btn, lv_color_hex(0x444444), LV_STATE_DISABLED);
    lv_obj_set_style_radius(observer_start_btn, 8, 0);
    lv_obj_add_event_cb(observer_start_btn, observer_start_btn_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *start_label = lv_label_create(observer_start_btn);
    lv_label_set_text(start_label, "Start");
    lv_obj_set_style_text_font(start_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(start_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(start_label);
    
    // Status label
    observer_status_label = lv_label_create(observer_page);
    lv_label_set_text(observer_status_label, "Press Start to begin observing");
    lv_obj_set_style_text_font(observer_status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(observer_status_label, lv_color_hex(0x888888), 0);
    
    // Network table container (scrollable)
    observer_table = lv_obj_create(observer_page);
    lv_obj_set_size(observer_table, lv_pct(100), lv_pct(100));
    lv_obj_set_flex_grow(observer_table, 1);
    lv_obj_set_style_bg_color(observer_table, lv_color_hex(0x0A1A1A), 0);
    lv_obj_set_style_border_color(observer_table, lv_color_hex(0x1A3333), 0);
    lv_obj_set_style_border_width(observer_table, 1, 0);
    lv_obj_set_style_radius(observer_table, 12, 0);
    lv_obj_set_style_pad_all(observer_table, 8, 0);
    lv_obj_set_flex_flow(observer_table, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(observer_table, 6, 0);
    lv_obj_set_scroll_dir(observer_table, LV_DIR_VER);
    
    // If we have existing data, show it
    if (observer_network_count > 0) {
        lv_label_set_text_fmt(observer_status_label, "%d networks (cached)", observer_network_count);
        update_observer_table();
    }
    
    // Update button states based on observer_running
    if (observer_running) {
        lv_obj_add_state(observer_start_btn, LV_STATE_DISABLED);
        lv_obj_clear_state(observer_stop_btn, LV_STATE_DISABLED);
        lv_label_set_text_fmt(observer_status_label, "%d networks (monitoring...)", observer_network_count);
    }
}

// ======================= ESP Modem Page =======================

// Helper: Convert auth mode to string
static const char* esp_modem_auth_mode_str(wifi_auth_mode_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3";
        case WIFI_AUTH_WAPI_PSK:        return "WAPI";
        default:                        return "UNKNOWN";
    }
}

// Initialize WiFi via ESP-Hosted (lazy initialization)
static esp_err_t esp_modem_wifi_init(void)
{
    if (esp_modem_wifi_initialized) {
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Initializing WiFi for ESP Modem via ESP-Hosted...");
    
    // Enable WiFi power on Tab5 (controls ESP32C6 power via IO expander)
    ESP_LOGI(TAG, "Enabling WiFi power...");
    bsp_set_wifi_power_enable(true);
    vTaskDelay(pdMS_TO_TICKS(500));  // Wait for ESP32C6 to power up
    
    // Initialize TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());
    
    // Create default event loop
    esp_err_t ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to create event loop: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Initialize ESP-Hosted (connects to ESP32C6 via SDIO)
    ret = esp_hosted_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize ESP-Hosted: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Wait for transport to be ready
    ESP_LOGI(TAG, "Waiting for ESP-Hosted transport...");
    vTaskDelay(pdMS_TO_TICKS(2000));  // Give time for SDIO connection
    
    // Create default WiFi station
    esp_netif_create_default_wifi_sta();
    
    // Initialize WiFi (via esp_hosted remote)
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init WiFi remote: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Set WiFi mode to station
    ret = esp_wifi_set_mode(WIFI_MODE_STA);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set WiFi mode: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Start WiFi
    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start WiFi: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Wait for WiFi station to be fully ready before scanning
    ESP_LOGI(TAG, "Waiting for WiFi station to be ready...");
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    esp_modem_wifi_initialized = true;
    ESP_LOGI(TAG, "WiFi initialized successfully via ESP-Hosted");
    
    return ESP_OK;
}

// Update ESP Modem network list UI
static void esp_modem_update_network_list(void)
{
    if (!esp_modem_network_list) return;
    
    lv_obj_clean(esp_modem_network_list);
    
    for (int i = 0; i < esp_modem_network_count; i++) {
        wifi_ap_record_t *ap = &esp_modem_networks[i];
        
        // Create list item
        lv_obj_t *item = lv_obj_create(esp_modem_network_list);
        lv_obj_set_size(item, lv_pct(100), LV_SIZE_CONTENT);
        lv_obj_set_style_pad_all(item, 8, 0);
        lv_obj_set_style_bg_color(item, lv_color_hex(0x2D2D2D), 0);
        lv_obj_set_style_border_width(item, 0, 0);
        lv_obj_set_style_radius(item, 8, 0);
        lv_obj_set_flex_flow(item, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_row(item, 4, 0);
        
        // SSID (or "Hidden" if empty)
        lv_obj_t *ssid_label = lv_label_create(item);
        if (strlen((char*)ap->ssid) > 0) {
            lv_label_set_text(ssid_label, (char*)ap->ssid);
        } else {
            lv_label_set_text(ssid_label, "(Hidden)");
        }
        lv_obj_set_style_text_font(ssid_label, &lv_font_montserrat_18, 0);
        lv_obj_set_style_text_color(ssid_label, lv_color_hex(0xFFFFFF), 0);
        
        // BSSID, Channel, RSSI, Auth
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        
        lv_obj_t *info_label = lv_label_create(item);
        lv_label_set_text_fmt(info_label, "%s  |  CH%d  |  %d dBm  |  %s", 
                              bssid_str, ap->primary, ap->rssi, 
                              esp_modem_auth_mode_str(ap->authmode));
        lv_obj_set_style_text_font(info_label, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(info_label, lv_color_hex(0x888888), 0);
    }
}

// ESP Modem scan task
static void esp_modem_scan_task(void *arg)
{
    ESP_LOGI(TAG, "Starting ESP Modem WiFi scan task");
    
    // Initialize WiFi if not already done
    esp_err_t ret = esp_modem_wifi_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WiFi");
        
        bsp_display_lock(0);
        if (esp_modem_status_label) {
            lv_label_set_text(esp_modem_status_label, "WiFi init failed!");
        }
        if (esp_modem_spinner) {
            lv_obj_add_flag(esp_modem_spinner, LV_OBJ_FLAG_HIDDEN);
        }
        if (esp_modem_scan_btn) {
            lv_obj_clear_state(esp_modem_scan_btn, LV_STATE_DISABLED);
        }
        esp_modem_scan_in_progress = false;
        bsp_display_unlock();
        
        vTaskDelete(NULL);
        return;
    }
    
    // Clear previous results
    esp_modem_network_count = 0;
    memset(esp_modem_networks, 0, sizeof(wifi_ap_record_t) * ESP_MODEM_MAX_NETWORKS);
    
    // Start scan (blocking) via ESP-Hosted - use NULL for default config
    // Retry up to 3 times if WiFi state is not ready (common after first init)
    ESP_LOGI(TAG, "Starting WiFi scan via ESP-Hosted (default config)...");
    int max_retries = 3;
    for (int attempt = 0; attempt < max_retries; attempt++) {
        ret = esp_wifi_scan_start(NULL, true);
        if (ret == ESP_OK) {
            break;  // Scan started successfully
        }
        
        if (ret == ESP_ERR_WIFI_STATE && attempt < max_retries - 1) {
            ESP_LOGW(TAG, "WiFi not ready for scan (attempt %d/%d), waiting...", attempt + 1, max_retries);
            vTaskDelay(pdMS_TO_TICKS(1500));  // Wait 1.5s before retry
        } else {
            break;  // Other error or last attempt
        }
    }
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WiFi scan failed after %d attempts: %s", max_retries, esp_err_to_name(ret));
        
        bsp_display_lock(0);
        if (esp_modem_status_label) {
            lv_label_set_text_fmt(esp_modem_status_label, "Scan failed: %s", esp_err_to_name(ret));
        }
        if (esp_modem_spinner) {
            lv_obj_add_flag(esp_modem_spinner, LV_OBJ_FLAG_HIDDEN);
        }
        if (esp_modem_scan_btn) {
            lv_obj_clear_state(esp_modem_scan_btn, LV_STATE_DISABLED);
        }
        esp_modem_scan_in_progress = false;
        bsp_display_unlock();
        
        vTaskDelete(NULL);
        return;
    }
    
    // Get scan results via ESP-Hosted
    uint16_t ap_count = 0;
    ret = esp_wifi_scan_get_ap_num(&ap_count);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get AP count: %s", esp_err_to_name(ret));
        ap_count = 0;
    }
    ESP_LOGI(TAG, "Scan complete. AP count from esp_wifi_scan_get_ap_num: %d", ap_count);
    
    // Only get records if we found some networks
    if (ap_count > 0) {
        // Limit to max networks
        if (ap_count > ESP_MODEM_MAX_NETWORKS) {
            ap_count = ESP_MODEM_MAX_NETWORKS;
        }
        
        // Get AP records via ESP-Hosted
        esp_modem_network_count = ap_count;
        ret = esp_wifi_scan_get_ap_records(&esp_modem_network_count, esp_modem_networks);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to get AP records: %s", esp_err_to_name(ret));
            esp_modem_network_count = 0;
        }
    } else {
        ESP_LOGW(TAG, "Scan returned 0 networks - this might indicate antenna/firmware issue");
        esp_modem_network_count = 0;
    }
    
    ESP_LOGI(TAG, "Retrieved %d network records", esp_modem_network_count);
    
    // Update UI
    bsp_display_lock(0);
    
    if (esp_modem_spinner) {
        lv_obj_add_flag(esp_modem_spinner, LV_OBJ_FLAG_HIDDEN);
    }
    
    if (esp_modem_status_label) {
        lv_label_set_text_fmt(esp_modem_status_label, "Found %d networks", esp_modem_network_count);
    }
    
    // Update network list
    esp_modem_update_network_list();
    
    if (esp_modem_scan_btn) {
        lv_obj_clear_state(esp_modem_scan_btn, LV_STATE_DISABLED);
    }
    
    esp_modem_scan_in_progress = false;
    
    bsp_display_unlock();
    
    ESP_LOGI(TAG, "ESP Modem scan task finished");
    vTaskDelete(NULL);
}

// ESP Modem scan button click handler
static void esp_modem_scan_btn_click_cb(lv_event_t *e)
{
    (void)e;
    
    if (esp_modem_scan_in_progress) {
        ESP_LOGW(TAG, "ESP Modem scan already in progress");
        return;
    }
    
    esp_modem_scan_in_progress = true;
    
    // Disable button during scan
    lv_obj_add_state(esp_modem_scan_btn, LV_STATE_DISABLED);
    
    // Show spinner
    if (esp_modem_spinner) {
        lv_obj_clear_flag(esp_modem_spinner, LV_OBJ_FLAG_HIDDEN);
    }
    
    // Update status
    if (esp_modem_status_label) {
        lv_label_set_text(esp_modem_status_label, "Scanning...");
    }
    
    // Clear previous results
    if (esp_modem_network_list) {
        lv_obj_clean(esp_modem_network_list);
    }
    
    // Start scan task
    xTaskCreate(esp_modem_scan_task, "esp_modem_scan", 8192, NULL, 5, NULL);
}

// ESP Modem back button handler
static void esp_modem_back_btn_event_cb(lv_event_t *e)
{
    (void)e;
    ESP_LOGI(TAG, "ESP Modem back button clicked");
    show_main_tiles();
}

// Show ESP Modem page
static void show_esp_modem_page(void)
{
    // Delete tiles container if present
    if (tiles_container) {
        lv_obj_del(tiles_container);
        tiles_container = NULL;
    }
    
    // Delete status bar if present
    if (status_bar) {
        lv_obj_del(status_bar);
        status_bar = NULL;
        battery_voltage_label = NULL;
        charging_status_label = NULL;
    }
    
    // Stop battery update timer when leaving main tiles
    if (battery_update_timer) {
        lv_timer_del(battery_update_timer);
        battery_update_timer = NULL;
    }
    
    // Delete scan page if present
    if (scan_page) {
        lv_obj_del(scan_page);
        scan_page = NULL;
        scan_btn = NULL;
        status_label = NULL;
        network_list = NULL;
        spinner = NULL;
    }
    
    // Delete observer page if present
    if (observer_page) {
        lv_obj_del(observer_page);
        observer_page = NULL;
        observer_start_btn = NULL;
        observer_stop_btn = NULL;
        observer_table = NULL;
        observer_status_label = NULL;
    }
    
    // Delete existing ESP Modem page if present
    if (esp_modem_page) {
        lv_obj_del(esp_modem_page);
        esp_modem_page = NULL;
    }
    
    lv_obj_t *scr = lv_scr_act();
    
    // Set dark background with orange tint
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1410), 0);
    
    // Create ESP Modem page container
    esp_modem_page = lv_obj_create(scr);
    lv_obj_set_size(esp_modem_page, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_color(esp_modem_page, lv_color_hex(0x1A1410), 0);
    lv_obj_set_style_border_width(esp_modem_page, 0, 0);
    lv_obj_set_style_pad_all(esp_modem_page, 16, 0);
    lv_obj_set_flex_flow(esp_modem_page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(esp_modem_page, 12, 0);
    
    // Header container
    lv_obj_t *header = lv_obj_create(esp_modem_page);
    lv_obj_set_size(header, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(header, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_pad_all(header, 0, 0);
    lv_obj_set_flex_flow(header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(header, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    
    // Left side: Back button + Title
    lv_obj_t *left_cont = lv_obj_create(header);
    lv_obj_set_size(left_cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(left_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(left_cont, 0, 0);
    lv_obj_set_style_pad_all(left_cont, 0, 0);
    lv_obj_set_flex_flow(left_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(left_cont, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(left_cont, 12, 0);
    
    // Back button
    lv_obj_t *back_btn = lv_btn_create(left_cont);
    lv_obj_set_size(back_btn, 48, 40);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x333333), 0);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x444444), LV_STATE_PRESSED);
    lv_obj_set_style_radius(back_btn, 8, 0);
    lv_obj_add_event_cb(back_btn, esp_modem_back_btn_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *back_icon = lv_label_create(back_btn);
    lv_label_set_text(back_icon, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(back_icon, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(back_icon);
    
    // Title
    lv_obj_t *title = lv_label_create(left_cont);
    lv_label_set_text(title, "Internal C6 WiFi");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(title, lv_color_make(255, 87, 34), 0);  // Deep Orange
    
    // Scan button container (for button + spinner)
    lv_obj_t *btn_cont = lv_obj_create(header);
    lv_obj_set_size(btn_cont, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(btn_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(btn_cont, 0, 0);
    lv_obj_set_style_pad_all(btn_cont, 0, 0);
    lv_obj_set_flex_flow(btn_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(btn_cont, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(btn_cont, 12, 0);
    
    // Spinner (hidden by default)
    esp_modem_spinner = lv_spinner_create(btn_cont);
    lv_obj_set_size(esp_modem_spinner, 32, 32);
    lv_spinner_set_anim_params(esp_modem_spinner, 1000, 200);
    lv_obj_add_flag(esp_modem_spinner, LV_OBJ_FLAG_HIDDEN);
    
    // Scan button
    esp_modem_scan_btn = lv_btn_create(btn_cont);
    lv_obj_set_size(esp_modem_scan_btn, 120, 40);
    lv_obj_set_style_bg_color(esp_modem_scan_btn, lv_color_make(255, 87, 34), 0);  // Deep Orange
    lv_obj_set_style_bg_color(esp_modem_scan_btn, lv_color_lighten(lv_color_make(255, 87, 34), 30), LV_STATE_PRESSED);
    lv_obj_set_style_bg_color(esp_modem_scan_btn, lv_color_hex(0x444444), LV_STATE_DISABLED);
    lv_obj_set_style_radius(esp_modem_scan_btn, 8, 0);
    lv_obj_add_event_cb(esp_modem_scan_btn, esp_modem_scan_btn_click_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t *btn_label = lv_label_create(esp_modem_scan_btn);
    lv_label_set_text(btn_label, "SCAN");
    lv_obj_set_style_text_font(btn_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(btn_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(btn_label);
    
    // Status label
    esp_modem_status_label = lv_label_create(esp_modem_page);
    lv_label_set_text(esp_modem_status_label, "Press SCAN to search for networks (via ESP32C6)");
    lv_obj_set_style_text_font(esp_modem_status_label, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(esp_modem_status_label, lv_color_hex(0x888888), 0);
    
    // Network list container (scrollable)
    esp_modem_network_list = lv_obj_create(esp_modem_page);
    lv_obj_set_size(esp_modem_network_list, lv_pct(100), lv_pct(100));
    lv_obj_set_flex_grow(esp_modem_network_list, 1);
    lv_obj_set_style_bg_color(esp_modem_network_list, lv_color_hex(0x1A1410), 0);
    lv_obj_set_style_border_color(esp_modem_network_list, lv_color_hex(0x332820), 0);
    lv_obj_set_style_border_width(esp_modem_network_list, 1, 0);
    lv_obj_set_style_radius(esp_modem_network_list, 12, 0);
    lv_obj_set_style_pad_all(esp_modem_network_list, 8, 0);
    lv_obj_set_flex_flow(esp_modem_network_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(esp_modem_network_list, 8, 0);
    lv_obj_set_scroll_dir(esp_modem_network_list, LV_DIR_VER);
    
    // If we have existing scan results, show them
    if (esp_modem_network_count > 0) {
        lv_label_set_text_fmt(esp_modem_status_label, "Found %d networks (cached)", esp_modem_network_count);
        esp_modem_update_network_list();
    }
    
    // Auto-start scan when entering the page
    lv_obj_send_event(esp_modem_scan_btn, LV_EVENT_CLICKED, NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "M5Stack Tab5 WiFi Scanner");
    
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Allocate large buffers in PSRAM for Network Observer
    ESP_LOGI(TAG, "Allocating observer buffers in PSRAM...");
    observer_networks = heap_caps_calloc(MAX_NETWORKS, sizeof(observer_network_t), MALLOC_CAP_SPIRAM);
    observer_rx_buffer = heap_caps_malloc(UART_BUF_SIZE, MALLOC_CAP_SPIRAM);
    observer_line_buffer = heap_caps_malloc(OBSERVER_LINE_BUFFER_SIZE, MALLOC_CAP_SPIRAM);
    
    if (!observer_networks || !observer_rx_buffer || !observer_line_buffer) {
        ESP_LOGE(TAG, "Failed to allocate PSRAM buffers for observer!");
    } else {
        ESP_LOGI(TAG, "Observer PSRAM buffers allocated successfully");
    }
    
    // Allocate buffer for ESP Modem WiFi scan results
    ESP_LOGI(TAG, "Allocating ESP Modem buffers in PSRAM...");
    esp_modem_networks = heap_caps_calloc(ESP_MODEM_MAX_NETWORKS, sizeof(wifi_ap_record_t), MALLOC_CAP_SPIRAM);
    if (!esp_modem_networks) {
        ESP_LOGE(TAG, "Failed to allocate PSRAM buffer for ESP Modem!");
    } else {
        ESP_LOGI(TAG, "ESP Modem PSRAM buffer allocated successfully");
    }
    
    // Initialize I2C (required for IO expander)
    ESP_ERROR_CHECK(bsp_i2c_init());
    
    // Initialize IO expander
    bsp_io_expander_pi4ioe_init(bsp_i2c_get_handle());
    
    // Enable battery charging
    ESP_LOGI(TAG, "Enabling battery charging...");
    bsp_set_charge_en(true);
    bsp_set_charge_qc_en(true);
    
    // Initialize UART for ESP32C5 communication
    uart_init();
    
    // Initialize display
    lv_display_t *disp = bsp_display_start();
    if (disp == NULL) {
        ESP_LOGE(TAG, "Failed to initialize display");
        return;
    }
    
    // Set display brightness
    bsp_display_brightness_set(80);
    
    // Create UI - show main tiles
    bsp_display_lock(0);
    show_main_tiles();
    bsp_display_unlock();
    
    ESP_LOGI(TAG, "Application started. Ready to scan.");
}
