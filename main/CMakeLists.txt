idf_component_register(SRCS "ui_components.c" "ui_theme.c" "main.c" "splash_bg.c"
                    INCLUDE_DIRS "."
                    REQUIRES lvgl m5stack_tab5 nvs_flash esp_lvgl_port driver esp_netif esp_event esp_wifi espressif__esp_hosted esp_http_server fatfs)
