#include "lvgl_memory.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "LVGL_MEMORY";

void lvgl_memory_init(void)
{
    ESP_LOGI(TAG, "LVGL custom PSRAM memory allocator initialized");
}

void lvgl_memory_deinit(void)
{
    // Nothing to clean up
}

void* lvgl_malloc(size_t size)
{
    if (size == 0) return NULL;
    
    void* ptr = NULL;
    
    // Try PSRAM first, then fallback to internal RAM
    ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr == NULL) {
        ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
        if (ptr == NULL) {
            ESP_LOGE(TAG, "Failed to allocate %zu bytes", size);
        }
    }
    
    return ptr;
}

void lvgl_free(void* ptr)
{
    if (ptr == NULL) return;
    heap_caps_free(ptr);
}

void* lvgl_realloc(void* ptr, size_t new_size)
{
    if (new_size == 0) {
        lvgl_free(ptr);
        return NULL;
    }
    
    if (ptr == NULL) {
        return lvgl_malloc(new_size);
    }
    
    // Try PSRAM first
    void* new_ptr = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (new_ptr == NULL) {
        // Fallback to any available memory
        new_ptr = heap_caps_realloc(ptr, new_size, MALLOC_CAP_8BIT);
    }
    
    return new_ptr;
}

