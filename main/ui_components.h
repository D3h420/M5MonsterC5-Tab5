#ifndef UI_COMPONENTS_H
#define UI_COMPONENTS_H

#include "lvgl.h"
#include "ui_theme.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UI_BADGE_INFO = 0,
    UI_BADGE_SUCCESS,
    UI_BADGE_WARNING,
    UI_BADGE_ERROR
} ui_badge_type_t;

lv_obj_t *ui_comp_create_page(lv_obj_t *parent);
lv_obj_t *ui_comp_create_app_bar(
    lv_obj_t *parent,
    const char *title,
    lv_event_cb_t back_cb,
    void *back_user_data,
    lv_obj_t **actions_out);
lv_obj_t *ui_comp_create_card(lv_obj_t *parent);
lv_obj_t *ui_comp_create_section(lv_obj_t *parent, const char *title, const char *subtitle);
lv_obj_t *ui_comp_create_primary_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user_data);
lv_obj_t *ui_comp_create_secondary_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user_data);
lv_obj_t *ui_comp_create_danger_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user_data);
lv_obj_t *ui_comp_create_icon_button(lv_obj_t *parent, const char *symbol, lv_event_cb_t cb, void *user_data);
lv_obj_t *ui_comp_create_status_badge(lv_obj_t *parent, const char *text, ui_badge_type_t type);
lv_obj_t *ui_comp_create_metric_card(
    lv_obj_t *parent,
    const char *value,
    const char *label,
    const char *symbol,
    lv_color_t accent,
    lv_event_cb_t cb,
    void *user_data);
lv_obj_t *ui_comp_create_list_row(
    lv_obj_t *parent,
    const char *title,
    const char *subtitle,
    const char *symbol,
    lv_event_cb_t cb,
    void *user_data);
void ui_comp_create_modal(lv_obj_t *parent, lv_coord_t width, lv_coord_t height, lv_obj_t **overlay_out, lv_obj_t **card_out);
void ui_comp_show_toast(lv_obj_t *parent, const char *message, uint32_t duration_ms);

#ifdef __cplusplus
}
#endif

#endif
