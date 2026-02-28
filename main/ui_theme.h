#ifndef UI_THEME_H
#define UI_THEME_H

#include <stdbool.h>
#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UI_COLOR_BG = 0,
    UI_COLOR_BG_LAYER,
    UI_COLOR_SURFACE,
    UI_COLOR_SURFACE_ALT,
    UI_COLOR_CARD,
    UI_COLOR_BORDER,
    UI_COLOR_TEXT_PRIMARY,
    UI_COLOR_TEXT_SECONDARY,
    UI_COLOR_TEXT_MUTED,
    UI_COLOR_ACCENT_PRIMARY,
    UI_COLOR_ACCENT_SECONDARY,
    UI_COLOR_SUCCESS,
    UI_COLOR_WARNING,
    UI_COLOR_ERROR,
    UI_COLOR_INFO,
    UI_COLOR_MODAL_OVERLAY,
    UI_COLOR_COUNT
} ui_color_token_t;

typedef enum {
    UI_SPACE_4 = 4,
    UI_SPACE_8 = 8,
    UI_SPACE_12 = 12,
    UI_SPACE_16 = 16,
    UI_SPACE_24 = 24
} ui_spacing_t;

#define UI_RADIUS_SM 12
#define UI_RADIUS_MD 18
#define UI_RADIUS_LG 24
#define UI_BORDER_THIN 1
#define UI_BORDER_THICK 2
#define UI_TOUCH_TARGET_MIN 48
#define UI_TOUCH_TARGET_PRIMARY 56

typedef struct {
    lv_style_t page;
    lv_style_t card;
    lv_style_t section;
    lv_style_t appbar;
    lv_style_t tabbar;
    lv_style_t button_primary;
    lv_style_t button_secondary;
    lv_style_t button_danger;
    lv_style_t button_pressed;
    lv_style_t button_disabled;
    lv_style_t icon_button;
    lv_style_t chip;
    lv_style_t metric_card;
    lv_style_t list_row;
    lv_style_t modal_overlay;
    lv_style_t modal_card;
} ui_theme_styles_t;

void ui_theme_init(lv_display_t *disp);
bool ui_theme_is_initialized(void);
void ui_theme_set_dark_mode(bool enabled);
bool ui_theme_is_dark_mode(void);
void ui_theme_set_custom_palette(const lv_color_t palette[UI_COLOR_COUNT]);
void ui_theme_clear_custom_palette(void);
void ui_theme_get_default_palette(lv_color_t out_palette[UI_COLOR_COUNT]);

lv_color_t ui_theme_color(ui_color_token_t token);

const lv_font_t *ui_theme_font_h1(void);
const lv_font_t *ui_theme_font_h2(void);
const lv_font_t *ui_theme_font_body(void);
const lv_font_t *ui_theme_font_label(void);

const ui_theme_styles_t *ui_theme_styles(void);

void ui_theme_apply_page(lv_obj_t *obj);
void ui_theme_apply_card(lv_obj_t *obj);
void ui_theme_apply_section(lv_obj_t *obj);
void ui_theme_apply_appbar(lv_obj_t *obj);
void ui_theme_apply_tabbar(lv_obj_t *obj);
void ui_theme_apply_primary_btn(lv_obj_t *obj);
void ui_theme_apply_secondary_btn(lv_obj_t *obj);
void ui_theme_apply_danger_btn(lv_obj_t *obj);
void ui_theme_apply_icon_btn(lv_obj_t *obj);
void ui_theme_apply_chip(lv_obj_t *obj, lv_color_t tint_color);
void ui_theme_apply_metric_card(lv_obj_t *obj, lv_color_t accent);
void ui_theme_apply_list_row(lv_obj_t *obj);
void ui_theme_apply_modal_overlay(lv_obj_t *obj);
void ui_theme_apply_modal_card(lv_obj_t *obj);

void ui_theme_style_title(lv_obj_t *label);
void ui_theme_style_subtitle(lv_obj_t *label);
void ui_theme_style_body(lv_obj_t *label);
void ui_theme_style_label(lv_obj_t *label);
void ui_theme_style_muted(lv_obj_t *label);

#ifdef __cplusplus
}
#endif

#endif
