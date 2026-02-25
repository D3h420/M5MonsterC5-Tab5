#include "ui_components.h"

#include <stdio.h>

static lv_color_t badge_tint(ui_badge_type_t type)
{
    switch (type) {
        case UI_BADGE_SUCCESS:
            return ui_theme_color(UI_COLOR_SUCCESS);
        case UI_BADGE_WARNING:
            return ui_theme_color(UI_COLOR_WARNING);
        case UI_BADGE_ERROR:
            return ui_theme_color(UI_COLOR_ERROR);
        case UI_BADGE_INFO:
        default:
            return ui_theme_color(UI_COLOR_INFO);
    }
}

static lv_obj_t *create_text_button(
    lv_obj_t *parent,
    const char *text,
    lv_event_cb_t cb,
    void *user_data,
    void (*apply_style)(lv_obj_t *))
{
    lv_obj_t *btn = lv_btn_create(parent);
    lv_obj_set_size(btn, LV_SIZE_CONTENT, UI_TOUCH_TARGET_PRIMARY);
    if (apply_style) {
        apply_style(btn);
    }

    if (cb) {
        lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user_data);
    }

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text ? text : "");
    ui_theme_style_body(label);
    lv_obj_center(label);

    return btn;
}

lv_obj_t *ui_comp_create_page(lv_obj_t *parent)
{
    lv_obj_t *page = lv_obj_create(parent);
    lv_obj_set_size(page, lv_pct(100), lv_pct(100));
    ui_theme_apply_page(page);
    lv_obj_set_flex_flow(page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(page, UI_SPACE_12, 0);
    lv_obj_clear_flag(page, LV_OBJ_FLAG_SCROLLABLE);
    return page;
}

lv_obj_t *ui_comp_create_app_bar(
    lv_obj_t *parent,
    const char *title,
    lv_event_cb_t back_cb,
    void *back_user_data,
    lv_obj_t **actions_out)
{
    lv_obj_t *bar = lv_obj_create(parent);
    lv_obj_set_size(bar, lv_pct(100), 64);
    ui_theme_apply_appbar(bar);
    lv_obj_set_flex_flow(bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bar, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(bar, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *left = lv_obj_create(bar);
    lv_obj_remove_style_all(left);
    lv_obj_set_size(left, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(left, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(left, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(left, UI_SPACE_12, 0);
    lv_obj_clear_flag(left, LV_OBJ_FLAG_CLICKABLE);

    if (back_cb) {
        lv_obj_t *back_btn = ui_comp_create_icon_button(left, LV_SYMBOL_LEFT, back_cb, back_user_data);
        lv_obj_set_size(back_btn, UI_TOUCH_TARGET_PRIMARY, UI_TOUCH_TARGET_PRIMARY);
    }

    lv_obj_t *title_label = lv_label_create(left);
    lv_label_set_text(title_label, title ? title : "");
    ui_theme_style_title(title_label);

    lv_obj_t *actions = lv_obj_create(bar);
    lv_obj_remove_style_all(actions);
    lv_obj_set_size(actions, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(actions, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(actions, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(actions, UI_SPACE_8, 0);
    lv_obj_clear_flag(actions, LV_OBJ_FLAG_CLICKABLE);

    if (actions_out) {
        *actions_out = actions;
    }

    return bar;
}

lv_obj_t *ui_comp_create_card(lv_obj_t *parent)
{
    lv_obj_t *card = lv_obj_create(parent);
    ui_theme_apply_card(card);
    lv_obj_set_width(card, lv_pct(100));
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(card, UI_SPACE_8, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    return card;
}

lv_obj_t *ui_comp_create_section(lv_obj_t *parent, const char *title, const char *subtitle)
{
    lv_obj_t *section = lv_obj_create(parent);
    ui_theme_apply_section(section);
    lv_obj_set_width(section, lv_pct(100));
    lv_obj_set_flex_flow(section, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(section, UI_SPACE_8, 0);
    lv_obj_clear_flag(section, LV_OBJ_FLAG_SCROLLABLE);

    if (title) {
        lv_obj_t *title_label = lv_label_create(section);
        lv_label_set_text(title_label, title);
        ui_theme_style_subtitle(title_label);
    }

    if (subtitle) {
        lv_obj_t *subtitle_label = lv_label_create(section);
        lv_label_set_text(subtitle_label, subtitle);
        ui_theme_style_muted(subtitle_label);
    }

    return section;
}

lv_obj_t *ui_comp_create_primary_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user_data)
{
    return create_text_button(parent, text, cb, user_data, ui_theme_apply_primary_btn);
}

lv_obj_t *ui_comp_create_secondary_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user_data)
{
    return create_text_button(parent, text, cb, user_data, ui_theme_apply_secondary_btn);
}

lv_obj_t *ui_comp_create_danger_button(lv_obj_t *parent, const char *text, lv_event_cb_t cb, void *user_data)
{
    return create_text_button(parent, text, cb, user_data, ui_theme_apply_danger_btn);
}

lv_obj_t *ui_comp_create_icon_button(lv_obj_t *parent, const char *symbol, lv_event_cb_t cb, void *user_data)
{
    lv_obj_t *btn = lv_btn_create(parent);
    lv_obj_set_size(btn, UI_TOUCH_TARGET_PRIMARY, UI_TOUCH_TARGET_PRIMARY);
    ui_theme_apply_icon_btn(btn);

    if (cb) {
        lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user_data);
    }

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, symbol ? symbol : "");
    lv_obj_set_style_text_font(label, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(label, ui_theme_color(UI_COLOR_TEXT_PRIMARY), 0);
    lv_obj_center(label);

    return btn;
}

lv_obj_t *ui_comp_create_status_badge(lv_obj_t *parent, const char *text, ui_badge_type_t type)
{
    lv_obj_t *badge = lv_obj_create(parent);
    lv_obj_set_size(badge, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    ui_theme_apply_chip(badge, badge_tint(type));
    lv_obj_clear_flag(badge, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *label = lv_label_create(badge);
    lv_label_set_text(label, text ? text : "");
    ui_theme_style_label(label);
    lv_obj_set_style_text_color(label, ui_theme_color(UI_COLOR_TEXT_PRIMARY), 0);
    lv_obj_center(label);

    return badge;
}

lv_obj_t *ui_comp_create_metric_card(
    lv_obj_t *parent,
    const char *value,
    const char *label,
    const char *symbol,
    lv_color_t accent,
    lv_event_cb_t cb,
    void *user_data)
{
    lv_obj_t *card = lv_btn_create(parent);
    lv_obj_set_size(card, 230, 146);
    ui_theme_apply_metric_card(card, accent);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(card, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    if (cb) {
        lv_obj_add_event_cb(card, cb, LV_EVENT_CLICKED, user_data);
    }

    lv_obj_t *top = lv_obj_create(card);
    lv_obj_remove_style_all(top);
    lv_obj_set_size(top, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(top, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(top, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(top, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *icon = lv_label_create(top);
    lv_label_set_text(icon, symbol ? symbol : "");
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_30, 0);
    lv_obj_set_style_text_color(icon, accent, 0);

    ui_comp_create_status_badge(top, "LIVE", UI_BADGE_INFO);

    lv_obj_t *value_label = lv_label_create(card);
    lv_label_set_text(value_label, value ? value : "");
    lv_obj_set_style_text_font(value_label, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(value_label, ui_theme_color(UI_COLOR_TEXT_PRIMARY), 0);

    lv_obj_t *caption = lv_label_create(card);
    lv_label_set_text(caption, label ? label : "");
    ui_theme_style_label(caption);

    return card;
}

lv_obj_t *ui_comp_create_list_row(
    lv_obj_t *parent,
    const char *title,
    const char *subtitle,
    const char *symbol,
    lv_event_cb_t cb,
    void *user_data)
{
    lv_obj_t *row = lv_btn_create(parent);
    lv_obj_set_size(row, lv_pct(100), 68);
    ui_theme_apply_list_row(row);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(row, UI_SPACE_12, 0);

    if (cb) {
        lv_obj_add_event_cb(row, cb, LV_EVENT_CLICKED, user_data);
    }

    lv_obj_t *icon = lv_label_create(row);
    lv_label_set_text(icon, symbol ? symbol : "");
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_22, 0);
    lv_obj_set_style_text_color(icon, ui_theme_color(UI_COLOR_ACCENT_PRIMARY), 0);

    lv_obj_t *text_col = lv_obj_create(row);
    lv_obj_remove_style_all(text_col);
    lv_obj_set_flex_flow(text_col, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(text_col, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(text_col, 2, 0);
    lv_obj_set_flex_grow(text_col, 1);
    lv_obj_clear_flag(text_col, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *title_label = lv_label_create(text_col);
    lv_label_set_text(title_label, title ? title : "");
    ui_theme_style_body(title_label);

    if (subtitle) {
        lv_obj_t *subtitle_label = lv_label_create(text_col);
        lv_label_set_text(subtitle_label, subtitle);
        ui_theme_style_muted(subtitle_label);
    }

    return row;
}

void ui_comp_create_modal(lv_obj_t *parent, lv_coord_t width, lv_coord_t height, lv_obj_t **overlay_out, lv_obj_t **card_out)
{
    lv_obj_t *base = parent ? parent : lv_scr_act();

    lv_obj_t *overlay = lv_obj_create(base);
    lv_obj_remove_style_all(overlay);
    lv_obj_set_size(overlay, lv_pct(100), lv_pct(100));
    ui_theme_apply_modal_overlay(overlay);
    lv_obj_add_flag(overlay, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *card = lv_obj_create(overlay);
    lv_obj_set_size(card, width, height);
    lv_obj_center(card);
    ui_theme_apply_modal_card(card);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(card, UI_SPACE_12, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

    if (overlay_out) {
        *overlay_out = overlay;
    }
    if (card_out) {
        *card_out = card;
    }
}

static void toast_timer_cb(lv_timer_t *timer)
{
    if (!timer) return;

    lv_obj_t *toast = (lv_obj_t *)lv_timer_get_user_data(timer);
    if (toast) {
        lv_obj_del(toast);
    }

    lv_timer_del(timer);
}

void ui_comp_show_toast(lv_obj_t *parent, const char *message, uint32_t duration_ms)
{
    lv_obj_t *base = parent ? parent : lv_layer_top();

    lv_obj_t *toast = lv_obj_create(base);
    ui_theme_apply_card(toast);
    lv_obj_set_style_bg_color(toast, ui_theme_color(UI_COLOR_SURFACE_ALT), 0);
    lv_obj_set_style_border_color(toast, ui_theme_color(UI_COLOR_ACCENT_PRIMARY), 0);
    lv_obj_set_style_border_width(toast, UI_BORDER_THICK, 0);
    lv_obj_set_style_radius(toast, UI_RADIUS_MD, 0);
    lv_obj_set_style_pad_left(toast, UI_SPACE_16, 0);
    lv_obj_set_style_pad_right(toast, UI_SPACE_16, 0);
    lv_obj_set_style_pad_top(toast, UI_SPACE_12, 0);
    lv_obj_set_style_pad_bottom(toast, UI_SPACE_12, 0);
    lv_obj_align(toast, LV_ALIGN_BOTTOM_MID, 0, -24);
    lv_obj_clear_flag(toast, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *label = lv_label_create(toast);
    lv_label_set_text(label, message ? message : "");
    ui_theme_style_label(label);
    lv_obj_center(label);

    lv_timer_create(toast_timer_cb, duration_ms ? duration_ms : 1800, toast);
}
