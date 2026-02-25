#include "ui_theme.h"

static bool s_theme_inited = false;

static lv_color_t s_palette[UI_COLOR_COUNT] = {
    [UI_COLOR_BG] = LV_COLOR_MAKE(0x04, 0x08, 0x10),
    [UI_COLOR_BG_LAYER] = LV_COLOR_MAKE(0x0A, 0x12, 0x20),
    [UI_COLOR_SURFACE] = LV_COLOR_MAKE(0x11, 0x1D, 0x31),
    [UI_COLOR_SURFACE_ALT] = LV_COLOR_MAKE(0x18, 0x26, 0x40),
    [UI_COLOR_CARD] = LV_COLOR_MAKE(0x15, 0x24, 0x3B),
    [UI_COLOR_BORDER] = LV_COLOR_MAKE(0x2D, 0x42, 0x63),
    [UI_COLOR_TEXT_PRIMARY] = LV_COLOR_MAKE(0xF3, 0xF7, 0xFF),
    [UI_COLOR_TEXT_SECONDARY] = LV_COLOR_MAKE(0xC9, 0xD5, 0xE8),
    [UI_COLOR_TEXT_MUTED] = LV_COLOR_MAKE(0x90, 0xA2, 0xBD),
    [UI_COLOR_ACCENT_PRIMARY] = LV_COLOR_MAKE(0x4F, 0x87, 0xFF),
    [UI_COLOR_ACCENT_SECONDARY] = LV_COLOR_MAKE(0x25, 0xD7, 0xC3),
    [UI_COLOR_SUCCESS] = LV_COLOR_MAKE(0x48, 0xDA, 0x89),
    [UI_COLOR_WARNING] = LV_COLOR_MAKE(0xFF, 0xB3, 0x47),
    [UI_COLOR_ERROR] = LV_COLOR_MAKE(0xFF, 0x5E, 0x7D),
    [UI_COLOR_INFO] = LV_COLOR_MAKE(0x7B, 0xB8, 0xFF),
    [UI_COLOR_MODAL_OVERLAY] = LV_COLOR_MAKE(0x00, 0x00, 0x00),
};

static ui_theme_styles_t s_styles;

static const lv_style_prop_t s_button_transition_props[] = {
    LV_STYLE_BG_COLOR,
    LV_STYLE_BORDER_COLOR,
    LV_STYLE_SHADOW_OPA,
    LV_STYLE_TRANSLATE_Y,
    LV_STYLE_PROP_INV,
};

static lv_style_transition_dsc_t s_button_transition;

static void init_button_style(lv_style_t *style, lv_color_t bg, lv_color_t border, lv_color_t text)
{
    lv_style_init(style);
    lv_style_set_bg_opa(style, LV_OPA_COVER);
    lv_style_set_bg_color(style, bg);
    lv_style_set_bg_grad_color(style, lv_color_lighten(bg, 8));
    lv_style_set_bg_grad_dir(style, LV_GRAD_DIR_VER);
    lv_style_set_border_width(style, UI_BORDER_THIN);
    lv_style_set_border_color(style, border);
    lv_style_set_radius(style, UI_RADIUS_LG);
    lv_style_set_pad_left(style, UI_SPACE_16);
    lv_style_set_pad_right(style, UI_SPACE_16);
    lv_style_set_pad_top(style, UI_SPACE_12);
    lv_style_set_pad_bottom(style, UI_SPACE_12);
    lv_style_set_min_height(style, UI_TOUCH_TARGET_PRIMARY);
    lv_style_set_text_color(style, text);
    lv_style_set_text_font(style, &lv_font_montserrat_20);
    lv_style_set_shadow_color(style, border);
    lv_style_set_shadow_width(style, 18);
    lv_style_set_shadow_opa(style, LV_OPA_30);
    lv_style_set_transition(style, &s_button_transition);
}

void ui_theme_init(lv_display_t *disp)
{
    if (s_theme_inited) {
        return;
    }

    if (disp == NULL) {
        disp = lv_display_get_default();
    }

    if (disp != NULL) {
        lv_theme_t *theme = lv_theme_default_init(
            disp,
            s_palette[UI_COLOR_ACCENT_PRIMARY],
            s_palette[UI_COLOR_ACCENT_SECONDARY],
            true,
            &lv_font_montserrat_18);
        if (theme != NULL) {
            lv_display_set_theme(disp, theme);
        }
    }

    lv_style_transition_dsc_init(
        &s_button_transition,
        s_button_transition_props,
        lv_anim_path_ease_out,
        210,
        0,
        NULL);

    lv_style_init(&s_styles.page);
    lv_style_set_bg_opa(&s_styles.page, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.page, s_palette[UI_COLOR_BG]);
    lv_style_set_bg_grad_color(&s_styles.page, s_palette[UI_COLOR_BG_LAYER]);
    lv_style_set_bg_grad_dir(&s_styles.page, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.page, 0);
    lv_style_set_pad_all(&s_styles.page, UI_SPACE_16);
    lv_style_set_pad_row(&s_styles.page, UI_SPACE_16);

    lv_style_init(&s_styles.card);
    lv_style_set_bg_opa(&s_styles.card, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.card, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_color(&s_styles.card, lv_color_darken(s_palette[UI_COLOR_CARD], 6));
    lv_style_set_bg_grad_dir(&s_styles.card, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.card, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.card, s_palette[UI_COLOR_BORDER]);
    lv_style_set_radius(&s_styles.card, UI_RADIUS_LG);
    lv_style_set_pad_all(&s_styles.card, UI_SPACE_12);
    lv_style_set_pad_row(&s_styles.card, UI_SPACE_8);
    lv_style_set_shadow_width(&s_styles.card, 14);
    lv_style_set_shadow_color(&s_styles.card, lv_color_darken(s_palette[UI_COLOR_BG], 10));
    lv_style_set_shadow_opa(&s_styles.card, LV_OPA_20);

    lv_style_init(&s_styles.section);
    lv_style_set_bg_opa(&s_styles.section, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.section, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.section, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_bg_grad_dir(&s_styles.section, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.section, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.section, s_palette[UI_COLOR_BORDER]);
    lv_style_set_radius(&s_styles.section, 20);
    lv_style_set_pad_all(&s_styles.section, UI_SPACE_16);
    lv_style_set_pad_row(&s_styles.section, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.section, 16);
    lv_style_set_shadow_color(&s_styles.section, lv_color_darken(s_palette[UI_COLOR_BG_LAYER], 8));
    lv_style_set_shadow_opa(&s_styles.section, LV_OPA_20);

    lv_style_init(&s_styles.appbar);
    lv_style_set_bg_opa(&s_styles.appbar, LV_OPA_90);
    lv_style_set_bg_color(&s_styles.appbar, s_palette[UI_COLOR_BG_LAYER]);
    lv_style_set_bg_grad_color(&s_styles.appbar, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_dir(&s_styles.appbar, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.appbar, UI_BORDER_THIN);
    lv_style_set_border_side(&s_styles.appbar, LV_BORDER_SIDE_BOTTOM);
    lv_style_set_border_color(&s_styles.appbar, s_palette[UI_COLOR_BORDER]);
    lv_style_set_pad_left(&s_styles.appbar, UI_SPACE_16);
    lv_style_set_pad_right(&s_styles.appbar, UI_SPACE_16);
    lv_style_set_pad_top(&s_styles.appbar, UI_SPACE_8);
    lv_style_set_pad_bottom(&s_styles.appbar, UI_SPACE_8);

    lv_style_init(&s_styles.tabbar);
    lv_style_set_bg_opa(&s_styles.tabbar, LV_OPA_90);
    lv_style_set_bg_color(&s_styles.tabbar, s_palette[UI_COLOR_BG_LAYER]);
    lv_style_set_bg_grad_color(&s_styles.tabbar, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_dir(&s_styles.tabbar, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.tabbar, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.tabbar, s_palette[UI_COLOR_BORDER]);
    lv_style_set_radius(&s_styles.tabbar, 16);
    lv_style_set_pad_left(&s_styles.tabbar, UI_SPACE_8);
    lv_style_set_pad_right(&s_styles.tabbar, UI_SPACE_8);
    lv_style_set_pad_top(&s_styles.tabbar, UI_SPACE_4);
    lv_style_set_pad_bottom(&s_styles.tabbar, UI_SPACE_4);

    init_button_style(
        &s_styles.button_primary,
        s_palette[UI_COLOR_ACCENT_PRIMARY],
        lv_color_lighten(s_palette[UI_COLOR_ACCENT_PRIMARY], 10),
        s_palette[UI_COLOR_TEXT_PRIMARY]);

    init_button_style(
        &s_styles.button_secondary,
        s_palette[UI_COLOR_SURFACE],
        s_palette[UI_COLOR_ACCENT_PRIMARY],
        s_palette[UI_COLOR_TEXT_PRIMARY]);

    init_button_style(
        &s_styles.button_danger,
        s_palette[UI_COLOR_ERROR],
        lv_color_lighten(s_palette[UI_COLOR_ERROR], 10),
        s_palette[UI_COLOR_TEXT_PRIMARY]);

    lv_style_init(&s_styles.button_pressed);
    lv_style_set_translate_y(&s_styles.button_pressed, 1);
    lv_style_set_shadow_opa(&s_styles.button_pressed, LV_OPA_50);
    lv_style_set_bg_opa(&s_styles.button_pressed, LV_OPA_90);

    lv_style_init(&s_styles.button_disabled);
    lv_style_set_bg_color(&s_styles.button_disabled, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_border_color(&s_styles.button_disabled, s_palette[UI_COLOR_BORDER]);
    lv_style_set_text_color(&s_styles.button_disabled, s_palette[UI_COLOR_TEXT_MUTED]);
    lv_style_set_opa(&s_styles.button_disabled, LV_OPA_60);
    lv_style_set_shadow_opa(&s_styles.button_disabled, LV_OPA_TRANSP);

    lv_style_init(&s_styles.icon_button);
    lv_style_set_bg_opa(&s_styles.icon_button, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.icon_button, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.icon_button, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_bg_grad_dir(&s_styles.icon_button, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.icon_button, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.icon_button, s_palette[UI_COLOR_BORDER]);
    lv_style_set_radius(&s_styles.icon_button, 16);
    lv_style_set_pad_all(&s_styles.icon_button, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.icon_button, 10);
    lv_style_set_shadow_color(&s_styles.icon_button, s_palette[UI_COLOR_ACCENT_PRIMARY]);
    lv_style_set_shadow_opa(&s_styles.icon_button, LV_OPA_20);
    lv_style_set_transition(&s_styles.icon_button, &s_button_transition);

    lv_style_init(&s_styles.chip);
    lv_style_set_bg_opa(&s_styles.chip, LV_OPA_40);
    lv_style_set_bg_color(&s_styles.chip, s_palette[UI_COLOR_ACCENT_PRIMARY]);
    lv_style_set_border_width(&s_styles.chip, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.chip, s_palette[UI_COLOR_ACCENT_PRIMARY]);
    lv_style_set_radius(&s_styles.chip, 30);
    lv_style_set_pad_left(&s_styles.chip, UI_SPACE_12);
    lv_style_set_pad_right(&s_styles.chip, UI_SPACE_12);
    lv_style_set_pad_top(&s_styles.chip, UI_SPACE_4);
    lv_style_set_pad_bottom(&s_styles.chip, UI_SPACE_4);
    lv_style_set_text_color(&s_styles.chip, s_palette[UI_COLOR_TEXT_PRIMARY]);
    lv_style_set_text_font(&s_styles.chip, &lv_font_montserrat_12);

    lv_style_init(&s_styles.metric_card);
    lv_style_set_bg_opa(&s_styles.metric_card, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.metric_card, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.metric_card, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_bg_grad_dir(&s_styles.metric_card, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.metric_card, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.metric_card, s_palette[UI_COLOR_BORDER]);
    lv_style_set_radius(&s_styles.metric_card, 22);
    lv_style_set_pad_all(&s_styles.metric_card, UI_SPACE_12);
    lv_style_set_pad_row(&s_styles.metric_card, UI_SPACE_12);
    lv_style_set_shadow_color(&s_styles.metric_card, s_palette[UI_COLOR_ACCENT_PRIMARY]);
    lv_style_set_shadow_width(&s_styles.metric_card, 22);
    lv_style_set_shadow_opa(&s_styles.metric_card, LV_OPA_30);
    lv_style_set_transition(&s_styles.metric_card, &s_button_transition);

    lv_style_init(&s_styles.list_row);
    lv_style_set_bg_opa(&s_styles.list_row, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.list_row, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_color(&s_styles.list_row, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_dir(&s_styles.list_row, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.list_row, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.list_row, s_palette[UI_COLOR_BORDER]);
    lv_style_set_radius(&s_styles.list_row, 16);
    lv_style_set_pad_all(&s_styles.list_row, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.list_row, 8);
    lv_style_set_shadow_color(&s_styles.list_row, lv_color_darken(s_palette[UI_COLOR_BG], 8));
    lv_style_set_shadow_opa(&s_styles.list_row, LV_OPA_20);

    lv_style_init(&s_styles.modal_overlay);
    lv_style_set_bg_color(&s_styles.modal_overlay, s_palette[UI_COLOR_MODAL_OVERLAY]);
    lv_style_set_bg_opa(&s_styles.modal_overlay, LV_OPA_70);

    lv_style_init(&s_styles.modal_card);
    lv_style_set_bg_opa(&s_styles.modal_card, LV_OPA_COVER);
    lv_style_set_bg_color(&s_styles.modal_card, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.modal_card, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_dir(&s_styles.modal_card, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.modal_card, UI_BORDER_THICK);
    lv_style_set_border_color(&s_styles.modal_card, s_palette[UI_COLOR_ACCENT_PRIMARY]);
    lv_style_set_radius(&s_styles.modal_card, 24);
    lv_style_set_pad_all(&s_styles.modal_card, UI_SPACE_16);
    lv_style_set_pad_row(&s_styles.modal_card, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.modal_card, 26);
    lv_style_set_shadow_color(&s_styles.modal_card, s_palette[UI_COLOR_ACCENT_PRIMARY]);
    lv_style_set_shadow_opa(&s_styles.modal_card, LV_OPA_30);

    s_theme_inited = true;
}

bool ui_theme_is_initialized(void)
{
    return s_theme_inited;
}

lv_color_t ui_theme_color(ui_color_token_t token)
{
    if ((int)token < 0 || token >= UI_COLOR_COUNT) {
        return lv_color_white();
    }
    return s_palette[token];
}

const lv_font_t *ui_theme_font_h1(void)
{
    return &lv_font_montserrat_44;
}

const lv_font_t *ui_theme_font_h2(void)
{
    return &lv_font_montserrat_28;
}

const lv_font_t *ui_theme_font_body(void)
{
    return &lv_font_montserrat_20;
}

const lv_font_t *ui_theme_font_label(void)
{
    return &lv_font_montserrat_16;
}

const ui_theme_styles_t *ui_theme_styles(void)
{
    return &s_styles;
}

void ui_theme_apply_page(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.page, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_card(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.card, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_section(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.section, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_appbar(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.appbar, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_tabbar(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.tabbar, LV_PART_MAIN | LV_STATE_DEFAULT);
}

static void apply_button_with_state_styles(lv_obj_t *obj, lv_style_t *base)
{
    lv_obj_add_style(obj, base, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_add_style(obj, &s_styles.button_pressed, LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_add_style(obj, &s_styles.button_disabled, LV_PART_MAIN | LV_STATE_DISABLED);
}

void ui_theme_apply_primary_btn(lv_obj_t *obj)
{
    if (!obj) return;
    apply_button_with_state_styles(obj, &s_styles.button_primary);
}

void ui_theme_apply_secondary_btn(lv_obj_t *obj)
{
    if (!obj) return;
    apply_button_with_state_styles(obj, &s_styles.button_secondary);
}

void ui_theme_apply_danger_btn(lv_obj_t *obj)
{
    if (!obj) return;
    apply_button_with_state_styles(obj, &s_styles.button_danger);
}

void ui_theme_apply_icon_btn(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.icon_button, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_add_style(obj, &s_styles.button_pressed, LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_add_style(obj, &s_styles.button_disabled, LV_PART_MAIN | LV_STATE_DISABLED);
}

void ui_theme_apply_chip(lv_obj_t *obj, lv_color_t tint_color)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.chip, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_bg_color(obj, tint_color, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_border_color(obj, tint_color, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_metric_card(lv_obj_t *obj, lv_color_t accent)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.metric_card, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_add_style(obj, &s_styles.button_pressed, LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_style_border_color(obj, accent, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_shadow_color(obj, accent, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_list_row(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.list_row, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_add_style(obj, &s_styles.button_pressed, LV_PART_MAIN | LV_STATE_PRESSED);
}

void ui_theme_apply_modal_overlay(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.modal_overlay, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_modal_card(lv_obj_t *obj)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.modal_card, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_style_title(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_h2(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_PRIMARY], 0);
}

void ui_theme_style_subtitle(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, &lv_font_montserrat_22, 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_SECONDARY], 0);
}

void ui_theme_style_body(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_body(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_PRIMARY], 0);
}

void ui_theme_style_label(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_label(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_SECONDARY], 0);
}

void ui_theme_style_muted(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_label(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_MUTED], 0);
}
