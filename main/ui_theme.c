#include "ui_theme.h"
#include <string.h>
#include <ctype.h>

static bool s_theme_inited = false;
static bool s_dark_mode = true;
static bool s_custom_palette_enabled = false;
static lv_display_t *s_theme_display = NULL;

static const lv_color_t s_palette_dark[UI_COLOR_COUNT] = {
    [UI_COLOR_BG] = LV_COLOR_MAKE(0x0B, 0x11, 0x17),
    [UI_COLOR_BG_LAYER] = LV_COLOR_MAKE(0x0B, 0x11, 0x17),
    [UI_COLOR_SURFACE] = LV_COLOR_MAKE(0x11, 0x18, 0x20),
    [UI_COLOR_SURFACE_ALT] = LV_COLOR_MAKE(0x14, 0x1D, 0x27),
    [UI_COLOR_CARD] = LV_COLOR_MAKE(0x11, 0x18, 0x20),
    [UI_COLOR_BORDER] = LV_COLOR_MAKE(0x2A, 0x36, 0x44),
    [UI_COLOR_TEXT_PRIMARY] = LV_COLOR_MAKE(0xF2, 0xF6, 0xFB),
    [UI_COLOR_TEXT_SECONDARY] = LV_COLOR_MAKE(0xB4, 0xC0, 0xCE),
    [UI_COLOR_TEXT_MUTED] = LV_COLOR_MAKE(0x7F, 0x8B, 0x9A),
    [UI_COLOR_ACCENT_PRIMARY] = LV_COLOR_MAKE(0x56, 0xA9, 0xFF),
    [UI_COLOR_ACCENT_SECONDARY] = LV_COLOR_MAKE(0x56, 0xA9, 0xFF),
    [UI_COLOR_SUCCESS] = LV_COLOR_MAKE(0x5F, 0xBF, 0x8A),
    [UI_COLOR_WARNING] = LV_COLOR_MAKE(0xD8, 0xA2, 0x5A),
    [UI_COLOR_ERROR] = LV_COLOR_MAKE(0xD7, 0x7B, 0x86),
    [UI_COLOR_INFO] = LV_COLOR_MAKE(0x56, 0xA9, 0xFF),
    [UI_COLOR_MODAL_OVERLAY] = LV_COLOR_MAKE(0x00, 0x00, 0x00),
};

static const lv_color_t s_palette_light[UI_COLOR_COUNT] = {
    [UI_COLOR_BG] = LV_COLOR_MAKE(0x24, 0x34, 0x45),
    [UI_COLOR_BG_LAYER] = LV_COLOR_MAKE(0x2A, 0x3C, 0x50),
    [UI_COLOR_SURFACE] = LV_COLOR_MAKE(0x31, 0x46, 0x5D),
    [UI_COLOR_SURFACE_ALT] = LV_COLOR_MAKE(0x39, 0x52, 0x6B),
    [UI_COLOR_CARD] = LV_COLOR_MAKE(0x32, 0x48, 0x60),
    [UI_COLOR_BORDER] = LV_COLOR_MAKE(0x57, 0x72, 0x8D),
    [UI_COLOR_TEXT_PRIMARY] = LV_COLOR_MAKE(0xF2, 0xF6, 0xFB),
    [UI_COLOR_TEXT_SECONDARY] = LV_COLOR_MAKE(0xD2, 0xDE, 0xEA),
    [UI_COLOR_TEXT_MUTED] = LV_COLOR_MAKE(0xA4, 0xB4, 0xC4),
    [UI_COLOR_ACCENT_PRIMARY] = LV_COLOR_MAKE(0x4E, 0xA0, 0xF7),
    [UI_COLOR_ACCENT_SECONDARY] = LV_COLOR_MAKE(0x4E, 0xA0, 0xF7),
    [UI_COLOR_SUCCESS] = LV_COLOR_MAKE(0x60, 0xB8, 0x88),
    [UI_COLOR_WARNING] = LV_COLOR_MAKE(0xD0, 0x9A, 0x58),
    [UI_COLOR_ERROR] = LV_COLOR_MAKE(0xCC, 0x75, 0x82),
    [UI_COLOR_INFO] = LV_COLOR_MAKE(0x4E, 0xA0, 0xF7),
    [UI_COLOR_MODAL_OVERLAY] = LV_COLOR_MAKE(0x00, 0x00, 0x00),
};

static lv_color_t s_palette[UI_COLOR_COUNT];
static lv_color_t s_custom_palette[UI_COLOR_COUNT];

static ui_theme_styles_t s_styles;
static ui_theme_font_profile_t s_font_profile = UI_THEME_FONT_DEFAULT;

typedef struct {
    const lv_font_t *theme_base;
    const lv_font_t *h1;
    const lv_font_t *h2;
    const lv_font_t *subtitle;
    const lv_font_t *body;
    const lv_font_t *label;
    const lv_font_t *button;
    const lv_font_t *chip;
} ui_theme_font_pack_t;

#if LV_FONT_UNSCII_16
#define UI_THEME_TERMINAL_THEME_BASE (&lv_font_unscii_16)
#define UI_THEME_TERMINAL_SUBTITLE (&lv_font_unscii_16)
#define UI_THEME_TERMINAL_BODY (&lv_font_unscii_16)
#define UI_THEME_TERMINAL_LABEL (&lv_font_unscii_8)
#define UI_THEME_TERMINAL_BUTTON (&lv_font_unscii_16)
#define UI_THEME_TERMINAL_CHIP (&lv_font_unscii_8)
#else
#define UI_THEME_TERMINAL_THEME_BASE (&lv_font_montserrat_14)
#define UI_THEME_TERMINAL_SUBTITLE (&lv_font_montserrat_18)
#define UI_THEME_TERMINAL_BODY (&lv_font_montserrat_16)
#define UI_THEME_TERMINAL_LABEL (&lv_font_montserrat_12)
#define UI_THEME_TERMINAL_BUTTON (&lv_font_montserrat_16)
#define UI_THEME_TERMINAL_CHIP (&lv_font_montserrat_10)
#endif

static const ui_theme_font_pack_t s_font_packs[UI_THEME_FONT_COUNT] = {
    [UI_THEME_FONT_DEFAULT] = {
        .theme_base = &lv_font_montserrat_18,
        .h1 = &lv_font_montserrat_44,
        .h2 = &lv_font_montserrat_28,
        .subtitle = &lv_font_montserrat_22,
        .body = &lv_font_montserrat_20,
        .label = &lv_font_montserrat_16,
        .button = &lv_font_montserrat_20,
        .chip = &lv_font_montserrat_12,
    },
    [UI_THEME_FONT_COMPACT] = {
        .theme_base = &lv_font_montserrat_16,
        .h1 = &lv_font_montserrat_38,
        .h2 = &lv_font_montserrat_24,
        .subtitle = &lv_font_montserrat_20,
        .body = &lv_font_montserrat_18,
        .label = &lv_font_montserrat_14,
        .button = &lv_font_montserrat_18,
        .chip = &lv_font_montserrat_10,
    },
    [UI_THEME_FONT_LARGE] = {
        .theme_base = &lv_font_montserrat_20,
        .h1 = &lv_font_montserrat_48,
        .h2 = &lv_font_montserrat_32,
        .subtitle = &lv_font_montserrat_24,
        .body = &lv_font_montserrat_22,
        .label = &lv_font_montserrat_18,
        .button = &lv_font_montserrat_22,
        .chip = &lv_font_montserrat_12,
    },
    [UI_THEME_FONT_TERMINAL] = {
        .theme_base = UI_THEME_TERMINAL_THEME_BASE,
        .h1 = &lv_font_montserrat_36,
        .h2 = &lv_font_montserrat_24,
        .subtitle = UI_THEME_TERMINAL_SUBTITLE,
        .body = UI_THEME_TERMINAL_BODY,
        .label = UI_THEME_TERMINAL_LABEL,
        .button = UI_THEME_TERMINAL_BUTTON,
        .chip = UI_THEME_TERMINAL_CHIP,
    },
};

static const char *s_font_profile_names[UI_THEME_FONT_COUNT] = {
    [UI_THEME_FONT_DEFAULT] = "default",
    [UI_THEME_FONT_COMPACT] = "compact",
    [UI_THEME_FONT_LARGE] = "large",
    [UI_THEME_FONT_TERMINAL] = "terminal",
};

static const lv_style_prop_t s_button_transition_props[] = {
    LV_STYLE_BG_COLOR,
    LV_STYLE_BORDER_COLOR,
    LV_STYLE_SHADOW_OPA,
    LV_STYLE_TRANSLATE_Y,
    LV_STYLE_PROP_INV,
};

static lv_style_transition_dsc_t s_button_transition;

static const ui_theme_font_pack_t *active_font_pack(void)
{
    if ((int)s_font_profile < 0 || s_font_profile >= UI_THEME_FONT_COUNT) {
        return &s_font_packs[UI_THEME_FONT_DEFAULT];
    }
    return &s_font_packs[s_font_profile];
}

static bool str_eq_icase(const char *a, const char *b)
{
    if (!a || !b) {
        return false;
    }
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static void update_palette_from_mode(void)
{
    if (s_custom_palette_enabled) {
        memcpy(s_palette, s_custom_palette, sizeof(s_palette));
        return;
    }

    const lv_color_t *src = s_dark_mode ? s_palette_dark : s_palette_light;
    memcpy(s_palette, src, sizeof(s_palette));
}

static void reset_all_styles(void)
{
    lv_style_reset(&s_styles.page);
    lv_style_reset(&s_styles.card);
    lv_style_reset(&s_styles.section);
    lv_style_reset(&s_styles.appbar);
    lv_style_reset(&s_styles.tabbar);
    lv_style_reset(&s_styles.button_primary);
    lv_style_reset(&s_styles.button_secondary);
    lv_style_reset(&s_styles.button_danger);
    lv_style_reset(&s_styles.button_pressed);
    lv_style_reset(&s_styles.button_disabled);
    lv_style_reset(&s_styles.icon_button);
    lv_style_reset(&s_styles.chip);
    lv_style_reset(&s_styles.metric_card);
    lv_style_reset(&s_styles.list_row);
    lv_style_reset(&s_styles.modal_overlay);
    lv_style_reset(&s_styles.modal_card);
}

static void init_button_style(lv_style_t *style,
                              lv_color_t bg,
                              lv_color_t border,
                              lv_color_t text,
                              const lv_font_t *font)
{
    lv_style_init(style);
    lv_style_set_bg_opa(style, 188);
    lv_style_set_bg_color(style, bg);
    lv_style_set_bg_grad_color(style, bg);
    lv_style_set_bg_grad_dir(style, LV_GRAD_DIR_NONE);
    lv_style_set_border_width(style, UI_BORDER_THIN);
    lv_style_set_border_color(style, border);
    lv_style_set_border_opa(style, 108);
    lv_style_set_radius(style, 14);
    lv_style_set_pad_left(style, UI_SPACE_16);
    lv_style_set_pad_right(style, UI_SPACE_16);
    lv_style_set_pad_top(style, UI_SPACE_12);
    lv_style_set_pad_bottom(style, UI_SPACE_12);
    lv_style_set_min_height(style, UI_TOUCH_TARGET_PRIMARY);
    lv_style_set_text_color(style, text);
    lv_style_set_text_font(style, font ? font : &lv_font_montserrat_20);
    lv_style_set_shadow_color(style, lv_color_black());
    lv_style_set_shadow_width(style, 7);
    lv_style_set_shadow_opa(style, LV_OPA_10);
    lv_style_set_transition(style, &s_button_transition);
}

void ui_theme_init(lv_display_t *disp)
{
    if (disp == NULL) {
        disp = lv_display_get_default();
    }
    if (disp != NULL) {
        s_theme_display = disp;
    } else if (s_theme_display != NULL) {
        disp = s_theme_display;
    }

    update_palette_from_mode();

    if (s_theme_inited) {
        reset_all_styles();
    }

    const ui_theme_font_pack_t *fonts = active_font_pack();

    if (disp != NULL) {
        lv_theme_t *theme = lv_theme_default_init(
            disp,
            s_palette[UI_COLOR_ACCENT_PRIMARY],
            s_palette[UI_COLOR_ACCENT_SECONDARY],
            s_dark_mode,
            fonts->theme_base);
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
    lv_style_set_bg_grad_color(&s_styles.page, s_palette[UI_COLOR_BG]);
    lv_style_set_bg_grad_dir(&s_styles.page, LV_GRAD_DIR_NONE);
    lv_style_set_border_width(&s_styles.page, 0);
    lv_style_set_pad_all(&s_styles.page, UI_SPACE_16);
    lv_style_set_pad_row(&s_styles.page, UI_SPACE_16);

    lv_style_init(&s_styles.card);
    lv_style_set_bg_opa(&s_styles.card, 232);
    lv_style_set_bg_color(&s_styles.card, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_color(&s_styles.card, lv_color_lighten(s_palette[UI_COLOR_CARD], 10));
    lv_style_set_bg_grad_dir(&s_styles.card, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.card, UI_BORDER_THIN);
    lv_style_set_border_color(
        &s_styles.card,
        lv_color_mix(s_palette[UI_COLOR_TEXT_PRIMARY], s_palette[UI_COLOR_CARD], LV_OPA_20));
    lv_style_set_border_opa(&s_styles.card, 40);
    lv_style_set_radius(&s_styles.card, 21);
    lv_style_set_pad_all(&s_styles.card, UI_SPACE_12);
    lv_style_set_pad_row(&s_styles.card, UI_SPACE_8);
    lv_style_set_shadow_width(&s_styles.card, 14);
    lv_style_set_shadow_ofs_y(&s_styles.card, 2);
    lv_style_set_shadow_color(&s_styles.card, lv_color_black());
    lv_style_set_shadow_opa(&s_styles.card, LV_OPA_20);

    lv_style_init(&s_styles.section);
    lv_style_set_bg_opa(&s_styles.section, 228);
    lv_style_set_bg_color(&s_styles.section, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_color(&s_styles.section, lv_color_lighten(s_palette[UI_COLOR_CARD], 8));
    lv_style_set_bg_grad_dir(&s_styles.section, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.section, UI_BORDER_THIN);
    lv_style_set_border_color(
        &s_styles.section,
        lv_color_mix(s_palette[UI_COLOR_TEXT_PRIMARY], s_palette[UI_COLOR_CARD], LV_OPA_20));
    lv_style_set_border_opa(&s_styles.section, 38);
    lv_style_set_radius(&s_styles.section, 18);
    lv_style_set_pad_all(&s_styles.section, UI_SPACE_16);
    lv_style_set_pad_row(&s_styles.section, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.section, 12);
    lv_style_set_shadow_ofs_y(&s_styles.section, 2);
    lv_style_set_shadow_color(&s_styles.section, lv_color_black());
    lv_style_set_shadow_opa(&s_styles.section, LV_OPA_10);

    lv_style_init(&s_styles.appbar);
    lv_style_set_bg_opa(&s_styles.appbar, 156);
    lv_style_set_bg_color(&s_styles.appbar, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.appbar, lv_color_lighten(s_palette[UI_COLOR_SURFACE], 2));
    lv_style_set_bg_grad_dir(&s_styles.appbar, LV_GRAD_DIR_NONE);
    lv_style_set_border_width(&s_styles.appbar, UI_BORDER_THIN);
    lv_style_set_border_side(&s_styles.appbar, LV_BORDER_SIDE_BOTTOM);
    lv_style_set_border_color(&s_styles.appbar, lv_color_mix(s_palette[UI_COLOR_BORDER], s_palette[UI_COLOR_SURFACE], LV_OPA_30));
    lv_style_set_border_opa(&s_styles.appbar, 100);
    lv_style_set_pad_left(&s_styles.appbar, UI_SPACE_16);
    lv_style_set_pad_right(&s_styles.appbar, UI_SPACE_16);
    lv_style_set_pad_top(&s_styles.appbar, UI_SPACE_8);
    lv_style_set_pad_bottom(&s_styles.appbar, UI_SPACE_8);

    lv_style_init(&s_styles.tabbar);
    lv_style_set_bg_opa(&s_styles.tabbar, 148);
    lv_style_set_bg_color(&s_styles.tabbar, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.tabbar, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_dir(&s_styles.tabbar, LV_GRAD_DIR_NONE);
    lv_style_set_border_width(&s_styles.tabbar, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.tabbar, lv_color_mix(s_palette[UI_COLOR_BORDER], s_palette[UI_COLOR_SURFACE], LV_OPA_30));
    lv_style_set_border_opa(&s_styles.tabbar, 100);
    lv_style_set_radius(&s_styles.tabbar, 14);
    lv_style_set_pad_left(&s_styles.tabbar, UI_SPACE_8);
    lv_style_set_pad_right(&s_styles.tabbar, UI_SPACE_8);
    lv_style_set_pad_top(&s_styles.tabbar, UI_SPACE_4);
    lv_style_set_pad_bottom(&s_styles.tabbar, UI_SPACE_4);

    init_button_style(
        &s_styles.button_primary,
        s_palette[UI_COLOR_ACCENT_PRIMARY],
        lv_color_lighten(s_palette[UI_COLOR_ACCENT_PRIMARY], 10),
        s_palette[UI_COLOR_TEXT_PRIMARY],
        fonts->button);

    init_button_style(
        &s_styles.button_secondary,
        s_palette[UI_COLOR_SURFACE_ALT],
        s_palette[UI_COLOR_BORDER],
        s_palette[UI_COLOR_TEXT_PRIMARY],
        fonts->button);

    init_button_style(
        &s_styles.button_danger,
        s_palette[UI_COLOR_ERROR],
        lv_color_lighten(s_palette[UI_COLOR_ERROR], 10),
        s_palette[UI_COLOR_TEXT_PRIMARY],
        fonts->button);

    lv_style_init(&s_styles.button_pressed);
    lv_style_set_translate_y(&s_styles.button_pressed, 1);
    lv_style_set_shadow_width(&s_styles.button_pressed, 8);
    lv_style_set_shadow_opa(&s_styles.button_pressed, LV_OPA_10);
    lv_style_set_bg_opa(&s_styles.button_pressed, 236);

    lv_style_init(&s_styles.button_disabled);
    lv_style_set_bg_color(&s_styles.button_disabled, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_border_color(&s_styles.button_disabled, s_palette[UI_COLOR_BORDER]);
    lv_style_set_text_color(&s_styles.button_disabled, s_palette[UI_COLOR_TEXT_MUTED]);
    lv_style_set_opa(&s_styles.button_disabled, 150);
    lv_style_set_shadow_opa(&s_styles.button_disabled, LV_OPA_TRANSP);

    lv_style_init(&s_styles.icon_button);
    lv_style_set_bg_opa(&s_styles.icon_button, 170);
    lv_style_set_bg_color(&s_styles.icon_button, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_bg_grad_color(&s_styles.icon_button, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_bg_grad_dir(&s_styles.icon_button, LV_GRAD_DIR_NONE);
    lv_style_set_border_width(&s_styles.icon_button, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.icon_button, lv_color_mix(s_palette[UI_COLOR_BORDER], s_palette[UI_COLOR_SURFACE_ALT], LV_OPA_20));
    lv_style_set_border_opa(&s_styles.icon_button, 90);
    lv_style_set_radius(&s_styles.icon_button, 14);
    lv_style_set_pad_all(&s_styles.icon_button, UI_SPACE_8);
    lv_style_set_shadow_width(&s_styles.icon_button, 6);
    lv_style_set_shadow_color(&s_styles.icon_button, lv_color_black());
    lv_style_set_shadow_opa(&s_styles.icon_button, LV_OPA_10);
    lv_style_set_transition(&s_styles.icon_button, &s_button_transition);

    lv_style_init(&s_styles.chip);
    lv_style_set_bg_opa(&s_styles.chip, 132);
    lv_style_set_bg_color(&s_styles.chip, s_palette[UI_COLOR_SURFACE_ALT]);
    lv_style_set_border_width(&s_styles.chip, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.chip, lv_color_mix(s_palette[UI_COLOR_BORDER], s_palette[UI_COLOR_SURFACE_ALT], LV_OPA_20));
    lv_style_set_border_opa(&s_styles.chip, 86);
    lv_style_set_radius(&s_styles.chip, 30);
    lv_style_set_pad_left(&s_styles.chip, UI_SPACE_8);
    lv_style_set_pad_right(&s_styles.chip, UI_SPACE_8);
    lv_style_set_pad_top(&s_styles.chip, UI_SPACE_4);
    lv_style_set_pad_bottom(&s_styles.chip, UI_SPACE_4);
    lv_style_set_text_color(&s_styles.chip, s_palette[UI_COLOR_TEXT_SECONDARY]);
    lv_style_set_text_font(&s_styles.chip, fonts->chip);

    lv_style_init(&s_styles.metric_card);
    lv_style_set_bg_opa(&s_styles.metric_card, 230);
    lv_style_set_bg_color(&s_styles.metric_card, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_color(&s_styles.metric_card, lv_color_lighten(s_palette[UI_COLOR_CARD], 8));
    lv_style_set_bg_grad_dir(&s_styles.metric_card, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.metric_card, UI_BORDER_THIN);
    lv_style_set_border_color(
        &s_styles.metric_card,
        lv_color_mix(s_palette[UI_COLOR_TEXT_PRIMARY], s_palette[UI_COLOR_CARD], LV_OPA_20));
    lv_style_set_border_opa(&s_styles.metric_card, 38);
    lv_style_set_radius(&s_styles.metric_card, 16);
    lv_style_set_pad_all(&s_styles.metric_card, UI_SPACE_12);
    lv_style_set_pad_row(&s_styles.metric_card, UI_SPACE_12);
    lv_style_set_shadow_color(&s_styles.metric_card, lv_color_black());
    lv_style_set_shadow_width(&s_styles.metric_card, 12);
    lv_style_set_shadow_ofs_y(&s_styles.metric_card, 2);
    lv_style_set_shadow_opa(&s_styles.metric_card, LV_OPA_10);
    lv_style_set_transition(&s_styles.metric_card, &s_button_transition);

    lv_style_init(&s_styles.list_row);
    lv_style_set_bg_opa(&s_styles.list_row, 228);
    lv_style_set_bg_color(&s_styles.list_row, s_palette[UI_COLOR_CARD]);
    lv_style_set_bg_grad_color(&s_styles.list_row, lv_color_lighten(s_palette[UI_COLOR_CARD], 8));
    lv_style_set_bg_grad_dir(&s_styles.list_row, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.list_row, UI_BORDER_THIN);
    lv_style_set_border_color(
        &s_styles.list_row,
        lv_color_mix(s_palette[UI_COLOR_TEXT_PRIMARY], s_palette[UI_COLOR_CARD], LV_OPA_20));
    lv_style_set_border_opa(&s_styles.list_row, 36);
    lv_style_set_radius(&s_styles.list_row, 14);
    lv_style_set_pad_all(&s_styles.list_row, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.list_row, 10);
    lv_style_set_shadow_ofs_y(&s_styles.list_row, 2);
    lv_style_set_shadow_color(&s_styles.list_row, lv_color_black());
    lv_style_set_shadow_opa(&s_styles.list_row, LV_OPA_10);

    lv_style_init(&s_styles.modal_overlay);
    lv_style_set_bg_color(&s_styles.modal_overlay, s_palette[UI_COLOR_MODAL_OVERLAY]);
    lv_style_set_bg_opa(&s_styles.modal_overlay, LV_OPA_70);

    lv_style_init(&s_styles.modal_card);
    lv_style_set_bg_opa(&s_styles.modal_card, 220);
    lv_style_set_bg_color(&s_styles.modal_card, s_palette[UI_COLOR_SURFACE]);
    lv_style_set_bg_grad_color(&s_styles.modal_card, lv_color_lighten(s_palette[UI_COLOR_SURFACE], 2));
    lv_style_set_bg_grad_dir(&s_styles.modal_card, LV_GRAD_DIR_VER);
    lv_style_set_border_width(&s_styles.modal_card, UI_BORDER_THIN);
    lv_style_set_border_color(&s_styles.modal_card, lv_color_mix(s_palette[UI_COLOR_BORDER], s_palette[UI_COLOR_SURFACE], LV_OPA_30));
    lv_style_set_border_opa(&s_styles.modal_card, 100);
    lv_style_set_radius(&s_styles.modal_card, 20);
    lv_style_set_pad_all(&s_styles.modal_card, UI_SPACE_16);
    lv_style_set_pad_row(&s_styles.modal_card, UI_SPACE_12);
    lv_style_set_shadow_width(&s_styles.modal_card, 15);
    lv_style_set_shadow_color(&s_styles.modal_card, lv_color_black());
    lv_style_set_shadow_opa(&s_styles.modal_card, LV_OPA_20);

    s_theme_inited = true;
}

bool ui_theme_is_initialized(void)
{
    return s_theme_inited;
}

void ui_theme_set_dark_mode(bool enabled)
{
    if (s_dark_mode == enabled && s_theme_inited) {
        return;
    }

    s_dark_mode = enabled;
    update_palette_from_mode();

    if (s_theme_inited) {
        ui_theme_init(s_theme_display);
        lv_obj_report_style_change(NULL);
    }
}

bool ui_theme_is_dark_mode(void)
{
    return s_dark_mode;
}

void ui_theme_set_custom_palette(const lv_color_t palette[UI_COLOR_COUNT])
{
    if (!palette) {
        return;
    }

    memcpy(s_custom_palette, palette, sizeof(s_custom_palette));
    s_custom_palette_enabled = true;
    update_palette_from_mode();

    if (s_theme_inited) {
        ui_theme_init(s_theme_display);
        lv_obj_report_style_change(NULL);
    }
}

void ui_theme_clear_custom_palette(void)
{
    if (!s_custom_palette_enabled) {
        return;
    }

    s_custom_palette_enabled = false;
    update_palette_from_mode();

    if (s_theme_inited) {
        ui_theme_init(s_theme_display);
        lv_obj_report_style_change(NULL);
    }
}

void ui_theme_get_default_palette(lv_color_t out_palette[UI_COLOR_COUNT])
{
    if (!out_palette) {
        return;
    }

    memcpy(out_palette, s_palette_dark, sizeof(s_palette_dark));
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
    return active_font_pack()->h1;
}

const lv_font_t *ui_theme_font_h2(void)
{
    return active_font_pack()->h2;
}

const lv_font_t *ui_theme_font_body(void)
{
    return active_font_pack()->body;
}

const lv_font_t *ui_theme_font_label(void)
{
    return active_font_pack()->label;
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
    lv_obj_set_style_border_color(
        obj,
        lv_color_mix(s_palette[UI_COLOR_BORDER], tint_color, LV_OPA_20),
        LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_border_opa(obj, 86, LV_PART_MAIN | LV_STATE_DEFAULT);
}

void ui_theme_apply_metric_card(lv_obj_t *obj, lv_color_t accent)
{
    if (!obj) return;
    lv_obj_add_style(obj, &s_styles.metric_card, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_add_style(obj, &s_styles.button_pressed, LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_style_border_color(
        obj,
        lv_color_mix(accent, s_palette[UI_COLOR_CARD], LV_OPA_20),
        LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_set_style_shadow_color(obj, lv_color_black(), LV_PART_MAIN | LV_STATE_DEFAULT);
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
    lv_obj_set_style_text_opa(label, LV_OPA_COVER, 0);
}

void ui_theme_style_subtitle(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, active_font_pack()->subtitle, 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_SECONDARY], 0);
    lv_obj_set_style_text_opa(label, 205, 0);
}

void ui_theme_style_body(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_body(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_PRIMARY], 0);
    lv_obj_set_style_text_opa(label, 235, 0);
}

void ui_theme_style_label(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_label(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_SECONDARY], 0);
    lv_obj_set_style_text_opa(label, 210, 0);
}

void ui_theme_style_muted(lv_obj_t *label)
{
    if (!label) return;
    lv_obj_set_style_text_font(label, ui_theme_font_label(), 0);
    lv_obj_set_style_text_color(label, s_palette[UI_COLOR_TEXT_MUTED], 0);
    lv_obj_set_style_text_opa(label, 185, 0);
}

void ui_theme_set_font_profile(ui_theme_font_profile_t profile)
{
    if ((int)profile < 0 || profile >= UI_THEME_FONT_COUNT) {
        profile = UI_THEME_FONT_DEFAULT;
    }

    if (s_font_profile == profile && s_theme_inited) {
        return;
    }

    s_font_profile = profile;
    if (s_theme_inited) {
        ui_theme_init(s_theme_display);
        lv_obj_report_style_change(NULL);
    }
}

ui_theme_font_profile_t ui_theme_get_font_profile(void)
{
    return s_font_profile;
}

const char *ui_theme_font_profile_name(ui_theme_font_profile_t profile)
{
    if ((int)profile < 0 || profile >= UI_THEME_FONT_COUNT) {
        return s_font_profile_names[UI_THEME_FONT_DEFAULT];
    }
    return s_font_profile_names[profile];
}

bool ui_theme_font_profile_from_name(const char *name, ui_theme_font_profile_t *out_profile)
{
    if (!name || !name[0] || !out_profile) {
        return false;
    }

    for (int i = 0; i < UI_THEME_FONT_COUNT; ++i) {
        if (str_eq_icase(name, s_font_profile_names[i])) {
            *out_profile = (ui_theme_font_profile_t)i;
            return true;
        }
    }

    if (str_eq_icase(name, "normal")) {
        *out_profile = UI_THEME_FONT_DEFAULT;
        return true;
    }
    if (str_eq_icase(name, "dense")) {
        *out_profile = UI_THEME_FONT_COMPACT;
        return true;
    }
    if (str_eq_icase(name, "big")) {
        *out_profile = UI_THEME_FONT_LARGE;
        return true;
    }
    if (str_eq_icase(name, "linux")) {
        *out_profile = UI_THEME_FONT_TERMINAL;
        return true;
    }

    return false;
}
