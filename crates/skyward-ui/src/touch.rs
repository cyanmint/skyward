use crate::app::Touch;

/// Pure touch/display mapping shared by the Android input adapter and host tests.

/// Whether a touch event begins a gesture and may request a panel switch.
pub fn is_touch_start(touch: Touch) -> bool {
    matches!(touch, Touch::Down(..))
}

/// Map a raw axis value into a display's pixel coordinates, clamping the
/// inclusive input range to the inclusive pixel range.
pub fn map_axis(raw: i32, range: (i32, i32), pixels: u32) -> f32 {
    if pixels <= 1 || range.1 <= range.0 {
        return 0.0;
    }
    let span = (range.1 - range.0) as f32;
    let unit = ((raw - range.0) as f32 / span).clamp(0.0, 1.0);
    unit * (pixels - 1) as f32
}

/// Return the configured display index for a matching evdev device name.
pub fn display_for_device<'a>(
    name: &str,
    panels: impl IntoIterator<Item = (&'a str, u32)>,
) -> Option<u32> {
    panels
        .into_iter()
        .find_map(|(device, display)| (device == name).then_some(display))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_switch_is_only_requested_at_the_start_of_a_touch() {
        assert!(is_touch_start(Touch::Down(100.0, 100.0)));
        assert!(!is_touch_start(Touch::Move(150.0, 150.0)));
        assert!(!is_touch_start(Touch::Up));
    }

    #[test]
    fn raw_touch_endpoints_land_on_display_pixels_not_outside_the_canvas() {
        assert_eq!(map_axis(0, (0, 1208), 1208), 0.0);
        assert_eq!(map_axis(1208, (0, 1208), 1208), 1207.0);
        assert_eq!(map_axis(19_583, (0, 19_583), 1224), 1223.0);
        assert_eq!(map_axis(-1, (0, 1208), 1208), 0.0);
        assert_eq!(map_axis(1209, (0, 1208), 1208), 1207.0);
    }

    #[test]
    fn touch_input_is_matched_by_its_device_name() {
        let panels = [("synaptics_tcm_touch", 0), ("goodix_ts", 1)];
        assert_eq!(display_for_device("synaptics_tcm_touch", panels), Some(0));
        assert_eq!(display_for_device("goodix_ts", panels), Some(1));
        assert_eq!(display_for_device("uinput-goodix", panels), None);
    }
}
