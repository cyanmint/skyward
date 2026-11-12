//! Pure touch/display mapping shared by the Android input adapter and host tests.


/// Map a raw axis value into a display's pixel coordinates, clamping the
/// inclusive input range to the inclusive pixel range. A descending range
/// reverses the axis, which lets callers express a 180-degree touch transform.
pub fn map_axis(raw: i32, range: (i32, i32), pixels: u32) -> f32 {
    if pixels <= 1 || range.1 == range.0 {
        return 0.0;
    }
    let span = (range.1 as i64 - range.0 as i64) as f64;
    let unit = ((raw as i64 - range.0 as i64) as f64 / span).clamp(0.0, 1.0);
    (unit * (pixels - 1) as f64) as f32
}

/// Map a raw touch point to pixels, applying a 180-degree transform when configured.
pub fn map_touch_point(
    raw: (i32, i32),
    ranges: ((i32, i32), (i32, i32)),
    pixels: (u32, u32),
    rotation: u16,
) -> (f32, f32) {
    let (x_range, y_range) = if rotation == 180 {
        ((ranges.0.1, ranges.0.0), (ranges.1.1, ranges.1.0))
    } else {
        ranges
    };
    (map_axis(raw.0, x_range, pixels.0), map_axis(raw.1, y_range, pixels.1))
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
    fn raw_touch_endpoints_land_on_display_pixels_not_outside_the_canvas() {
        assert_eq!(map_axis(0, (0, 1208), 1208), 0.0);
        assert_eq!(map_axis(1208, (0, 1208), 1208), 1207.0);
        assert_eq!(map_axis(19_583, (0, 19_583), 1224), 1223.0);
        assert_eq!(map_axis(-1, (0, 1208), 1208), 0.0);
        assert_eq!(map_axis(1209, (0, 1208), 1208), 1207.0);
    }

    #[test]
    fn descending_axis_ranges_flip_touch_coordinates_for_a_180_degree_panel() {
        let map_outer = |x, y| {
            (
                map_axis(x, (1208, 0), 1208),
                map_axis(y, (1392, 0), 1392),
            )
        };
        assert_eq!(map_outer(1208, 1392), (0.0, 0.0));
        assert_eq!(map_outer(0, 0), (1207.0, 1391.0));
    }

    #[test]
    fn configured_touch_rotation_maps_the_raw_point_to_the_opposite_corner() {
        assert_eq!(map_touch_point((1208, 1392), ((0, 1208), (0, 1392)), (1208, 1392), 180), (0.0, 0.0));
        assert_eq!(map_touch_point((0, 0), ((0, 1208), (0, 1392)), (1208, 1392), 180), (1207.0, 1391.0));
        assert_eq!(map_touch_point((0, 0), ((0, 1208), (0, 1392)), (1208, 1392), 0), (0.0, 0.0));
    }

    #[test]
    fn touch_input_is_matched_by_its_device_name() {
        let panels = [("synaptics_tcm_touch", 0), ("goodix_ts", 1)];
        assert_eq!(display_for_device("synaptics_tcm_touch", panels), Some(0));
        assert_eq!(display_for_device("goodix_ts", panels), Some(1));
        assert_eq!(display_for_device("uinput-goodix", panels), None);
    }
}
