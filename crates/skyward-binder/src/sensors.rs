#[cfg(test)]
mod tests {
    use super::*;
    use crate::parcel::Parcel;

    fn sensor_list_reply() -> Parcel {
        let mut reply = Parcel::default();
        reply.i32(0); // AIDL exception: none.
        reply.i32(1); // One SensorInfo.

        reply.i32(1); // Parcelable present.
        let size_at = reply.here();
        reply.i32(0); // Filled with the parcelable size below.
        reply.i32(73); // sensorHandle.
        reply.string("QSH Flip Status");
        reply.string("Qualcomm");
        reply.i32(2); // version.
        reply.i32(65536); // device-private type.
        reply.string("com.qualcomm.sensor.flip_status");
        reply.i32(0.0f32.to_bits() as i32); // maxRange.
        reply.i32(1.0f32.to_bits() as i32); // resolution.
        reply.i32(0.1f32.to_bits() as i32); // power.
        reply.i32(0); // minDelayUs.
        reply.i32(0); // fifoReservedEventCount.
        reply.i32(0); // fifoMaxEventCount.
        reply.string(""); // requiredPermission.
        reply.i32(0); // maxDelayUs.
        reply.i32(2); // flags: on-change.
        reply.fill(size_at, (reply.here() - size_at) as i32);
        reply
    }

    #[test]
    fn sensor_list_returns_handle_name_and_oem_type() {
        let reply = sensor_list_reply();
        let sensors = parse_sensor_list(reply.bytes()).unwrap();

        assert_eq!(sensors.len(), 1);
        assert_eq!(sensors[0].handle, 73);
        assert_eq!(sensors[0].name, "QSH Flip Status");
        assert_eq!(sensors[0].sensor_type, 65536);
        assert_eq!(sensors[0].type_as_string, "com.qualcomm.sensor.flip_status");
    }

    #[test]
    fn sensor_list_rejects_implausible_vector_counts() {
        let mut reply = Parcel::default();
        reply.i32(0); // AIDL exception: none.
        reply.i32(513);

        assert!(parse_sensor_list(reply.bytes()).is_err());
    }
}
