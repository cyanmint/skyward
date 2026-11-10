use crate::parcel::Reader;
use anyhow::{ensure, Context, Result};

#[cfg(target_os = "android")]
const INTERFACE: &str = "android.hardware.sensors.ISensors";
#[cfg(target_os = "android")]
const SERVICE: &str = "android.hardware.sensors.ISensors/default";
#[cfg(target_os = "android")]
const GET_SENSORS_LIST: u32 = 5;
const MAX_SENSORS: i32 = 512;

#[derive(Debug, PartialEq, Eq)]
pub struct SensorInfo {
    pub handle: i32,
    pub name: String,
    pub vendor: String,
    pub sensor_type: i32,
    pub type_as_string: String,
}

/// Decode the successful AIDL getSensorsList reply, including its status
/// header and the parcelable vector.
pub fn parse_sensor_list(data: &[u8]) -> Result<Vec<SensorInfo>> {
    let mut read = Reader::new(data);
    crate::status::ok(&mut read).context("read the Sensors HAL reply status")?;
    let count = read
        .i32()
        .context("read how many sensors the HAL returned")?;
    ensure!(
        (0..=MAX_SENSORS).contains(&count),
        "the Sensors HAL returned an implausible count of {count}"
    );

    let mut sensors = Vec::with_capacity(count as usize);
    for index in 0..count {
        let end = read
            .structure()
            .with_context(|| format!("read SensorInfo {index}"))?;
        let handle = read.i32().context("read the sensor handle")?;
        let name = read.string().context("read the sensor name")?;
        let vendor = read.string().context("read the sensor vendor")?;
        let _version = read.i32().context("read the sensor version")?;
        let sensor_type = read.i32().context("read the sensor type")?;
        let type_as_string = read.string().context("read the sensor OEM type")?;

        // SensorInfo stores maxRange, resolution and power as three f32s.
        for _ in 0..3 {
            read.i32().context("skip a SensorInfo float")?;
        }
        read.i32().context("read minimum delay")?;
        read.i32().context("read reserved FIFO count")?;
        read.i32().context("read maximum FIFO count")?;
        read.string().context("read required permission")?;
        read.i32().context("read maximum delay")?;
        read.i32().context("read sensor flags")?;
        ensure!(
            read.here() <= end,
            "SensorInfo {index} fields extend beyond its parcelable size"
        );
        read.go(end)
            .with_context(|| format!("skip unknown fields in SensorInfo {index}"))?;
        sensors.push(SensorInfo {
            handle,
            name,
            vendor,
            sensor_type,
            type_as_string,
        });
    }
    Ok(sensors)
}

/// Enumerate metadata from the default Sensors AIDL service. This does not
/// initialize its FMQs or activate any sensor.
#[cfg(target_os = "android")]
pub fn list(binder: &crate::driver::Binder) -> Result<Vec<SensorInfo>> {
    let service = crate::service::find(binder, SERVICE)?
        .with_context(|| format!("{SERVICE} is not registered"))?;
    let reply = service
        .transact(GET_SENSORS_LIST, &crate::parcel::Parcel::call(INTERFACE))
        .context("call getSensorsList")?;
    parse_sensor_list(reply.bytes()).context("decode getSensorsList")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parcel::Parcel;

    fn write_sensor(reply: &mut Parcel, handle: i32, appended_field: bool) {
        reply.i32(1); // Parcelable present.
        let size_at = reply.here();
        reply.i32(0); // Filled with the parcelable size below.
        reply.i32(handle); // sensorHandle.
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
        if appended_field {
            reply.i32(123); // A future AIDL field unknown to this client.
        }
        reply.fill(size_at, (reply.here() - size_at) as i32);
    }

    fn sensor_list_reply(count: i32, appended_field: bool) -> Parcel {
        let mut reply = Parcel::default();
        reply.i32(0); // AIDL exception: none.
        reply.i32(count);
        for handle in 0..count {
            write_sensor(&mut reply, handle + 73, appended_field);
        }
        reply
    }

    #[test]
    fn sensor_list_returns_handle_name_and_oem_type() {
        let reply = sensor_list_reply(1, false);
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

    #[test]
    fn sensor_list_accepts_more_than_a_small_fixed_count_limit() {
        let reply = sensor_list_reply(513, false);
        let sensors = parse_sensor_list(reply.bytes()).unwrap();

        assert_eq!(sensors.len(), 513);
        assert_eq!(sensors.last().unwrap().handle, 585);
    }

    #[test]
    fn sensor_list_skips_unknown_appended_parcelable_fields() {
        let reply = sensor_list_reply(1, true);

        assert_eq!(parse_sensor_list(reply.bytes()).unwrap().len(), 1);
    }

    #[test]
    fn sensor_list_rejects_trailing_reply_bytes() {
        let mut reply = sensor_list_reply(1, false);
        reply.i32(123);

        assert!(parse_sensor_list(reply.bytes()).is_err());
    }
}
