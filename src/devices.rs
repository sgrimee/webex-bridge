//! Metadata-only summary of the account's Webex (WDM) devices, for diagnosing
//! a slow device list. It never prints device IDs, URLs, names or hostnames:
//! only counts per class, an age histogram and the response size and time.

use crate::{auth, paths::Paths, supervisor::device_name};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::{fmt, time::Duration};

/// System name webex-rust registers its devices with (bridge and old TUI).
const RUST_SYSTEM_NAME: &str = "rust-spark-client";
/// Name suffix of the bridge's devices (`<host>-webex-bridge`).
const BRIDGE_SUFFIX: &str = "-webex-bridge";

#[derive(Deserialize)]
struct DeviceList {
    #[serde(default)]
    devices: Vec<Device>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Device {
    name: Option<String>,
    system_name: Option<String>,
    device_type: Option<String>,
    modification_time: Option<DateTime<Utc>>,
}

/// Who registered a device, as far as its metadata tells.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DeviceClass {
    /// webex-rust device named `<this host>-webex-bridge`.
    BridgeThisHost,
    /// webex-rust device named `<other host>-webex-bridge`.
    BridgeOtherHost,
    /// webex-rust device named exactly this host (the pre-bridge webex-tui).
    TuiThisHost,
    /// Any other webex-rust device (another host's TUI, other programs).
    OtherRustClient,
    /// Not registered by webex-rust: the user's real Webex clients.
    Other,
}

/// Age buckets by `modificationTime`.
pub const AGE_BUCKETS: [(&str, Option<i64>); 6] = [
    ("<1d", Some(1)),
    ("1-7d", Some(7)),
    ("7-30d", Some(30)),
    ("30-90d", Some(90)),
    (">90d", None),
    ("unknown", None),
];

/// Per-class counts with an age histogram (indexes into [`AGE_BUCKETS`]).
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ClassSummary {
    pub count: usize,
    pub ages: [usize; 6],
}

/// The whole summary. Contains no identifiers.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct DeviceSummary {
    pub status: u16,
    pub elapsed: Duration,
    pub bytes: usize,
    pub classes: Vec<(DeviceClass, ClassSummary)>,
    /// Device types of the `Other` class, with counts.
    pub other_types: Vec<(String, usize)>,
}

fn classify(device: &Device, this_host: &str) -> DeviceClass {
    let rust = device.system_name.as_deref() == Some(RUST_SYSTEM_NAME);
    let name = device.name.as_deref().unwrap_or_default();
    match (rust, name.strip_suffix(BRIDGE_SUFFIX)) {
        (true, Some(host)) if host == this_host => DeviceClass::BridgeThisHost,
        (true, Some(_)) => DeviceClass::BridgeOtherHost,
        (true, None) if name == this_host => DeviceClass::TuiThisHost,
        (true, None) => DeviceClass::OtherRustClient,
        (false, _) => DeviceClass::Other,
    }
}

fn age_bucket(modified: Option<DateTime<Utc>>, now: DateTime<Utc>) -> usize {
    let Some(modified) = modified else {
        return 5;
    };
    let days = (now - modified).num_days();
    AGE_BUCKETS
        .iter()
        .take(4)
        .position(|(_, limit)| limit.is_some_and(|limit| days < limit))
        .unwrap_or(4)
}

/// Summarize a WDM device-list body. Pure, for tests.
pub fn summarize(body: &[u8], this_host: &str, now: DateTime<Utc>) -> Result<DeviceSummary> {
    let list: DeviceList =
        serde_json::from_slice(body).context("Invalid WDM device-list response")?;
    let mut classes: Vec<(DeviceClass, ClassSummary)> = Vec::new();
    let mut other_types: Vec<(String, usize)> = Vec::new();
    for device in &list.devices {
        let class = classify(device, this_host);
        let index = match classes.iter().position(|(known, _)| *known == class) {
            Some(index) => index,
            None => {
                classes.push((class, ClassSummary::default()));
                classes.len() - 1
            }
        };
        let summary = &mut classes[index].1;
        summary.count += 1;
        summary.ages[age_bucket(device.modification_time, now)] += 1;
        if class == DeviceClass::Other {
            // Device types are a short fixed vocabulary (DESKTOP, UC, ...);
            // bound them anyway so remote text cannot flood the output.
            let kind: String = device
                .device_type
                .as_deref()
                .unwrap_or("unknown")
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(24)
                .collect();
            match other_types.iter_mut().find(|(known, _)| *known == kind) {
                Some((_, count)) => *count += 1,
                None => other_types.push((kind, 1)),
            }
        }
    }
    classes.sort_by_key(|(class, _)| *class);
    other_types.sort();
    Ok(DeviceSummary {
        classes,
        other_types,
        ..DeviceSummary::default()
    })
}

impl fmt::Display for DeviceSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total: usize = self.classes.iter().map(|(_, s)| s.count).sum();
        writeln!(
            f,
            "WDM GET /devices: HTTP {} in {:.1} s, {} bytes, {total} devices",
            self.status,
            self.elapsed.as_secs_f64(),
            self.bytes
        )?;
        for (class, summary) in &self.classes {
            let ages = AGE_BUCKETS
                .iter()
                .zip(summary.ages)
                .map(|((label, _), count)| format!("{label}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(f, "  {class:?}: {} ({ages})", summary.count)?;
        }
        if !self.other_types.is_empty() {
            let types = self
                .other_types
                .iter()
                .map(|(kind, count)| format!("{kind}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(f, "  Other by type: {types}")?;
        }
        Ok(())
    }
}

/// Fetch the device list once (bounded at 180 s) and summarize it.
pub async fn device_list_summary(paths: &Paths) -> Result<DeviceSummary> {
    let tokens = auth::fresh_token(paths).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let started = std::time::Instant::now();
    let response = client
        .get("https://wdm-a.wbx2.com/wdm/api/v1/devices")
        .bearer_auth(tokens.access_token)
        .send()
        .await
        .context("WDM device list did not respond")?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .context("WDM device list body did not complete")?;
    let elapsed = started.elapsed();
    let this_host = device_name()
        .strip_suffix(BRIDGE_SUFFIX)
        .unwrap_or_default()
        .to_owned();
    let mut summary = if (200..300).contains(&status) {
        summarize(&body, &this_host, Utc::now())?
    } else {
        DeviceSummary::default()
    };
    summary.status = status;
    summary.elapsed = elapsed;
    summary.bytes = body.len();
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_devices_and_buckets_ages_without_identifiers() {
        let now: DateTime<Utc> = "2026-10-14T00:00:00Z".parse().unwrap();
        let body = serde_json::json!({"devices": [
            {"name": "host-a-webex-bridge", "systemName": "rust-spark-client",
             "modificationTime": "2026-10-13T12:00:00Z", "url": "https://secret/device/1"},
            {"name": "host-a-webex-bridge", "systemName": "rust-spark-client",
             "modificationTime": "2026-05-01T00:00:00Z"},
            {"name": "host-b-webex-bridge", "systemName": "rust-spark-client"},
            {"name": "host-a", "systemName": "rust-spark-client",
             "modificationTime": "2026-10-01T00:00:00Z"},
            {"name": "laptop", "systemName": "rust-spark-client",
             "modificationTime": "2026-10-10T00:00:00Z"},
            {"name": "Sam's Mac", "systemName": "Mac OS X", "deviceType": "DESKTOP",
             "modificationTime": "2026-10-13T18:00:00Z"},
            {"name": "phone", "systemName": "iOS", "deviceType": "UC\nX=1"}
        ]});
        let summary = summarize(&serde_json::to_vec(&body).unwrap(), "host-a", now).unwrap();
        let class = |wanted: DeviceClass| {
            summary
                .classes
                .iter()
                .find(|(class, _)| *class == wanted)
                .map(|(_, s)| (s.count, s.ages))
                .unwrap()
        };
        assert_eq!(class(DeviceClass::BridgeThisHost), (2, [1, 0, 0, 0, 1, 0]));
        assert_eq!(class(DeviceClass::BridgeOtherHost), (1, [0, 0, 0, 0, 0, 1]));
        assert_eq!(class(DeviceClass::TuiThisHost), (1, [0, 0, 1, 0, 0, 0]));
        assert_eq!(class(DeviceClass::OtherRustClient), (1, [0, 1, 0, 0, 0, 0]));
        assert_eq!(class(DeviceClass::Other), (2, [1, 0, 0, 0, 0, 1]));
        // Remote device types are reduced to bounded alphanumerics.
        assert_eq!(
            summary.other_types,
            vec![("DESKTOP".to_string(), 1), ("UCX1".to_string(), 1)]
        );
        let printed = summary.to_string();
        for leak in ["host-a", "host-b", "laptop", "Sam", "phone", "secret"] {
            assert!(!printed.contains(leak), "{leak} in {printed}");
        }
    }
}
