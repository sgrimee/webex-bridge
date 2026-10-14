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
    url: Option<String>,
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

const DEVICES_URL: &str = "https://wdm-a.wbx2.com/wdm/api/v1/devices";

fn this_host() -> String {
    device_name()
        .strip_suffix(BRIDGE_SUFFIX)
        .unwrap_or_default()
        .to_owned()
}

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// GET the device list: `(status, body, elapsed)`.
async fn fetch_devices(client: &reqwest::Client, token: &str) -> Result<(u16, Vec<u8>, Duration)> {
    let started = std::time::Instant::now();
    let response = client
        .get(DEVICES_URL)
        .bearer_auth(token)
        .send()
        .await
        .context("WDM device list did not respond")?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .context("WDM device list body did not complete")?;
    Ok((status, body.to_vec(), started.elapsed()))
}

/// Fetch the device list once (bounded at 180 s) and summarize it.
pub async fn device_list_summary(paths: &Paths) -> Result<DeviceSummary> {
    let tokens = auth::fresh_token(paths).await?;
    let (status, body, elapsed) = fetch_devices(&http_client()?, &tokens.access_token).await?;
    let this_host = this_host();
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

/// A stale device this bridge (or the old webex-tui) registered. The URL is
/// kept only to delete it and is never printed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneCandidate {
    pub class: DeviceClass,
    pub modified: Option<DateTime<Utc>>,
    url: String,
}

/// Devices safe to delete: this host's bridge devices except the newest one
/// (the one the daemon reconnects to), and this host's old webex-tui devices.
/// Never another host's devices, other programs' or the user's real clients,
/// and only devices whose URL is a Webex WDM URL. Oldest first.
pub fn prune_candidates(body: &[u8], this_host: &str) -> Result<Vec<PruneCandidate>> {
    let list: DeviceList =
        serde_json::from_slice(body).context("Invalid WDM device-list response")?;
    let mut bridge: Vec<&Device> = Vec::new();
    let mut candidates = Vec::new();
    for device in &list.devices {
        match classify(device, this_host) {
            DeviceClass::BridgeThisHost => bridge.push(device),
            DeviceClass::TuiThisHost => candidates.push(device),
            _ => {}
        }
    }
    // Keep the newest bridge device (unknown times sort as oldest).
    bridge.sort_by_key(|device| std::cmp::Reverse(device.modification_time));
    candidates.extend(bridge.into_iter().skip(1));
    let mut candidates: Vec<PruneCandidate> = candidates
        .into_iter()
        .filter_map(|device| {
            let url = device.url.clone()?;
            wdm_url(&url).then(|| PruneCandidate {
                class: classify(device, this_host),
                modified: device.modification_time,
                url,
            })
        })
        .collect();
    candidates.sort_by_key(|candidate| candidate.modified);
    Ok(candidates)
}

/// Only an https URL on a Webex WDM host may receive the bearer token.
fn wdm_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| host.starts_with("wdm") && host.ends_with(".wbx2.com"))
    })
}

/// Short digest of the candidate set, shown by the dry run and required by
/// `--confirm`, so a set that changed in between is never deleted.
pub fn fingerprint(candidates: &[PruneCandidate]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for candidate in candidates {
        hasher.update(candidate.url.as_bytes());
        hasher.update([0]);
    }
    hasher
        .finalize()
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Dry run (no `confirm`): list the candidates. With `confirm = (count,
/// fingerprint)` matching the current candidates exactly, delete them and
/// report the device list afterwards. Never prints device IDs or URLs.
pub async fn prune(paths: &Paths, confirm: Option<(usize, &str)>) -> Result<String> {
    use std::fmt::Write as _;
    let tokens = auth::fresh_token(paths).await?;
    let client = http_client()?;
    let (status, body, _) = fetch_devices(&client, &tokens.access_token).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("WDM device list returned HTTP {status}");
    }
    let candidates = prune_candidates(&body, &this_host())?;
    let digest = fingerprint(&candidates);
    let mut out = String::new();
    let Some((count, expected)) = confirm else {
        writeln!(
            out,
            "{} stale device(s) would be deleted:",
            candidates.len()
        )?;
        for (index, candidate) in candidates.iter().enumerate() {
            let modified = candidate
                .modified
                .map_or_else(|| "unknown".to_owned(), |time| time.to_rfc3339());
            writeln!(
                out,
                "  #{} {:?} modified {modified}",
                index + 1,
                candidate.class
            )?;
        }
        writeln!(
            out,
            "Kept: the newest bridge device of this host and every other device."
        )?;
        if !candidates.is_empty() {
            writeln!(
                out,
                "To delete exactly these: webex-bridge devices prune --confirm {} {digest}",
                candidates.len()
            )?;
        }
        return Ok(out);
    };
    if count != candidates.len() || expected != digest {
        anyhow::bail!("The stale device set changed since the dry run; run the dry run again");
    }
    let mut deleted = 0;
    for candidate in &candidates {
        let response = client
            .delete(&candidate.url)
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .context("WDM device delete did not respond")?;
        if response.status().is_success() || response.status().as_u16() == 404 {
            deleted += 1;
        } else {
            writeln!(out, "A delete returned HTTP {}", response.status().as_u16())?;
        }
    }
    writeln!(
        out,
        "Deleted {deleted} of {} stale device(s).",
        candidates.len()
    )?;
    let (status, body, elapsed) = fetch_devices(&client, &tokens.access_token).await?;
    let mut summary = summarize(&body, &this_host(), Utc::now())?;
    summary.status = status;
    summary.elapsed = elapsed;
    summary.bytes = body.len();
    write!(out, "{summary}")?;
    Ok(out)
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

    #[test]
    fn prune_keeps_the_newest_bridge_device_and_everything_not_ours() {
        let body = serde_json::json!({"devices": [
            {"url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/old", "name": "host-a-webex-bridge",
             "systemName": "rust-spark-client", "modificationTime": "2026-10-01T00:00:00Z"},
            {"url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/new", "name": "host-a-webex-bridge",
             "systemName": "rust-spark-client", "modificationTime": "2026-10-13T00:00:00Z"},
            {"url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/mid", "name": "host-a-webex-bridge",
             "systemName": "rust-spark-client", "modificationTime": "2026-10-05T00:00:00Z"},
            {"url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/tui", "name": "host-a",
             "systemName": "rust-spark-client", "modificationTime": "2026-09-01T00:00:00Z"},
            {"url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/other-host",
             "name": "host-b-webex-bridge", "systemName": "rust-spark-client"},
            {"url": "https://wdm-a.wbx2.com/wdm/api/v1/devices/mac", "name": "host-a",
             "systemName": "Mac OS X", "deviceType": "MAC"},
            {"url": "https://evil.example/devices/x", "name": "host-a",
             "systemName": "rust-spark-client", "modificationTime": "2026-08-01T00:00:00Z"}
        ]});
        let candidates = prune_candidates(&serde_json::to_vec(&body).unwrap(), "host-a").unwrap();
        let urls: Vec<&str> = candidates.iter().map(|c| c.url.as_str()).collect();
        // Oldest first; the newest bridge device, another host's, the user's
        // Mac and any non-WDM URL are never candidates.
        assert_eq!(
            urls,
            [
                "https://wdm-a.wbx2.com/wdm/api/v1/devices/tui",
                "https://wdm-a.wbx2.com/wdm/api/v1/devices/old",
                "https://wdm-a.wbx2.com/wdm/api/v1/devices/mid",
            ]
        );
        assert_eq!(candidates[0].class, DeviceClass::TuiThisHost);
        // The fingerprint changes with the set and reveals no URL.
        let digest = fingerprint(&candidates);
        assert_eq!(digest.len(), 8);
        assert_ne!(digest, fingerprint(&candidates[1..]));
        assert!(!digest.contains("wdm"));
    }

    #[test]
    fn only_webex_wdm_urls_may_receive_the_token() {
        assert!(wdm_url("https://wdm-a.wbx2.com/wdm/api/v1/devices/x"));
        assert!(wdm_url("https://wdm-r.wbx2.com/wdm/api/v1/devices/x"));
        assert!(!wdm_url("http://wdm-a.wbx2.com/wdm/api/v1/devices/x"));
        assert!(!wdm_url("https://wdm-a.wbx2.com.evil.example/x"));
        assert!(!wdm_url("https://evil.example/wdm"));
    }
}
