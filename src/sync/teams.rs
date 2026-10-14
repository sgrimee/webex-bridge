//! Background team-name hydration, so UI team reads are mirror hits instead
//! of one REST call each. Paced like the history sweep (one GET per pause),
//! bounded per step, and sharing the API's in-memory negative cache: a team
//! the account cannot read is not asked again within that cache's TTL, by
//! either side. Inaccessible teams are never written to the mirror.

use crate::{
    api::{TeamMiss, TeamMisses},
    diagnostics,
    mirror::SharedMirror,
    sync::history::WebexRest,
};
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

/// Teams looked up per hydration step.
pub const TEAM_BATCH: usize = 20;

/// Pause between team lookups.
pub const TEAM_PAUSE: Duration = Duration::from_secs(1);

/// Missing member-room teams considered per step (inaccessible ones are
/// skipped through the negative cache, so look past them).
const TEAM_SCAN: usize = 1000;

/// Outcome counts of one step (metadata only).
#[derive(Debug, Default, Eq, PartialEq)]
pub struct TeamStep {
    pub hydrated: usize,
    pub inaccessible: usize,
    pub failed: usize,
    /// Missing teams still not tried (not in the negative cache) after this step.
    pub remaining: usize,
}

/// Look up at most `batch` missing teams, pausing `pause` between lookups.
/// An authentication failure stops the step and is returned.
pub async fn hydrate_teams_step(
    mirror: &SharedMirror,
    rest: &WebexRest,
    misses: &TeamMisses,
    batch: usize,
    pause: Duration,
) -> Result<TeamStep> {
    let missing = mirror.with(|db| db.teams_missing(TEAM_SCAN)).await?;
    let todo: Vec<String> = missing
        .into_iter()
        .filter(|team_id| misses.get(team_id).is_none())
        .collect();
    let mut step = TeamStep {
        remaining: todo.len().saturating_sub(batch),
        ..TeamStep::default()
    };
    for (index, team_id) in todo.into_iter().take(batch).enumerate() {
        if index > 0 {
            sleep(pause).await;
        }
        match rest.team(&team_id).await {
            Ok(Some(team)) if team.id == team_id => {
                mirror.with(move |db| db.upsert_team(&team)).await?;
                step.hydrated += 1;
            }
            Ok(Some(_)) => {
                misses.record(&team_id, TeamMiss::Unavailable).await;
                step.failed += 1;
            }
            Ok(None) => {
                misses.record(&team_id, TeamMiss::NotFound).await;
                step.inaccessible += 1;
            }
            Err(error) if error.to_string().contains("auth_required") => return Err(error),
            Err(_) => {
                misses.record(&team_id, TeamMiss::Unavailable).await;
                step.failed += 1;
            }
        }
    }
    if step != TeamStep::default() {
        diagnostics::debug(format_args!(
            "sync.teams hydrated={} inaccessible={} failed={} remaining={}",
            step.hydrated, step.inaccessible, step.failed, step.remaining
        ));
    }
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::Mirror;
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn team_id(n: u32) -> String {
        STANDARD_NO_PAD.encode(format!(
            "ciscospark://us/TEAM/00000000-0000-4000-8000-{:012}",
            900 + n
        ))
    }

    fn room(id: &str, team: Option<&str>) -> webex::Room {
        webex::Room {
            id: id.into(),
            title: Some("private title".into()),
            room_type: "group".into(),
            is_locked: false,
            team_id: team.map(str::to_owned),
            last_activity: "2026-10-08T12:00:00Z".into(),
            creator_id: "person".into(),
            created: "2026-10-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn missing_team_names_are_hydrated_and_inaccessible_ones_not_asked_again() {
        let server = MockServer::start().await;
        let (readable, hidden, broken) = (team_id(1), team_id(2), team_id(3));
        Mock::given(method("GET"))
            .and(path(format!("/v1/teams/{readable}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": readable, "name": "Readable team", "created": "2026-10-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/teams/{hidden}")))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/teams/{broken}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let rest =
            WebexRest::for_tests(reqwest::Url::parse(&format!("{}/v1/", server.uri())).unwrap())
                .unwrap();
        let mut mirror = Mirror::in_memory([44_u8; 32]).unwrap();
        for (n, team) in [&readable, &hidden, &broken, &readable].iter().enumerate() {
            mirror
                .upsert_room(&room(&format!("room-{n}"), Some(team)), true)
                .unwrap();
        }
        // A room without a team and a former room's team are never asked.
        mirror.upsert_room(&room("room-solo", None), true).unwrap();
        mirror
            .upsert_room(&room("room-left", Some(&team_id(4))), false)
            .unwrap();
        let mirror = SharedMirror::new(mirror);
        let misses = TeamMisses::default();

        let step = hydrate_teams_step(&mirror, &rest, &misses, 20, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            step,
            TeamStep {
                hydrated: 1,
                inaccessible: 1,
                failed: 1,
                remaining: 0
            }
        );
        let readable_name = mirror
            .with({
                let id = readable.clone();
                move |db| db.ui_team(&id)
            })
            .await
            .unwrap()
            .unwrap()
            .name;
        assert_eq!(readable_name.as_deref(), Some("Readable team"));
        assert_eq!(misses.get(&hidden), Some(TeamMiss::NotFound));
        assert_eq!(misses.get(&broken), Some(TeamMiss::Unavailable));
        // Nothing left to ask: the next step makes no REST call.
        assert_eq!(
            hydrate_teams_step(&mirror, &rest, &misses, 20, Duration::ZERO)
                .await
                .unwrap(),
            TeamStep::default()
        );
    }
}
