//! Compile-time bridge-only TUI contract coverage.
//!
//! This target is invoked with only the `client` feature. The two async
//! functions below are never called, so this test starts no UDS client; their
//! bodies make Rust type-check each public operation the TUI will use.

use webex_bridge::client::{
    events::{BridgeEvent, EventStream},
    ui::{
        Continuity, Message, MessageBodyInput, MessagePage, MessageRead, Person, PersonRead, Room,
        Status, Team, ThreadChildren, ThreadParent, UiClient,
    },
    BridgeClient, ClientError,
};

async fn typed_bootstrap_contract(
    bridge: &BridgeClient,
    secret_hash: &str,
    secret: &str,
) -> std::result::Result<UiClient, ClientError> {
    let _: Status = bridge.status().await?;
    bridge.pair_ui(secret_hash).await?;
    let client = bridge.create_ui_session(secret).await?;
    // Lease renewal keeps the same token; its refusals are typed.
    if let Err(error) = client.renew().await {
        let _: bool = error.is_pairing_removed() || error.is_session_cap_reached();
    }
    Ok(client)
}

async fn typed_tui_intent_contract(
    client: &UiClient,
    body: &MessageBodyInput,
) -> std::result::Result<(), ClientError> {
    // TUI intents 1/2: Initialize and WhoAmI.
    let _: Person = client.me().await?;
    let _: Person = client.me().await?;
    // Intent 3: ListAllRooms.
    let _: Vec<Room> = client.rooms().await?;
    // Intent 4: UpdateRoom.
    let _: Room = client.room("room-id").await?;
    // Intent 5: UpdateTeam.
    let _: Team = client.team("team-id").await?;
    // Intent 6: UpdatePerson.
    let _: PersonRead = client.person_read("person-id").await?;
    // Intent 7: ListMessagesInRoom.
    let _: MessagePage = client
        .room_messages_page("room-id", Some("opaque-cursor"), Some(50))
        .await?;
    // Intent 8: UpdateMessage.
    let _: MessageRead = client.message_read("message-id").await?;
    // Intent 9: UpdateChildrenMessages.
    let _: ThreadChildren = client
        .thread_children("parent-id", Some("opaque-cursor"), Some(50))
        .await?;
    // Intent 10: SendMessage. The body form preserves plain-text/Markdown kind.
    let _: Message = client
        .create_message_body("room-id", Some("parent-id"), body)
        .await?;
    // Intent 11: EditMessage.
    let _: Message = client
        .edit_message_body("message-id", "room-id", body)
        .await?;
    // Intent 12: DeleteMessage.
    client.delete_message("message-id").await?;
    // Intent 13: LeaveRoom.
    client.leave_room("room-id").await?;

    // The remaining read/event contract required for snapshot fencing and
    // lifecycle resync is also public in the client-only build.
    let _: Continuity = client.continuity().await?;
    let _: ThreadParent = client.thread_parent("message-id").await?;
    let _: EventStream = client.events().await?;
    Ok(())
}

#[test]
fn public_client_contract_covers_all_thirteen_tui_intents() {
    // Referencing the futures type-checks their exact typed method calls while
    // retaining this as a no-I/O compile contract.
    let _ = typed_bootstrap_contract;
    let _ = typed_tui_intent_contract;
    let _ = BridgeClient::discover;
    let _ = BridgeClient::socket;
    let _ = UiClient::lease_ttl;
    let _ = BridgeEvent::requires_resync;
}

/// The TUI shares the daemon's own write bounds instead of copying them.
#[test]
fn write_bounds_are_exported_for_client_only_builds() {
    use webex_bridge::dto::{
        valid_message_body, valid_resource_id, MAX_MESSAGE_BODY_BYTES, MAX_RESOURCE_ID_BYTES,
    };
    assert_eq!(MAX_MESSAGE_BODY_BYTES, 7439);
    assert_eq!(MAX_RESOURCE_ID_BYTES, 1024);
    // 3719 two-byte characters + 1 byte = exactly the limit.
    let exact = "é".repeat(3719) + "x";
    assert!(valid_message_body(&exact));
    assert!(!valid_message_body(&(exact + "x")));
    assert!(!valid_message_body(""));
    assert!(!valid_message_body("nul\0"));
    assert!(valid_resource_id(&"x".repeat(MAX_RESOURCE_ID_BYTES)));
    assert!(!valid_resource_id(&"x".repeat(MAX_RESOURCE_ID_BYTES + 1)));
    assert!(!valid_resource_id(""));
    assert!(!valid_resource_id("a\nb"));
}
