//! UI-neutral thread grouping from canonical mirror message metadata.
//! Missing parents are represented as an explicit group instead of dropped.

use std::collections::BTreeMap;

/// Non-sensitive metadata sufficient to order/group messages for a UI client.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ThreadMessage {
    /// Canonical REST message ID.
    pub id: String,
    /// Canonical parent ID when this is a reply.
    pub parent_id: Option<String>,
    /// RFC3339 creation timestamp (indexed plaintext metadata).
    pub created_at: String,
}

/// Messages belonging to one thread, ordered by creation time then ID.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Thread {
    /// Parent message ID, or missing parent ID for an orphaned reply group.
    pub root_id: String,
    /// Whether `root_id` itself was unavailable in the current page/mirror view.
    pub missing_root: bool,
    /// Ordered canonical messages.
    pub messages: Vec<ThreadMessage>,
}

/// Group room messages by parent and preserve threads whose root is absent.
pub fn group(messages: impl IntoIterator<Item = ThreadMessage>) -> Vec<Thread> {
    let mut all: Vec<_> = messages.into_iter().collect();
    all.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    let ids: std::collections::HashSet<String> =
        all.iter().map(|message| message.id.clone()).collect();
    let mut groups: BTreeMap<String, Thread> = BTreeMap::new();
    for message in all {
        let root_id = message
            .parent_id
            .clone()
            .unwrap_or_else(|| message.id.clone());
        let missing_root = message
            .parent_id
            .as_ref()
            .is_some_and(|parent| !ids.contains(parent));
        let thread = groups.entry(root_id.clone()).or_insert_with(|| Thread {
            root_id,
            missing_root,
            messages: Vec::new(),
        });
        thread.missing_root |= missing_root;
        thread.messages.push(message);
    }
    let mut threads: Vec<_> = groups.into_values().collect();
    for thread in &mut threads {
        thread.messages.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
    }
    threads.sort_by(|a, b| {
        a.messages
            .first()
            .map(|message| &message.created_at)
            .cmp(&b.messages.first().map(|message| &message.created_at))
            .then_with(|| a.root_id.cmp(&b.root_id))
    });
    threads
}

#[cfg(test)]
mod tests {
    use super::*;
    fn message(id: &str, parent: Option<&str>, created: &str) -> ThreadMessage {
        ThreadMessage {
            id: id.into(),
            parent_id: parent.map(str::to_owned),
            created_at: created.into(),
        }
    }

    #[test]
    fn groups_out_of_order_reply_with_its_root() {
        let threads = group([
            message("reply", Some("root"), "2026-10-08T12:01:00Z"),
            message("root", None, "2026-10-08T12:00:00Z"),
        ]);
        assert_eq!(threads.len(), 1);
        assert!(!threads[0].missing_root);
        assert_eq!(
            threads[0]
                .messages
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            ["root", "reply"]
        );
    }

    #[test]
    fn preserves_missing_parent_thread() {
        let threads = group([message("reply", Some("missing"), "2026-10-08T12:01:00Z")]);
        assert!(threads[0].missing_root);
        assert_eq!(threads[0].root_id, "missing");
    }
}
