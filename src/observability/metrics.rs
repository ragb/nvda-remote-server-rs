// Metric name constants.

// Gauges
pub const ACTIVE_CONNECTIONS: &str = "active_connections";
pub const ACTIVE_CHANNELS: &str = "active_channels";

// Counters
pub const CONNECTIONS_TOTAL: &str = "connections_total";
pub const DISCONNECTIONS_TOTAL: &str = "disconnections_total";
pub const MESSAGES_RELAYED_TOTAL: &str = "messages_relayed_total";
pub const TARGETED_MESSAGES_TOTAL: &str = "targeted_messages_total";
pub const TLS_HANDSHAKE_FAILURES_TOTAL: &str = "tls_handshake_failures_total";
pub const JOIN_FAILURES_TOTAL: &str = "join_failures_total";
pub const KEYS_GENERATED_TOTAL: &str = "keys_generated_total";
pub const BYTES_RELAYED_TOTAL: &str = "bytes_relayed_total";

/// Register metric descriptions with the global recorder.
pub fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge};

    describe_gauge!(ACTIVE_CONNECTIONS, "Number of currently connected clients");
    describe_gauge!(ACTIVE_CHANNELS, "Number of active channels");
    describe_counter!(CONNECTIONS_TOTAL, "Total client connections accepted");
    describe_counter!(DISCONNECTIONS_TOTAL, "Total client disconnections");
    describe_counter!(
        MESSAGES_RELAYED_TOTAL,
        "Total messages relayed between clients"
    );
    describe_counter!(
        TARGETED_MESSAGES_TOTAL,
        "Total targeted (to-field) messages relayed"
    );
    describe_counter!(TLS_HANDSHAKE_FAILURES_TOTAL, "Total TLS handshake failures");
    describe_counter!(JOIN_FAILURES_TOTAL, "Total failed channel join attempts");
    describe_counter!(KEYS_GENERATED_TOTAL, "Total channel keys generated");
    describe_counter!(BYTES_RELAYED_TOTAL, "Total bytes relayed between clients");
}
