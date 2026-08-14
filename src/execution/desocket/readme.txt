NEXSIZ :: execution/desocket

Protocol-level connection reset without full reconnect.

Implements ProtocolReset trait and builtin strategies for
FTP, SMTP, MQTT, HTTP, plus binary/null backends and
SocketState tracking.

Used by workers when connection_reuse is enabled and the
session needs a clean slate cheaper than TCP teardown +
rehandshake. Feeds desocket counters and cost-aware energy.
