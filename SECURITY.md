# Security

RAMMesh is a tested prototype for a trusted private network. It has not received an independent security audit and should not be the sole holder of indispensable data. Handles are ephemeral and lost when their TLS session ends. A donor crash, sleep or network failure can invalidate them.

Use mutually authenticated TLS, a private CA, owner-only key files and conservative donation limits. Keep the CA key offline. Any client-auth certificate signed by the configured CA can connect. Individual certificate revocation and per-device quotas are not implemented. Never expose a development donor to the public Internet.

The wired pool's RAM guarantee does not cover every transient TLS buffer, OS hibernation, privileged inspection or physical attacks. See [the README](README.md) for exact limits.

For a suspected vulnerability, use GitHub private vulnerability reporting if available. Otherwise open a minimal issue requesting a private reporting channel, without exploit details, credentials, memory contents or personal logs. Include the affected version and general component. No response-time or production-support guarantee is offered.
