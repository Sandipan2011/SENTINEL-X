# SENTINEL-X

SENTINEL-X is a read-only cyber threat detection prototype for unidirectional IP telemetry. It ingests passively observed flow metadata, extracts signal-rich features, and raises threat alerts without any active return path or payload decryption.

## Threat classes covered

- Volumetric and protocol DDoS
- Botnet beaconing
- DNS tunneling and DGA-style domains
- Encrypted-sessions malware using TLS metadata only
- Reconnaissance and port scanning
- Data exfiltration

## Runtime model

The current prototype does not depend on external ML training artifacts. It uses deterministic, explainable heuristics and streaming aggregations over short windows, which is appropriate for a fast prototype and is intentionally read-only.

### Example detection signals

- high source fan-out across destination ports
- sustained packet and byte bursts over a rolling window
- regular inter-arrival timing in repeated flows
- long or high-entropy DNS labels
- TLS fingerprint anomalies with low-version metadata
- strong outbound-to-inbound byte asymmetry

## Replay and API

The app exposes:

- `/health` for health checks
- `/api/alerts` for the most recent alerts
- `/api/replay` for synthetic attack replay
- `/dashboard` for a lightweight browser dashboard

## Throughput note

The prototype was validated locally against replayed synthetic traffic with a sustained rate of roughly 250 flows in a short stream, which is suitable for a functional prototype demonstration.

## Security constraints

- passive-only observation
- metadata-only analysis for encrypted sessions
- no decryption or inbox-channel response
- no active scan or mitigation execution
