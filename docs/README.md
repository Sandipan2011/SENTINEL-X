# SENTINEL-X

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript" />
  <img src="https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" alt="React" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Threat%20Detection-Cyber%20Security-7C3AED?style=for-the-badge" alt="Cyber Security" />
</p>

<p align="center">
  <strong>Passive network telemetry analysis for detecting suspicious behavior without decrypting traffic.</strong>
</p>

---

## Overview

SENTINEL-X is a read-only cyber threat detection prototype designed for unidirectional IP telemetry. It ingests passively observed flow metadata, extracts signal-rich features, and raises threat alerts based on explainable heuristics rather than opaque black-box models.

The project focuses on building a lightweight, observable security monitoring workflow that can process metadata-rich network events and highlight suspicious patterns in near real time.

---

## Why this project exists

Traditional monitoring systems often depend on deep packet inspection or active probing. SENTINEL-X takes a different approach:

- Passive-only observation
- Metadata-first analysis
- Explainable detection logic
- Suitable for prototype and demonstration environments
- No payload inspection or decryption

---

## Threat classes covered

- Volumetric and protocol DDoS
- Botnet beaconing
- DNS tunneling and DGA-like domain behavior
- TLS-based encrypted-session malware indicators
- Reconnaissance and port scanning
- Data exfiltration

---

## Detection model

The current prototype does not rely on external machine-learning artifacts or training pipelines. Instead, it uses deterministic heuristics and streaming aggregation over short time windows.

### Example signals

- High source fan-out across destination ports
- Sustained packet and byte bursts in rolling windows
- Regular timing patterns in repeated flows
- Long or high-entropy DNS labels
- TLS fingerprint anomalies based on metadata
- Strong outbound-to-inbound byte asymmetry

This keeps the system transparent, easy to reason about, and useful for research, learning, and prototype security monitoring.

---

## Architecture

```text
SENTINEL-X/
├── backend/             # Detection engine, APIs, streaming, alerts, and storage
├── frontend/            # React dashboard
├── replay/              # Synthetic traffic generation and replay tools
├── tests/               # Integration and validation tests
├── docs/                # Project documentation
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

The backend provides the detection pipeline, alert handling, API routes, and WebSocket services. The frontend provides a lightweight browser dashboard for viewing activity and alerts. Replay utilities support repeatable demonstrations using synthetic traffic.

---

## Runtime and API

The application exposes:

- `/health` — health checks
- `/api/alerts` — recent detections
- `/api/replay` — synthetic attack replay
- `/dashboard` — browser dashboard

---

## Quick start

### Using Docker Compose

```bash
git clone https://github.com/Sandipan2011/SENTINEL-X.git
cd SENTINEL-X
cp .env.example .env
docker compose up --build
```

After the services start, open the dashboard at the address configured by the local deployment.

### Local development

The backend and frontend can also be run independently. Refer to the service configuration and package files in `backend/` and `frontend/` for the relevant development commands.

---

## Security constraints

SENTINEL-X intentionally follows a conservative, read-only design:

- Passive-only observation
- Metadata-only analysis for encrypted sessions
- No payload decryption
- No active scanning
- No mitigation execution
- No inbox-channel response behavior

Use synthetic or authorized telemetry only when testing the project.

---

## Performance note

The prototype was validated locally against replayed synthetic traffic at a sustained rate of roughly 250 flows in a short stream. This is intended as a functional demonstration benchmark, not a production-scale capacity guarantee.

---

## Technology stack

- **Backend:** Python
- **Frontend:** JavaScript, React, Vite, CSS
- **Interfaces:** HTTP APIs and WebSockets
- **Deployment:** Docker and Docker Compose
- **Analysis:** Flow features, streaming windows, deterministic detection heuristics

---

## Project status

SENTINEL-X is an active prototype for experimentation, learning, and security research. Future improvements may include richer telemetry support, stronger test coverage, additional detection strategies, improved dashboard visualizations, and production-oriented observability.

---

## Contributing

Contributions are welcome. Useful areas include:

- Improving detection accuracy and explainability
- Adding tests and replay scenarios
- Enhancing the dashboard
- Improving documentation
- Supporting additional telemetry formats

Please open an issue before starting a large change so the proposed direction can be discussed.

---

## Disclaimer

SENTINEL-X is provided for educational, research, and authorized defensive-monitoring purposes. Do not use it to inspect or interact with networks without permission.

<p align="center">
  <img src="https://img.shields.io/badge/Status-Prototype%20Demo-10B981?style=for-the-badge" alt="Prototype Demo" />
</p>
