import { useEffect, useMemo, useState } from "react";
import {
    Activity,
    AlertTriangle,
    Bell,
    CheckCircle2,
    CircleDot,
    Database,
    Eye,
    Gauge,
    Lock,
    Network,
    Radio,
    Shield,
    ShieldCheck,
    Wifi,
    WifiOff,
    XCircle,
} from "lucide-react";

import {
    getAlerts,
    getAlertStats,
    getHealth,
    getSecurityPolicy,
} from "./services/api";

import { AlertWebSocket } from "./services/websocket";

import "./App.css";


const INITIAL_STATS = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
};


function severityClass(severity) {
    return `severity-${String(
        severity || "INFO"
    ).toLowerCase()}`;
}


function formatTime(timestamp) {
    if (!timestamp) {
        return "--";
    }

    try {
        return new Date(timestamp).toLocaleTimeString();
    } catch {
        return "--";
    }
}


function StatCard({
    title,
    value,
    subtitle,
    icon: Icon,
    className = "",
}) {
    return (
        <div className={`stat-card ${className}`}>
            <div className="stat-card-top">
                <span>{title}</span>

                <div className="stat-icon">
                    <Icon size={19} />
                </div>
            </div>

            <div className="stat-value">
                {value}
            </div>

            <div className="stat-subtitle">
                {subtitle}
            </div>
        </div>
    );
}


function TimelineItem({ alert }) {
    return (
        <div className="timeline-item">
            <div className="timeline-marker" />

            <div className="timeline-content">
                <div className="timeline-top">
                    <strong>
                        {alert.threat_class ||
                            "UNKNOWN THREAT"}
                    </strong>

                    <span
                        className={`severity-badge ${severityClass(
                            alert.severity
                        )}`}
                    >
                        {alert.severity || "INFO"}
                    </span>
                </div>

                <div className="timeline-meta">
                    <span>
                        {formatTime(alert.timestamp)}
                    </span>

                    <span>
                        {alert.source_ip || "N/A"}
                        {" → "}
                        {alert.destination_ip || "N/A"}
                    </span>
                </div>

                <p>
                    {alert.description ||
                        "Threat detected from passive network observations."}
                </p>
            </div>
        </div>
    );
}


function EvidenceItem({
    label,
    value,
}) {
    return (
        <div className="evidence-item">
            <span>{label}</span>

            <code>
                {value}
            </code>
        </div>
    );
}


function App() {
    const [alerts, setAlerts] = useState([]);

    const [stats, setStats] =
        useState(INITIAL_STATS);

    const [backendStatus, setBackendStatus] =
        useState("checking");

    const [websocketStatus, setWebsocketStatus] =
        useState("disconnected");

    const [securityPolicy, setSecurityPolicy] =
        useState(null);

    const [selectedSeverity, setSelectedSeverity] =
        useState("");

    const [selectedThreat, setSelectedThreat] =
        useState("");

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState("");

    const [selectedAlert, setSelectedAlert] =
        useState(null);


    /*
     * Load initial dashboard data.
     */
    useEffect(() => {
        let mounted = true;

        async function loadDashboard() {
            try {
                setLoading(true);
                setError("");

                const [
                    alertData,
                    statsData,
                    healthData,
                    policyData,
                ] = await Promise.all([
                    getAlerts({
                        limit: 100,
                    }),

                    getAlertStats(),

                    getHealth(),

                    getSecurityPolicy(),
                ]);

                if (!mounted) {
                    return;
                }

                setAlerts(
                    Array.isArray(alertData)
                        ? alertData
                        : alertData?.alerts || []
                );

                setStats({
                    ...INITIAL_STATS,
                    ...(statsData || {}),
                });

                setBackendStatus(
                    healthData?.status === "ok"
                        ? "online"
                        : "degraded"
                );

                setSecurityPolicy(
                    policyData
                );
            } catch (err) {
                console.error(err);

                if (mounted) {
                    setBackendStatus(
                        "offline"
                    );

                    setError(
                        "Unable to connect to SENTINEL-X backend."
                    );
                }
            } finally {
                if (mounted) {
                    setLoading(false);
                }
            }
        }

        loadDashboard();

        return () => {
            mounted = false;
        };
    }, []);


    /*
     * Real-time WebSocket alert stream.
     */
    useEffect(() => {
        const client = new AlertWebSocket({
            onAlert: (newAlert) => {
                setAlerts((current) => [
                    newAlert,
                    ...current,
                ].slice(0, 100));

                setStats((current) => {
                    const severity =
                        String(
                            newAlert.severity ||
                                "INFO"
                        ).toLowerCase();

                    return {
                        ...current,

                        total:
                            (current.total || 0) + 1,

                        [severity]:
                            (current[severity] || 0) +
                            1,
                    };
                });
            },

            onStatusChange: (status) => {
                setWebsocketStatus(status);
            },
        });

        client.connect();

        return () => {
            client.disconnect();
        };
    }, []);


    /*
     * Extract available threat classes.
     */
    const threatClasses = useMemo(() => {
        const classes = new Set();

        alerts.forEach((alert) => {
            if (alert.threat_class) {
                classes.add(
                    alert.threat_class
                );
            }
        });

        return Array.from(classes).sort();
    }, [alerts]);


    /*
     * Filter alerts.
     */
    const filteredAlerts = useMemo(() => {
        return alerts.filter((alert) => {
            const severityMatch =
                !selectedSeverity ||
                String(
                    alert.severity
                ).toUpperCase() ===
                    selectedSeverity;

            const threatMatch =
                !selectedThreat ||
                alert.threat_class ===
                    selectedThreat;

            return (
                severityMatch &&
                threatMatch
            );
        });
    }, [
        alerts,
        selectedSeverity,
        selectedThreat,
    ]);


    /*
     * Average risk score.
     */
    const averageRisk = useMemo(() => {
        if (!alerts.length) {
            return 0;
        }

        const total = alerts.reduce(
            (sum, alert) =>
                sum +
                Number(
                    alert.risk_score || 0
                ),
            0
        );

        return Math.round(
            total / alerts.length
        );
    }, [alerts]);


    const isPassive =
        securityPolicy?.read_only_mode === true;


    return (
        <div className="app-shell">

            {/* ───────────────── HEADER ───────────────── */}

            <header className="topbar">

                <div className="brand">

                    <div className="brand-mark">
                        <ShieldCheck size={27} />
                    </div>

                    <div>
                        <h1>
                            SENTINEL-X
                        </h1>

                        <span>
                            AI CYBER THREAT DETECTION
                        </span>
                    </div>

                </div>


                <div className="topbar-status">

                    <div className="system-mode">
                        <Radio size={16} />

                        <span>
                            PASSIVE / READ-ONLY
                        </span>
                    </div>


                    <div
                        className={`connection-badge ${
                            websocketStatus ===
                            "connected"
                                ? "connected"
                                : ""
                        }`}
                    >
                        {websocketStatus ===
                        "connected" ? (
                            <>
                                <Wifi size={15} />
                                LIVE
                            </>
                        ) : (
                            <>
                                <WifiOff
                                    size={15}
                                />

                                {websocketStatus.toUpperCase()}
                            </>
                        )}
                    </div>

                </div>

            </header>


            {/* ───────────────── MAIN ───────────────── */}

            <main className="dashboard">

                {error && (
                    <div className="error-banner">
                        <XCircle size={18} />

                        {error}
                    </div>
                )}


                {/* ───────────────── STATISTICS ───────────────── */}

                <section className="stats-grid">

                    <StatCard
                        title="TOTAL THREATS"
                        value={
                            stats.total ?? 0
                        }
                        subtitle="Detected events"
                        icon={AlertTriangle}
                    />

                    <StatCard
                        title="CRITICAL"
                        value={
                            stats.critical ?? 0
                        }
                        subtitle="Immediate attention"
                        icon={Shield}
                        className="critical-card"
                    />

                    <StatCard
                        title="HIGH"
                        value={
                            stats.high ?? 0
                        }
                        subtitle="High-risk events"
                        icon={Bell}
                    />

                    <StatCard
                        title="AVG RISK"
                        value={`${averageRisk}/100`}
                        subtitle="Current alert window"
                        icon={Gauge}
                    />

                </section>


                {/* ───────────────── MAIN CONTENT ───────────────── */}

                <section className="content-grid">


                    {/* ───────────────── ALERT STREAM ───────────────── */}

                    <div className="panel alert-panel">

                        <div className="panel-header">

                            <div>
                                <h2>
                                    <Activity
                                        size={18}
                                    />

                                    LIVE THREAT STREAM
                                </h2>

                                <p>
                                    Real-time security intelligence
                                </p>
                            </div>


                            <div className="live-indicator">
                                <span />
                                STREAMING
                            </div>

                        </div>


                        {/* Filters */}

                        <div className="filters">

                            <select
                                value={
                                    selectedSeverity
                                }
                                onChange={(event) =>
                                    setSelectedSeverity(
                                        event.target.value
                                    )
                                }
                            >
                                <option value="">
                                    All Severities
                                </option>

                                <option value="CRITICAL">
                                    Critical
                                </option>

                                <option value="HIGH">
                                    High
                                </option>

                                <option value="MEDIUM">
                                    Medium
                                </option>

                                <option value="LOW">
                                    Low
                                </option>

                                <option value="INFO">
                                    Info
                                </option>
                            </select>


                            <select
                                value={
                                    selectedThreat
                                }
                                onChange={(event) =>
                                    setSelectedThreat(
                                        event.target.value
                                    )
                                }
                            >
                                <option value="">
                                    All Threat Types
                                </option>

                                {threatClasses.map(
                                    (threat) => (
                                        <option
                                            key={
                                                threat
                                            }
                                            value={
                                                threat
                                            }
                                        >
                                            {threat}
                                        </option>
                                    )
                                )}

                            </select>

                        </div>


                        {/* Alert list */}

                        <div className="alert-list">

                            {loading ? (

                                <div className="empty-state">

                                    <Activity
                                        className="spin"
                                        size={26}
                                    />

                                    Loading security data...

                                </div>

                            ) : filteredAlerts.length ===
                              0 ? (

                                <div className="empty-state">

                                    <CheckCircle2
                                        size={28}
                                    />

                                    No alerts match the current filters.

                                </div>

                            ) : (

                                filteredAlerts.map(
                                    (
                                        alert,
                                        index
                                    ) => (

                                        <div
                                            className="alert-row"
                                            key={
                                                alert.alert_id ||
                                                `${alert.timestamp}-${index}`
                                            }
                                            onClick={() =>
                                                setSelectedAlert(
                                                    alert
                                                )
                                            }
                                            role="button"
                                            tabIndex={0}
                                            onKeyDown={(
                                                event
                                            ) => {
                                                if (
                                                    event.key ===
                                                        "Enter" ||
                                                    event.key ===
                                                        " "
                                                ) {
                                                    event.preventDefault();

                                                    setSelectedAlert(
                                                        alert
                                                    );
                                                }
                                            }}
                                        >

                                            <div
                                                className={`severity-dot ${severityClass(
                                                    alert.severity
                                                )}`}
                                            />


                                            <div className="alert-main">

                                                <div className="alert-title">

                                                    <strong>
                                                        {alert.threat_class ||
                                                            "UNKNOWN THREAT"}
                                                    </strong>

                                                    <span
                                                        className={`severity-badge ${severityClass(
                                                            alert.severity
                                                        )}`}
                                                    >
                                                        {alert.severity ||
                                                            "INFO"}
                                                    </span>

                                                </div>


                                                <div className="alert-meta">

                                                    <span>
                                                        {alert.source_ip ||
                                                            "Unknown source"}
                                                    </span>

                                                    <span>
                                                        →
                                                    </span>

                                                    <span>
                                                        {alert.destination_ip ||
                                                            "Unknown destination"}
                                                    </span>

                                                    <span>
                                                        {alert.protocol ||
                                                            "N/A"}
                                                    </span>

                                                </div>

                                            </div>


                                            <div className="risk-score">

                                                <strong>
                                                    {alert.risk_score ??
                                                        0}
                                                </strong>

                                                <span>
                                                    RISK
                                                </span>

                                            </div>


                                            <div className="alert-time">
                                                {formatTime(
                                                    alert.timestamp
                                                )}
                                            </div>

                                        </div>

                                    )
                                )

                            )}

                        </div>

                    </div>


                    {/* ───────────────── SIDE COLUMN ───────────────── */}

                    <div className="side-column">


                        {/* Security mode */}

                        <div className="panel">

                            <div className="panel-header compact">

                                <div>
                                    <h2>
                                        <Lock
                                            size={17}
                                        />

                                        SECURITY MODE
                                    </h2>
                                </div>

                            </div>


                            <div
                                className={`security-status ${
                                    isPassive
                                        ? "safe"
                                        : "warning"
                                }`}
                            >

                                {isPassive ? (
                                    <ShieldCheck
                                        size={28}
                                    />
                                ) : (
                                    <AlertTriangle
                                        size={28}
                                    />
                                )}

                                <div>

                                    <strong>
                                        {isPassive
                                            ? "PASSIVE MODE ACTIVE"
                                            : "POLICY UNAVAILABLE"}
                                    </strong>

                                    <span>
                                        {isPassive
                                            ? "Observation only"
                                            : "Verify security policy"}
                                    </span>

                                </div>

                            </div>


                            <div className="policy-grid">

                                <div>
                                    <span>
                                        PROBING
                                    </span>

                                    <strong>
                                        {securityPolicy?.active_probing
                                            ? "ENABLED"
                                            : "BLOCKED"}
                                    </strong>
                                </div>


                                <div>
                                    <span>
                                        SCANNING
                                    </span>

                                    <strong>
                                        {securityPolicy?.active_scanning
                                            ? "ENABLED"
                                            : "BLOCKED"}
                                    </strong>
                                </div>


                                <div>
                                    <span>
                                        BLOCKING
                                    </span>

                                    <strong>
                                        {securityPolicy?.automated_blocking
                                            ? "ENABLED"
                                            : "BLOCKED"}
                                    </strong>
                                </div>


                                <div>
                                    <span>
                                        DECRYPTION
                                    </span>

                                    <strong>
                                        {securityPolicy?.payload_decryption
                                            ? "ENABLED"
                                            : "BLOCKED"}
                                    </strong>
                                </div>

                            </div>

                        </div>


                        {/* System health */}

                        <div className="panel">

                            <div className="panel-header compact">

                                <div>
                                    <h2>
                                        <Network
                                            size={17}
                                        />

                                        SYSTEM HEALTH
                                    </h2>
                                </div>

                            </div>


                            <div className="health-list">

                                <HealthItem
                                    icon={Activity}
                                    name="FastAPI Backend"
                                    status={
                                        backendStatus
                                    }
                                />

                                <HealthItem
                                    icon={Database}
                                    name="PostgreSQL"
                                    status="online"
                                />

                                <HealthItem
                                    icon={Radio}
                                    name="Redis Stream"
                                    status={
                                        websocketStatus ===
                                        "connected"
                                            ? "online"
                                            : "checking"
                                    }
                                />

                                <HealthItem
                                    icon={Wifi}
                                    name="WebSocket"
                                    status={
                                        websocketStatus ===
                                        "connected"
                                            ? "online"
                                            : websocketStatus
                                    }
                                />

                            </div>

                        </div>


                        {/* Threat distribution */}

                        <div className="panel">

                            <div className="panel-header compact">

                                <div>
                                    <h2>
                                        <Eye
                                            size={17}
                                        />

                                        THREAT DISTRIBUTION
                                    </h2>
                                </div>

                            </div>


                            <div className="distribution">

                                <DistributionBar
                                    label="Critical"
                                    value={
                                        stats.critical
                                    }
                                    total={
                                        stats.total
                                    }
                                />

                                <DistributionBar
                                    label="High"
                                    value={
                                        stats.high
                                    }
                                    total={
                                        stats.total
                                    }
                                />

                                <DistributionBar
                                    label="Medium"
                                    value={
                                        stats.medium
                                    }
                                    total={
                                        stats.total
                                    }
                                />

                                <DistributionBar
                                    label="Low"
                                    value={
                                        stats.low
                                    }
                                    total={
                                        stats.total
                                    }
                                />

                            </div>

                        </div>

                    </div>

                </section>


                {/* ───────────────── THREAT ACTIVITY TIMELINE ───────────────── */}

                <section className="panel timeline-panel">

                    <div className="panel-header">

                        <div>
                            <span className="panel-kicker">
                                THREAT ACTIVITY
                            </span>

                            <h2>
                                Detection Timeline
                            </h2>

                            <p>
                                Recent passive detection events
                            </p>
                        </div>


                        <span className="panel-live">
                            LIVE
                        </span>

                    </div>


                    <div className="timeline">

                        {alerts.length === 0 ? (

                            <div className="empty-state">

                                <CheckCircle2
                                    size={28}
                                />

                                No threat activity recorded.

                            </div>

                        ) : (

                            alerts
                                .slice(0, 8)
                                .map(
                                    (
                                        alert,
                                        index
                                    ) => (

                                        <TimelineItem
                                            key={
                                                alert.alert_id ||
                                                `${alert.timestamp}-${index}`
                                            }
                                            alert={
                                                alert
                                            }
                                        />

                                    )
                                )

                        )}

                    </div>

                </section>


            </main>


            {/* ───────────────── ALERT INVESTIGATION DRAWER ───────────────── */}

            {selectedAlert && (

                <div
                    className="drawer-overlay"
                    onClick={() =>
                        setSelectedAlert(
                            null
                        )
                    }
                >

                    <aside
                        className="alert-drawer"
                        onClick={(event) =>
                            event.stopPropagation()
                        }
                    >

                        {/* Drawer header */}

                        <div className="drawer-header">

                            <div>

                                <span className="drawer-kicker">
                                    ALERT INVESTIGATION
                                </span>

                                <h2>
                                    {selectedAlert.threat_class ||
                                        "UNKNOWN THREAT"}
                                </h2>

                            </div>


                            <button
                                className="drawer-close"
                                onClick={() =>
                                    setSelectedAlert(
                                        null
                                    )
                                }
                                aria-label="Close alert details"
                            >
                                ×
                            </button>

                        </div>


                        {/* Severity */}

                        <div className="drawer-severity">

                            <span
                                className={`severity-badge ${severityClass(
                                    selectedAlert.severity
                                )}`}
                            >
                                {selectedAlert.severity ||
                                    "INFO"}
                            </span>

                            <strong>
                                Risk{" "}
                                {selectedAlert.risk_score ??
                                    0}
                                /100
                            </strong>

                        </div>


                        {/* Network context */}

                        <section className="evidence-section">

                            <h3>
                                NETWORK CONTEXT
                            </h3>

                            <div className="evidence-grid">

                                <EvidenceItem
                                    label="SOURCE IP"
                                    value={
                                        selectedAlert.source_ip ||
                                        "N/A"
                                    }
                                />

                                <EvidenceItem
                                    label="DESTINATION IP"
                                    value={
                                        selectedAlert.destination_ip ||
                                        "N/A"
                                    }
                                />

                                <EvidenceItem
                                    label="SOURCE PORT"
                                    value={
                                        selectedAlert.source_port ??
                                        "N/A"
                                    }
                                />

                                <EvidenceItem
                                    label="DESTINATION PORT"
                                    value={
                                        selectedAlert.destination_port ??
                                        "N/A"
                                    }
                                />

                                <EvidenceItem
                                    label="PROTOCOL"
                                    value={
                                        selectedAlert.protocol ||
                                        "N/A"
                                    }
                                />

                                <EvidenceItem
                                    label="DETECTOR"
                                    value={
                                        selectedAlert.detector ||
                                        "N/A"
                                    }
                                />

                            </div>

                        </section>


                        {/* Detection result */}

                        <section className="evidence-section">

                            <h3>
                                DETECTION RESULT
                            </h3>

                            <div className="description-box">

                                {selectedAlert.description ||
                                    "No description available."}

                            </div>

                        </section>


                        {/* Confidence */}

                        <section className="evidence-section">

                            <h3>
                                CONFIDENCE
                            </h3>

                            <div className="confidence-container">

                                <div className="confidence-value">

                                    {Math.round(
                                        Number(
                                            selectedAlert.confidence ||
                                                0
                                        ) * 100
                                    )}
                                    %

                                </div>


                                <div className="confidence-track">

                                    <div
                                        className="confidence-fill"
                                        style={{
                                            width: `${Math.min(
                                                100,
                                                Number(
                                                    selectedAlert.confidence ||
                                                        0
                                                ) * 100
                                            )}%`,
                                        }}
                                    />

                                </div>

                            </div>

                        </section>


                        {/* Evidence */}

                        <section className="evidence-section">

                            <h3>
                                DETECTION EVIDENCE
                            </h3>

                            <pre className="evidence-json">
                                {JSON.stringify(
                                    selectedAlert.evidence ||
                                        {},
                                    null,
                                    2
                                )}
                            </pre>

                        </section>


                        {/* Metadata */}

                        <section className="evidence-section">

                            <h3>
                                ALERT METADATA
                            </h3>

                            <div className="metadata-list">

                                <div>

                                    <span>
                                        Alert ID
                                    </span>

                                    <code>
                                        {selectedAlert.alert_id ||
                                            "N/A"}
                                    </code>

                                </div>


                                <div>

                                    <span>
                                        Status
                                    </span>

                                    <strong>
                                        {selectedAlert.status ||
                                            "NEW"}
                                    </strong>

                                </div>


                                <div>

                                    <span>
                                        Timestamp
                                    </span>

                                    <code>
                                        {selectedAlert.timestamp ||
                                            "N/A"}
                                    </code>

                                </div>

                            </div>

                        </section>


                        {/* Passive security footer */}

                        <div className="drawer-footer">

                            <ShieldCheck size={16} />

                            PASSIVE OBSERVATION ONLY

                        </div>

                    </aside>

                </div>

            )}


            {/* ───────────────── FOOTER ───────────────── */}

            <footer className="footer">

                <span>
                    SENTINEL-X • AI-BASED CYBER THREAT DETECTION
                </span>


                <span>

                    <CircleDot size={12} />

                    METADATA ONLY

                </span>


                <span>
                    NO ACTIVE NETWORK ACTIONS
                </span>

            </footer>

        </div>
    );
}


function HealthItem({
    icon: Icon,
    name,
    status,
}) {
    const online =
        status === "online";

    return (
        <div className="health-item">

            <div className="health-name">

                <Icon size={16} />

                {name}

            </div>


            <div
                className={`health-status ${
                    online
                        ? "online"
                        : "offline"
                }`}
            >

                <span />

                {status}

            </div>

        </div>
    );
}


function DistributionBar({
    label,
    value,
    total,
}) {
    const percentage =
        total > 0
            ? Math.min(
                  100,
                  Math.round(
                      (value / total) *
                          100
                  )
              )
            : 0;

    return (
        <div className="distribution-item">

            <div className="distribution-label">

                <span>
                    {label}
                </span>

                <strong>
                    {value}
                </strong>

            </div>


            <div className="distribution-track">

                <div
                    className="distribution-fill"
                    style={{
                        width: `${percentage}%`,
                    }}
                />

            </div>

        </div>
    );
}


export default App;