from typing import Any

from backend.alerts.schema import SentinelAlert

from backend.detection.ddos.syn_flood import (
    SynFloodDetector,
)

from backend.detection.ddos.volumetric import (
    VolumetricDDoSDetector,
)

from backend.detection.recon.port_scan import (
    PortScanDetector,
)

from backend.detection.beacon.beacon_detector import (
    BeaconDetector,
)

from backend.detection.dns.dns_detector import (
    DNSDetector,
)

from backend.detection.tls.tls_detector import (
    TLSDetector,
)

from backend.detection.exfiltration.exfil_detector import (
    ExfiltrationDetector,
)

from backend.features.flow_features import (
    FlowFeatureExtractor,
)

from backend.features.window import FeatureWindow

from backend.ingest.flow import FlowState

from backend.scoring.threat_fusion import (
    ThreatFusionEngine,
)

from backend.scoring.deduplicator import (
    AlertDeduplicator,
)


class DetectionPipeline:
    """
    Central SENTINEL-X real-time detection pipeline.

    Flow:

        Flow
          ↓
        Features
          ↓
        Detection Engines
          ↓
        Threat Fusion
          ↓
        Alert Deduplication
          ↓
        Unified Alerts

    The pipeline only analyzes observed metadata.

    No active scanning.
    No active probing.
    No automated blocking.
    No payload decryption.
    No return-path communication.
    """

    def __init__(
        self,
        window_seconds: int = 10,
    ):
        self.feature_extractor = (
            FlowFeatureExtractor()
        )

        self.window = FeatureWindow(
            window_seconds=window_seconds
        )

        # --------------------------------------------------
        # Detection engines
        # --------------------------------------------------

        self.syn_detector = (
            SynFloodDetector()
        )

        self.volumetric_detector = (
            VolumetricDDoSDetector()
        )

        self.port_scan_detector = (
            PortScanDetector()
        )

        self.beacon_detector = (
            BeaconDetector()
        )

        self.dns_detector = (
            DNSDetector()
        )

        self.tls_detector = (
            TLSDetector()
        )

        self.exfiltration_detector = (
            ExfiltrationDetector()
        )

        # --------------------------------------------------
        # Threat fusion
        # --------------------------------------------------

        self.fusion = (
            ThreatFusionEngine()
        )

        # --------------------------------------------------
        # Alert deduplication
        #
        # Prevents the same threat from generating
        # hundreds of identical alerts.
        # --------------------------------------------------

        self.deduplicator = (
            AlertDeduplicator(
                cooldown_seconds=30.0
            )
        )

    # ======================================================
    # Internal helper
    # ======================================================

    def _deduplicate(
        self,
        alerts: list[SentinelAlert],
    ) -> list[SentinelAlert]:

        if not alerts:
            return []

        return self.deduplicator.filter(
            alerts
        )

    # ======================================================
    # FLOW PROCESSING
    # ======================================================

    def process_flow(
        self,
        flow: FlowState,
    ) -> list[SentinelAlert]:

        alerts: list[SentinelAlert] = []

        # --------------------------------------------------
        # Add flow to bounded streaming window
        # --------------------------------------------------

        self.window.add_flow(
            flow
        )

        # --------------------------------------------------
        # Extract normalized flow features
        # --------------------------------------------------

        features = (
            self.feature_extractor.extract(
                flow
            )
        )

        # ==================================================
        # 1. SYN FLOOD
        # ==================================================

        syn_result = (
            self.syn_detector.detect(
                flow
            )
        )

        if syn_result.detected:

            fusion_result = (
                self.fusion.create_alert(
                    threat_class=(
                        syn_result.threat_class
                    ),
                    severity=(
                        syn_result.severity
                    ),
                    confidence=(
                        syn_result.confidence
                    ),
                    evidence=(
                        syn_result.evidence
                    ),
                    detector=(
                        "SynFloodDetector"
                    ),
                    source_ip=(
                        flow.src_ip
                    ),
                    destination_ip=(
                        flow.dst_ip
                    ),
                    source_port=(
                        flow.src_port
                    ),
                    destination_port=(
                        flow.dst_port
                    ),
                    protocol=(
                        flow.key.protocol
                    ),
                    description=(
                        "Potential SYN flood "
                        "detected from passive "
                        "network metadata."
                    ),
                )
            )

            alerts.append(
                fusion_result.alert
            )

        # ==================================================
        # 2. VOLUMETRIC DDOS
        # ==================================================

        volumetric_results = (
            self.volumetric_detector.detect(
                self.window
            )
        )

        for result in volumetric_results:

            fusion_result = (
                self.fusion.create_alert(
                    threat_class=(
                        result.threat_class
                    ),
                    severity=(
                        result.severity
                    ),
                    confidence=(
                        result.confidence
                    ),
                    evidence=(
                        result.evidence
                    ),
                    detector=(
                        "VolumetricDDoSDetector"
                    ),
                    destination_ip=(
                        result.evidence.get(
                            "destination_ip"
                        )
                    ),
                    protocol="TCP",
                    description=(
                        "Potential volumetric "
                        "DDoS activity detected "
                        "using passive flow "
                        "statistics."
                    ),
                )
            )

            alerts.append(
                fusion_result.alert
            )

        # ==================================================
        # 3. PORT SCAN
        # ==================================================

        recon_results = (
            self.port_scan_detector.detect(
                self.window
            )
        )

        for result in recon_results:

            fusion_result = (
                self.fusion.create_alert(
                    threat_class=(
                        result.threat_class
                    ),
                    severity=(
                        result.severity
                    ),
                    confidence=(
                        result.confidence
                    ),
                    evidence=(
                        result.evidence
                    ),
                    detector=(
                        "PortScanDetector"
                    ),
                    source_ip=(
                        result.evidence.get(
                            "source_ip"
                        )
                    ),
                    description=(
                        "Potential reconnaissance "
                        "or port scanning detected "
                        "from passive traffic."
                    ),
                )
            )

            alerts.append(
                fusion_result.alert
            )

        # ==================================================
        # 4. C2 BEACONING
        # ==================================================

        beacon_results = (
            self.beacon_detector.detect(
                self.window
            )
        )

        for result in beacon_results:

            fusion_result = (
                self.fusion.create_alert(
                    threat_class=(
                        result.threat_class
                    ),
                    severity=(
                        result.severity
                    ),
                    confidence=(
                        result.confidence
                    ),
                    evidence=(
                        result.evidence
                    ),
                    detector=(
                        "BeaconDetector"
                    ),
                    source_ip=(
                        result.evidence.get(
                            "source_ip"
                        )
                    ),
                    destination_ip=(
                        result.evidence.get(
                            "destination_ip"
                        )
                    ),
                    destination_port=(
                        result.evidence.get(
                            "destination_port"
                        )
                    ),
                    description=(
                        "Potential periodic C2 "
                        "beaconing detected from "
                        "passive flow timing."
                    ),
                )
            )

            alerts.append(
                fusion_result.alert
            )

        # --------------------------------------------------
        # Feature dictionary retained for future ML engine.
        # --------------------------------------------------

        _ = features

        # --------------------------------------------------
        # Deduplicate alerts before returning.
        # --------------------------------------------------

        return self._deduplicate(
            alerts
        )

    # ======================================================
    # DNS PROCESSING
    # ======================================================

    def process_dns_query(
        self,
        query: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ) -> list[SentinelAlert]:

        result = (
            self.dns_detector.detect(
                query
            )
        )

        if not result.detected:
            return []

        alert = (
            self.fusion.create_alert(
                threat_class=(
                    result.threat_class
                ),
                severity=(
                    result.severity
                ),
                confidence=(
                    result.confidence
                ),
                evidence=(
                    result.evidence
                ),
                detector="DNSDetector",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="DNS",
                description=(
                    "Suspicious DNS behavior "
                    "detected using query "
                    "metadata."
                ),
            )
        )

        return self._deduplicate(
            [alert.alert]
        )

    # ======================================================
    # TLS / QUIC PROCESSING
    # ======================================================

    def process_tls_session(
        self,
        protocol: str,
        packet_sizes: list[int],
        duration: float,
        bytes_forward: int,
        bytes_reverse: int,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        tls_version: str | None = None,
        fingerprint: str | None = None,
    ) -> list[SentinelAlert]:

        result = (
            self.tls_detector.detect(
                protocol=protocol,
                packet_sizes=packet_sizes,
                duration=duration,
                bytes_forward=bytes_forward,
                bytes_reverse=bytes_reverse,
                tls_version=tls_version,
                fingerprint=fingerprint,
            )
        )

        if not result.detected:
            return []

        alert = (
            self.fusion.create_alert(
                threat_class=(
                    result.threat_class
                ),
                severity=(
                    result.severity
                ),
                confidence=(
                    result.confidence
                ),
                evidence=(
                    result.evidence
                ),
                detector="TLSDetector",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol.upper(),
                description=(
                    "Suspicious encrypted-session "
                    "behavior detected using "
                    "TLS/QUIC metadata only."
                ),
            )
        )

        return self._deduplicate(
            [alert.alert]
        )

    # ======================================================
    # EXFILTRATION PROCESSING
    # ======================================================

    def process_exfiltration(
        self,
        source_ip: str | None = None,
    ) -> list[SentinelAlert]:

        results = (
            self.exfiltration_detector.detect(
                self.window
            )
        )

        alerts = []

        for result in results:

            alert = (
                self.fusion.create_alert(
                    threat_class=(
                        result.threat_class
                    ),
                    severity=(
                        result.severity
                    ),
                    confidence=(
                        result.confidence
                    ),
                    evidence=(
                        result.evidence
                    ),
                    detector=(
                        "ExfiltrationDetector"
                    ),
                    source_ip=(
                        result.evidence.get(
                            "source_ip"
                        )
                        or source_ip
                    ),
                    destination_ip=(
                        result.evidence.get(
                            "destination_ip"
                        )
                    ),
                    description=(
                        "Potential data "
                        "exfiltration detected "
                        "using passive flow "
                        "volume asymmetry."
                    ),
                )
            )

            alerts.append(
                alert.alert
            )

        return self._deduplicate(
            alerts
        )

    # ======================================================
    # WINDOW STATISTICS
    # ======================================================

    def get_window_statistics(
        self,
    ) -> dict[str, Any]:

        return {
            "flows": len(
                self.window.flows
            ),
            "total_packets": (
                self.window.total_packets()
            ),
            "total_bytes": (
                self.window.total_bytes()
            ),
            "sources": (
                self.window.source_flow_counts()
            ),
            "destinations": (
                self.window.destination_flow_counts()
            ),
        }

    # ======================================================
    # CLEAR PIPELINE STATE
    # ======================================================

    def clear(
        self,
    ) -> None:

        self.window.clear()

        self.fusion.clear()

        self.deduplicator.clear()