from datetime import datetime, timedelta, timezone


class AlertDeduplicator:
    """
    Prevents identical alerts from being generated repeatedly
    within a configurable cooldown period.
    """

    def __init__(self, cooldown_seconds: float = 30.0):
        self.cooldown = timedelta(
            seconds=cooldown_seconds
        )

        self.last_seen: dict[
            tuple,
            datetime
        ] = {}

    @staticmethod
    def _key(alert) -> tuple:
        return (
            alert.threat_class,
            alert.source_ip,
            alert.destination_ip,
            alert.destination_port,
            alert.protocol,
        )

    def is_duplicate(self, alert) -> bool:
        now = datetime.now(timezone.utc)
        key = self._key(alert)

        previous = self.last_seen.get(key)

        if previous is not None:
            if now - previous < self.cooldown:
                return True

        self.last_seen[key] = now

        return False

    def filter(self, alerts: list) -> list:
        unique_alerts = []

        for alert in alerts:
            if not self.is_duplicate(alert):
                unique_alerts.append(alert)

        return unique_alerts

    def clear(self):
        self.last_seen.clear()

    def size(self) -> int:
        return len(self.last_seen)