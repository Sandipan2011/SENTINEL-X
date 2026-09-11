import json
from typing import Any

import redis

from backend.config.settings import settings


class RedisStream:
    """
    Redis Streams adapter for SENTINEL-X.

    Redis is used only as an internal event bus.

    SENTINEL-X remains completely passive with respect
    to the observed network.
    """

    def __init__(
        self,
        stream_name: str | None = None,
        redis_url: str | None = None,
    ):

        self.stream_name = (
            stream_name
            or settings.stream_name
        )

        self.redis_url = (
            redis_url
            or settings.redis_url
        )

        self.client = redis.Redis.from_url(
            self.redis_url,
            decode_responses=True,
        )

    # -------------------------------------------------
    # CONNECTION
    # -------------------------------------------------

    def ping(self) -> bool:

        return bool(
            self.client.ping()
        )

    # -------------------------------------------------
    # PUBLISH
    # -------------------------------------------------

    def publish(
        self,
        data: dict[str, Any],
    ) -> str:

        payload = json.dumps(
            data,
            default=str,
        )

        message_id = self.client.xadd(
            self.stream_name,
            {
                "data": payload
            },
        )

        return message_id

    # -------------------------------------------------
    # SIMPLE READ
    # -------------------------------------------------

    def read(
        self,
        count: int = 10,
        block_ms: int = 1000,
        last_id: str = "0-0",
    ) -> list[dict[str, Any]]:

        response = self.client.xread(
            {
                self.stream_name: last_id
            },
            count=count,
            block=block_ms,
        )

        return self._parse_messages(
            response
        )

    # -------------------------------------------------
    # CREATE CONSUMER GROUP
    # -------------------------------------------------

    def create_group(
        self,
        group_name: str,
        start_id: str = "0-0",
    ) -> bool:

        try:

            self.client.xgroup_create(
                name=self.stream_name,
                groupname=group_name,
                id=start_id,
                mkstream=True,
            )

            return True

        except redis.exceptions.ResponseError as exc:

            if "BUSYGROUP" in str(exc):

                return False

            raise

    # -------------------------------------------------
    # READ CONSUMER GROUP
    # -------------------------------------------------

    def read_group(
        self,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block_ms: int = 1000,
        last_id: str = ">",
    ) -> list[dict[str, Any]]:

        response = self.client.xreadgroup(
            groupname=group_name,
            consumername=consumer_name,
            streams={
                self.stream_name: last_id
            },
            count=count,
            block=block_ms,
        )

        return self._parse_messages(
            response
        )

    # -------------------------------------------------
    # ACKNOWLEDGE
    # -------------------------------------------------

    def acknowledge(
        self,
        group_name: str,
        message_id: str,
    ) -> int:

        return int(
            self.client.xack(
                self.stream_name,
                group_name,
                message_id,
            )
        )

    # -------------------------------------------------
    # PENDING SUMMARY
    # -------------------------------------------------

    def pending(
        self,
        group_name: str,
    ):

        return self.client.xpending(
            self.stream_name,
            group_name,
        )

    # -------------------------------------------------
    # PENDING MESSAGE DETAILS
    # -------------------------------------------------

    def pending_messages(
        self,
        group_name: str,
        min_idle_time: int = 5000,
        count: int = 10,
    ):

        """
        Return pending messages that have been idle
        for at least min_idle_time milliseconds.

        These messages can be recovered by another worker.
        """

        try:

            messages = (
                self.client.xpending_range(
                    self.stream_name,
                    group_name,
                    min="-",
                    max="+",
                    count=count,
                    idle=min_idle_time,
                )
            )

        except TypeError:

            # Compatibility fallback for Redis clients
            # that do not support the idle argument.
            messages = (
                self.client.xpending_range(
                    self.stream_name,
                    group_name,
                    min="-",
                    max="+",
                    count=count,
                )
            )

        return messages

    # -------------------------------------------------
    # CLAIM PENDING MESSAGE
    # -------------------------------------------------

    def claim_pending(
        self,
        group_name: str,
        consumer_name: str,
        message_ids: list[str],
        min_idle_time: int = 5000,
    ) -> list[dict[str, Any]]:

        if not message_ids:

            return []

        claimed = self.client.xclaim(
            self.stream_name,
            group_name,
            consumer_name,
            min_idle_time,
            message_ids,
        )

        events = []

        for message_id, fields in claimed:

            raw_data = fields.get(
                "data"
            )

            if raw_data is None:

                continue

            data = json.loads(
                raw_data
            )

            events.append(
                {
                    "message_id": message_id,
                    "stream": self.stream_name,
                    "data": data,
                    "recovered": True,
                }
            )

        return events

    # -------------------------------------------------
    # STREAM LENGTH
    # -------------------------------------------------

    def length(self) -> int:

        return int(
            self.client.xlen(
                self.stream_name
            )
        )

    # -------------------------------------------------
    # CLEAR STREAM
    # -------------------------------------------------

    def clear(self) -> None:

        self.client.delete(
            self.stream_name
        )

    # -------------------------------------------------
    # INTERNAL PARSER
    # -------------------------------------------------

    @staticmethod
    def _parse_messages(
        response,
    ) -> list[dict[str, Any]]:

        events = []

        for stream_name, messages in response:

            for message_id, fields in messages:

                raw_data = fields.get(
                    "data"
                )

                if raw_data is None:

                    continue

                data = json.loads(
                    raw_data
                )

                events.append(
                    {
                        "message_id": message_id,
                        "stream": stream_name,
                        "data": data,
                        "recovered": False,
                    }
                )

        return events