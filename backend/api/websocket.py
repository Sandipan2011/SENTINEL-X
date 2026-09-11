import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.streaming.redis_stream import RedisStream


router = APIRouter(
    tags=["WebSocket"],
)


ALERT_STREAM = "sentinel:alerts"


class ConnectionManager:
    """
    Manages active WebSocket connections.
    """

    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(
        self,
        websocket: WebSocket,
    ):
        await websocket.accept()

        self.connections.append(
            websocket
        )

        print(
            "[WEBSOCKET] Client connected."
        )

        print(
            "[WEBSOCKET] Active clients:",
            len(self.connections),
        )

    def disconnect(
        self,
        websocket: WebSocket,
    ):
        if websocket in self.connections:
            self.connections.remove(
                websocket
            )

        print(
            "[WEBSOCKET] Client disconnected."
        )

        print(
            "[WEBSOCKET] Active clients:",
            len(self.connections),
        )


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def alert_websocket(
    websocket: WebSocket,
):
    """
    Real-time cybersecurity alert WebSocket.

    The endpoint listens to the Redis alert stream
    and forwards new alerts to the connected client.

    SENTINEL-X remains passive.

    This endpoint only:
        - Reads alert events
        - Sends alert information to dashboard clients

    It does NOT:
        - Scan systems
        - Probe systems
        - Block traffic
        - Modify firewalls
        - Contact observed hosts
        - Decrypt payloads
    """

    await manager.connect(
        websocket
    )

    redis_stream = RedisStream(
        stream_name=ALERT_STREAM
    )

    last_id = "$"

    try:

        while True:

            messages = redis_stream.read(
                count=10,
                block_ms=1000,
                last_id=last_id,
            )

            for message in messages:

                message_id = message[
                    "message_id"
                ]

                data = message[
                    "data"
                ]

                last_id = message_id

                payload = {
                    "event_type": "ALERT",
                    "message_id": message_id,
                    "alert": data,
                }

                await websocket.send_text(
                    json.dumps(
                        payload,
                        default=str,
                    )
                )

            await asyncio.sleep(
                0.05
            )

    except WebSocketDisconnect:

        manager.disconnect(
            websocket
        )

    except Exception as exc:

        print(
            "[WEBSOCKET ERROR]",
            exc,
        )

        manager.disconnect(
            websocket
        )