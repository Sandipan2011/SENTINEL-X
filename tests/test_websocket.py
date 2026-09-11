import asyncio
import json

import websockets


async def main():
    uri = "ws://127.0.0.1:8000/ws/alerts"

    print("Connecting to:")
    print(uri)
    print()

    async with websockets.connect(
        uri
    ) as websocket:

        print(
            "WebSocket connected."
        )

        print(
            "Waiting for alerts..."
        )

        while True:

            message = await websocket.recv()

            data = json.loads(
                message
            )

            print()
            print("=" * 70)
            print(
                "🚨 LIVE SENTINEL-X ALERT"
            )
            print("=" * 70)

            print(
                json.dumps(
                    data,
                    indent=2,
                )
            )

            print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())