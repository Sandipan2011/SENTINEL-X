import asyncio
import json

import websockets


async def main():
    uri = "ws://127.0.0.1:8000/ws/alerts"

    print("=" * 70)
    print("SENTINEL-X WEBSOCKET ALERT CLIENT")
    print("=" * 70)
    print("Connecting:", uri)
    print()

    try:
        async with websockets.connect(uri) as websocket:
            print("[CONNECTED] Waiting for real-time alerts...")
            print()

            while True:
                message = await websocket.recv()

                data = json.loads(message)

                print("🚨 REAL-TIME ALERT")
                print("-" * 70)
                print(json.dumps(data, indent=2))
                print("-" * 70)
                print()

    except KeyboardInterrupt:
        print("\n[CLIENT] Stopped.")

    except Exception as exc:
        print("[CLIENT ERROR]", exc)


if __name__ == "__main__":
    asyncio.run(main())