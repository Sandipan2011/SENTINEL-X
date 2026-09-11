import { ALERT_WEBSOCKET_URL } from "./api";


/*
 * SENTINEL-X real-time alert WebSocket client.
 *
 * The browser only receives security intelligence.
 * It does not send commands to the monitored network.
 */
export class AlertWebSocket {
    constructor({
        onAlert,
        onStatusChange,
        reconnectDelay = 3000,
    } = {}) {
        this.onAlert = onAlert;
        this.onStatusChange = onStatusChange;
        this.reconnectDelay = reconnectDelay;

        this.socket = null;
        this.shouldReconnect = true;
        this.reconnectTimer = null;
    }


    connect() {
        if (
            this.socket &&
            (
                this.socket.readyState === WebSocket.OPEN ||
                this.socket.readyState === WebSocket.CONNECTING
            )
        ) {
            return;
        }

        this.shouldReconnect = true;

        this.updateStatus("connecting");

        try {
            this.socket = new WebSocket(ALERT_WEBSOCKET_URL);

            this.socket.onopen = () => {
                this.updateStatus("connected");
            };

            this.socket.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);

                    if (message.event_type === "ALERT") {
                        if (this.onAlert) {
                            this.onAlert(message.alert);
                        }
                    }
                } catch (error) {
                    console.error(
                        "SENTINEL-X WebSocket message error:",
                        error
                    );
                }
            };

            this.socket.onerror = (error) => {
                console.error(
                    "SENTINEL-X WebSocket error:",
                    error
                );

                this.updateStatus("error");
            };

            this.socket.onclose = () => {
                this.updateStatus("disconnected");

                this.socket = null;

                if (this.shouldReconnect) {
                    this.scheduleReconnect();
                }
            };
        } catch (error) {
            console.error(
                "Unable to connect to SENTINEL-X WebSocket:",
                error
            );

            this.updateStatus("error");
            this.scheduleReconnect();
        }
    }


    scheduleReconnect() {
        if (!this.shouldReconnect) {
            return;
        }

        if (this.reconnectTimer) {
            return;
        }

        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.connect();
        }, this.reconnectDelay);
    }


    updateStatus(status) {
        if (this.onStatusChange) {
            this.onStatusChange(status);
        }
    }


    disconnect() {
        this.shouldReconnect = false;

        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }

        this.updateStatus("disconnected");
    }
}