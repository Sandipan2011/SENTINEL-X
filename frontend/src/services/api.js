const API_BASE_URL = "http://127.0.0.1:8000";

async function request(endpoint, options = {}) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
        },
        ...options,
    });

    if (!response.ok) {
        throw new Error(
            `API request failed: ${response.status} ${response.statusText}`
        );
    }

    return response.json();
}


/*
 * Get recent security alerts.
 */
export async function getAlerts({
    limit = 100,
    severity = "",
    threatClass = "",
    status = "",
} = {}) {
    const params = new URLSearchParams();

    params.set("limit", limit);

    if (severity) {
        params.set("severity", severity);
    }

    if (threatClass) {
        params.set("threat_class", threatClass);
    }

    if (status) {
        params.set("status", status);
    }

    return request(`/api/alerts?${params.toString()}`);
}


/*
 * Get aggregated alert statistics.
 */
export async function getAlertStats() {
    return request("/api/alerts/stats");
}


/*
 * Backend health.
 */
export async function getHealth() {
    return request("/health");
}


/*
 * SENTINEL-X security policy.
 *
 * This allows the dashboard to visibly prove
 * that the system is operating in passive mode.
 */
export async function getSecurityPolicy() {
    return request("/security-policy");
}


/*
 * WebSocket endpoint for real-time alerts.
 */
export const ALERT_WEBSOCKET_URL =
    "ws://127.0.0.1:8000/ws/alerts";


/*
 * API base URL.
 */
export { API_BASE_URL };