// utils/metrics.js
import client from 'prom-client'; // Requires 'prom-client' package (npm install prom-client)
import { logger } from './logger.js';

// Enable metrics collection
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ timeout: 5000 });

// Custom Registry to avoid global conflicts in multi-instance setups
const Registry = client.Registry;
const register = new Registry();

// Counters for events (e.g., summary.created)
const counter = new client.Counter({
    name: 'app_events_total',
    help: 'Total number of application events',
    labelNames: ['event', 'userId', 'error'], // Dimensional labels for filtering
    registers: [register],
});

// Histograms for durations (e.g., response times)
const histogram = new client.Histogram({
    name: 'app_operation_duration_seconds',
    help: 'Duration of operations in seconds',
    labelNames: ['operation', 'status'],
    buckets: [0.1, 0.5, 1, 2, 5, 10], // Buckets for latency distribution
    registers: [register],
});

// Gauges for current states (e.g., active users, cache size)
const gauge = new client.Gauge({
    name: 'app_current_state',
    help: 'Current state metrics',
    labelNames: ['metric'],
    registers: [register],
});

class MetricsCollector {
    /**
     * Increment a counter metric
     * @param {string} event - Event name (e.g., 'summary.created')
     * @param {object} labels - Additional labels (e.g., { userId: '123', category: 'tech' })
     */
    increment(event, labels = {}) {
        try {
            counter.inc({ ...labels, event });
            logger.debug('Metric incremented', { event, labels });
        } catch (error) {
            logger.error('Failed to increment metric', { event, error: error.message });
        }
    }

    /**
     * Record a duration in histogram
     * @param {string} operation - Operation name (e.g., 'summary.fetch')
     * @param {number} duration - Duration in ms
     * @param {object} labels - Additional labels (e.g., { status: 'success' })
     */
    record(operation, duration, labels = {}) {
        try {
            histogram.observe({ ...labels, operation }, duration / 1000); // Convert ms to seconds
            logger.debug('Duration recorded', { operation, duration, labels });
        } catch (error) {
            logger.error('Failed to record duration', { operation, error: error.message });
        }
    }

    /**
     * Set a gauge value
     * @param {string} metric - Metric name (e.g., 'active_users')
     * @param {number} value - Value to set
     * @param {object} labels - Additional labels
     */
    setGauge(metric, value, labels = {}) {
        try {
            gauge.set({ ...labels, metric }, value);
            logger.debug('Gauge set', { metric, value, labels });
        } catch (error) {
            logger.error('Failed to set gauge', { metric, error: error.message });
        }
    }

    /**
     * Get all metrics as Prometheus text
     * @returns {Promise<string>}
     */
    async getMetrics() {
        try {
            return await register.metrics();
        } catch (error) {
            logger.error('Failed to get metrics', { error: error.message });
            return '';
        }
    }

    /**
     * Clear all metrics (for testing)
     */
    clear() {
        register.clear();
        logger.info('Metrics registry cleared');
    }
}

export const metricsCollector = new MetricsCollector();

// Expose metrics endpoint in your app (e.g., in Express)
// app.get('/metrics', async (req, res) => {
//     res.set('Content-Type', register.contentType);
//     res.end(await metricsCollector.getMetrics());
// });