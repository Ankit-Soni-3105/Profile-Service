// utils/events.js
import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';
import { metricsCollector } from '../utils/matrics.js'; // Optional, for tracking events

class AppEventEmitter extends EventEmitter {
    constructor() {
        super();
        this.setMaxListeners(100); // Increase for high-scale (monitor for memory leaks)
    }

    /**
     * Emit an event asynchronously to avoid blocking
     * @param {string} event - Event name
     * @param {any} data - Data to pass to listeners
     */
    async emitAsync(event, data) {
        return new Promise((resolve, reject) => {
            try {
                const emitted = this.emit(event, data);
                logger.info('Event emitted', { event, data, emitted });
                metricsCollector.increment('event.emitted', { event });
                resolve(emitted);
            } catch (error) {
                logger.error('Failed to emit event', { event, error: error.message });
                metricsCollector.increment('event.emit_failed', { event });
                reject(error);
            }
        });
    }

    /**
     * Add a listener with error handling
     * @param {string} event - Event name
     * @param {function} listener - Listener function
     */
    on(event, listener) {
        const wrappedListener = async (...args) => {
            try {
                await listener(...args);
                metricsCollector.increment('event.handled', { event });
            } catch (error) {
                logger.error('Event listener error', { event, error: error.message });
                metricsCollector.increment('event.handle_failed', { event });
            }
        };
        super.on(event, wrappedListener);
        logger.debug('Listener added', { event });
    }

    /**
     * Remove all listeners for an event
     * @param {string} event - Event name
     */
    removeAllListeners(event) {
        super.removeAllListeners(event);
        logger.info('All listeners removed', { event });
    }
}

export const eventEmitter = new AppEventEmitter();