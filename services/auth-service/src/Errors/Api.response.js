/**
 * Standardized API Response Class
 * Ensures consistent response structure across all microservices
 */
class ApiResponse {
    constructor(statusCode, data, message = "Success") {
        this.statusCode = statusCode;
        this.data = data;
        this.message = message;
        this.success = statusCode < 400;
        this.timestamp = new Date().toISOString();
        this.count = Array.isArray(data) ? data.length : data ? 1 : 0;
    }

    // Static methods for common response types
    static success(data = null, message = "Operation successful") {
        return new ApiResponse(200, data, message);
    }

    static created(data = null, message = "Resource created successfully") {
        return new ApiResponse(201, data, message);
    }

    static accepted(data = null, message = "Request accepted") {
        return new ApiResponse(202, data, message);
    }

    static noContent(message = "No content") {
        return new ApiResponse(204, null, message);
    }

    // Pagination response
    static paginated(data, pagination, message = "Data retrieved successfully") {
        const response = new ApiResponse(200, data, message);
        response.pagination = {
            page: pagination.page,
            limit: pagination.limit,
            total: pagination.total,
            totalPages: Math.ceil(pagination.total / pagination.limit),
            hasNextPage: pagination.page < Math.ceil(pagination.total / pagination.limit),
            hasPrevPage: pagination.page > 1
        };
        return response;
    }

    // Cache response indicator
    static cached(data, message = "Data retrieved from cache") {
        const response = new ApiResponse(200, data, message);
        response.fromCache = true;
        return response;
    }
}

export default ApiResponse;