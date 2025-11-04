// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

import { ErrorUnauthorized } from '@/api/errors/ErrorUnauthorized';

/**
 * AdminHttpClient is a specialized HTTP client for admin APIs.
 * Uses cookie-based authentication (cookies are automatically sent by browser).
 */
export class AdminHttpClient {
    /**
     * Sends HTTP requests. Cookies are automatically sent by browser.
     */
    private async sendJSON(method: string, path: string, body: string | null): Promise<Response> {
        const request: RequestInit = {
            method: method,
            body: body,
            credentials: 'include', // Include cookies in requests
        };

        request.headers = {
            'Content-Type': 'application/json',
        };

        const response = await fetch(path, request);
        if (response.status === 401) {
            await this.handleUnauthorized();
            throw new ErrorUnauthorized();
        }

        return response;
    }

    /**
     * Performs POST http request with JSON body.
     */
    public async post(path: string, body: string | null): Promise<Response> {
        return this.sendJSON('POST', path, body);
    }

    /**
     * Performs PATCH http request with JSON body.
     */
    public async patch(path: string, body: string | null): Promise<Response> {
        return this.sendJSON('PATCH', path, body);
    }

    /**
     * Performs PUT http request with JSON body.
     */
    public async put(path: string, body: string | null): Promise<Response> {
        return this.sendJSON('PUT', path, body);
    }

    /**
     * Performs GET http request.
     */
    public async get(path: string): Promise<Response> {
        return this.sendJSON('GET', path, null);
    }

    /**
     * Performs DELETE http request.
     */
    public async delete(path: string, body: string | null = null): Promise<Response> {
        return this.sendJSON('DELETE', path, body);
    }

    /**
     * Handles unauthorized actions.
     */
    private async handleUnauthorized(): Promise<void> {
        try {
            const logoutPath = '/api/auth/logout';
            const request: RequestInit = {
                method: 'POST',
                body: null,
                credentials: 'include', // Include cookies
            };

            request.headers = {
                'Content-Type': 'application/json',
            };

            await fetch(logoutPath, request);
            // eslint-disable-next-line no-empty
        } catch (error) {}
        
        setTimeout(() => {
            if (!window.location.href.includes('/login')) {
                window.location.href = window.location.origin + '/login';
            }
        }, 1000);
    }
}
