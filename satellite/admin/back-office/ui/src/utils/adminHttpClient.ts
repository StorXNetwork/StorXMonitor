// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

import { ErrorUnauthorized } from '@/api/errors/ErrorUnauthorized';

/**
 * AdminHttpClient is a specialized HTTP client for admin APIs that includes authorization headers.
 */
export class AdminHttpClient {
    private readonly authToken: string = 'very-secret-token';

    /**
     * Sends HTTP requests with admin authorization headers.
     */
    private async sendJSON(method: string, path: string, body: string | null): Promise<Response> {
        const request: RequestInit = {
            method: method,
            body: body,
        };

        request.headers = {
            'Content-Type': 'application/json',
            'Authorization': this.authToken,
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
            const logoutPath = '/api/v0/auth/logout';
            const request: RequestInit = {
                method: 'POST',
                body: null,
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
        }, 2000);
    }
}
