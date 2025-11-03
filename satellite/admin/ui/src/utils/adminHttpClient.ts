// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

import { ErrorUnauthorized } from '@/api/errors/ErrorUnauthorized';

/**
 * AdminHttpClient is a specialized HTTP client for admin APIs that includes authorization headers.
 */
export class AdminHttpClient {
    private get authToken(): string {
        // Get token from localStorage, fallback to empty string
        return localStorage.getItem('adminToken') || '';
    }

    /**
     * Sends HTTP requests with admin authorization headers.
     */
    private async sendJSON(method: string, path: string, body: string | null): Promise<Response> {
        const request: RequestInit = {
            method: method,
            body: body,
        };

        const token = this.authToken;
        request.headers = {
            'Content-Type': 'application/json',
        };
        
        // Only add Authorization header if token exists (skip for login endpoint)
        if (token && !path.includes('/auth/login')) {
            // Use Bearer prefix for JWT tokens
            request.headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`;
        }

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

        // Clear token from localStorage
        localStorage.removeItem('adminToken');
        
        setTimeout(() => {
            if (!window.location.href.includes('/login')) {
                window.location.href = window.location.origin + '/login';
            }
        }, 1000);
    }
}
