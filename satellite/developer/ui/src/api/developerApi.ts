/**
 * Developer Console API Service
 * Handles all API calls to the backend
 */

const API_BASE = '/api/v0/developer/auth';

export interface TokenInfo {
    token: string;
    expiresAt: string;
}

export interface DeveloperAccount {
    id: string;
    fullName: string;
    email: string;
    companyName: string;
    createdAt: string;
    pendingVerification: boolean;
    status?: number;
}

export interface TokenVerificationResponse {
    email: string;
    fullName: string;
    valid: boolean;
}

export interface OAuthClient {
    id: string;
    clientId: string;
    name: string;
    redirectUris: string[];
    status: number;
    createdAt: string;
    updatedAt: string;
}

class DeveloperAPI {
    /**
     * Verify JWT token from email link
     */
    async verifyResetToken(token: string): Promise<TokenVerificationResponse> {
        const response = await fetch(
            `${API_BASE}/verify-reset-token?token=${encodeURIComponent(token)}`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        );

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Token verification failed');
        }

        return await response.json();
    }

    /**
     * Login with email and password
     */
    async login(email: string, password: string): Promise<TokenInfo> {
        const response = await fetch(`${API_BASE}/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ email, password }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Login failed');
        }

        return await response.json();
    }

    /**
     * Reset password using JWT token (from email link)
     */
    async resetPasswordWithToken(token: string, newPassword: string): Promise<{ success: boolean }> {
        const response = await fetch(`${API_BASE}/reset-password-with-token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token, newPassword }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Password reset failed');
        }

        return await response.json();
    }

    /**
     * Reset password after first login (when status is ResetPass)
     * Requires authentication
     */
    async resetPasswordAfterLogin(newPassword: string): Promise<{ success: boolean }> {
        const response = await fetch(`${API_BASE}/reset-password-after-login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ newPassword }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Password reset failed');
        }

        return await response.json();
    }

    /**
     * Get current developer account information
     * Requires authentication
     */
    async getAccount(): Promise<DeveloperAccount> {
        const response = await fetch(`${API_BASE}/account`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to get account');
        }

        return await response.json();
    }

    /**
     * Update account information
     * Requires authentication
     */
    async updateAccount(fullName: string): Promise<void> {
        const response = await fetch(`${API_BASE}/account`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ fullName }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to update account');
        }
    }

    /**
     * Change password
     * Requires authentication
     */
    async changePassword(currentPassword: string, newPassword: string): Promise<void> {
        const response = await fetch(`${API_BASE}/account/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ password: currentPassword, newPassword }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to change password');
        }
    }

    /**
     * Logout current session
     * Requires authentication
     */
    async logout(): Promise<void> {
        await fetch(`${API_BASE}/logout`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });
    }

    /**
     * Refresh session token
     * Requires authentication
     */
    async refreshSession(): Promise<string> {
        const response = await fetch(`${API_BASE}/refresh-session`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            throw new Error('Session refresh failed');
        }

        return await response.text();
    }

    /**
     * Create OAuth client
     * Requires authentication
     */
    async createOAuthClient(name: string, redirectUris: string[]): Promise<{ clientId: string; clientSecret: string }> {
        const response = await fetch(`${API_BASE}/oauth2/clients`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ name, redirectUris }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create OAuth client');
        }

        return await response.json();
    }

    /**
     * List OAuth clients
     * Requires authentication
     */
    async listOAuthClients(): Promise<OAuthClient[]> {
        const response = await fetch(`${API_BASE}/oauth2/clients`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to list OAuth clients');
        }

        return await response.json();
    }

    /**
     * Delete OAuth client
     * Requires authentication
     */
    async deleteOAuthClient(id: string): Promise<void> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete OAuth client');
        }
    }

    /**
     * Update OAuth client status
     * Requires authentication
     */
    async updateOAuthClientStatus(id: string, status: number): Promise<void> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${id}/status`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ status }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to update OAuth client status');
        }
    }
}

export const developerApi = new DeveloperAPI();

