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
    description?: string;
    redirectUris: string[];
    scopes?: string[];
    status: number;
    createdAt: string;
    updatedAt: string;
}

export interface AccessLogFilters {
    startDate?: string;
    endDate?: string;
    status?: number; // 0=pending, 1=approved, 2=rejected
    clientId?: string;
    limit?: number;
    page?: number;
}

export interface AccessLogEntry {
    id: string;
    clientId: string;
    clientName: string;
    timestamp: string;
    status: number;
    accessStatus: string; // "pending", "approved", "rejected"
    redirectUri: string;
    scopes: string[];
    approvedScopes: string[];
    rejectedScopes: string[];
    rejectionReason?: string;
    consentExpiresAt?: string;
    codeExpiresAt?: string;
}

export interface AccessLogStatistics {
    total: number;
    approved: number;
    pending: number;
    rejected: number;
    successRate: number; // percentage
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
    async createOAuthClient(
        name: string,
        redirectUris: string[],
        description?: string,
        scopes?: string[]
    ): Promise<{ clientId: string; clientSecret: string }> {
        const response = await fetch(`${API_BASE}/oauth2/clients`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                name,
                redirect_uris: redirectUris,
                description: description || '',
                scopes: scopes || [],
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to create OAuth client';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const result = await response.json();
        // Backend returns client_id and client_secret, convert to camelCase
        return {
            clientId: result.client_id || result.clientId,
            clientSecret: result.client_secret || result.clientSecret,
        };
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
            const errorText = await response.text();
            let errorMessage = 'Failed to list OAuth clients';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        // Map snake_case to camelCase for each client
        if (!Array.isArray(data)) {
            return [];
        }
        return data.map((client: any) => ({
            id: client.id || client.ID,
            clientId: client.client_id || client.clientId || client.ClientID,
            name: client.name || client.Name,
            description: client.description || client.Description || '',
            redirectUris: client.redirect_uris || client.redirectUris || client.RedirectURIs || [],
            scopes: client.scopes || client.Scopes || [],
            status: client.status || client.Status || 0,
            createdAt: client.created_at || client.createdAt || client.CreatedAt,
            updatedAt: client.updated_at || client.updatedAt || client.UpdatedAt,
        }));
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
     * Get single OAuth client
     * Requires authentication
     */
    async getOAuthClient(id: string): Promise<OAuthClient> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${id}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to get OAuth client';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        // Map snake_case to camelCase
        return {
            id: data.id || data.ID,
            clientId: data.client_id || data.clientId || data.ClientID,
            name: data.name || data.Name,
            description: data.description || data.Description || '',
            redirectUris: data.redirect_uris || data.redirectUris || data.RedirectURIs || [],
            scopes: data.scopes || data.Scopes || [],
            status: data.status || data.Status || 0,
            createdAt: data.created_at || data.createdAt || data.CreatedAt,
            updatedAt: data.updated_at || data.updatedAt || data.UpdatedAt,
        };
    }

    /**
     * Update OAuth client
     * Requires authentication
     */
    async updateOAuthClient(
        id: string,
        updates: {
            name?: string;
            description?: string;
            redirectUris?: string[];
            scopes?: string[];
        }
    ): Promise<OAuthClient> {
        // Convert camelCase to snake_case for backend
        const body: any = {};
        if (updates.name !== undefined) body.name = updates.name;
        if (updates.description !== undefined) body.description = updates.description;
        if (updates.redirectUris !== undefined) body.redirect_uris = updates.redirectUris;
        if (updates.scopes !== undefined) body.scopes = updates.scopes;

        const response = await fetch(`${API_BASE}/oauth2/clients/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to update OAuth client';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        return await response.json();
    }

    /**
     * Regenerate OAuth client secret
     * Requires authentication
     */
    async regenerateOAuthClientSecret(id: string): Promise<{ clientId: string; clientSecret: string }> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${id}/regenerate-secret`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to regenerate OAuth client secret';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const result = await response.json();
        return {
            clientId: result.client_id || result.clientId,
            clientSecret: result.client_secret || result.clientSecret,
        };
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

    /**
     * Add redirect URI to OAuth client
     * Requires authentication
     */
    async addRedirectURI(clientId: string, uri: string): Promise<OAuthClient> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${clientId}/redirect-uris`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ uri }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to add redirect URI';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        // Map snake_case to camelCase
        return {
            id: data.id || data.ID,
            clientId: data.client_id || data.clientId || data.ClientID,
            name: data.name || data.Name,
            description: data.description || data.Description || '',
            redirectUris: data.redirect_uris || data.redirectUris || data.RedirectURIs || [],
            scopes: data.scopes || data.Scopes || [],
            status: data.status || data.Status || 0,
            createdAt: data.created_at || data.createdAt || data.CreatedAt,
            updatedAt: data.updated_at || data.updatedAt || data.UpdatedAt,
        };
    }

    /**
     * Update redirect URI in OAuth client
     * Requires authentication
     */
    async updateRedirectURI(clientId: string, oldURI: string, newURI: string): Promise<OAuthClient> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${clientId}/redirect-uris`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ old_uri: oldURI, new_uri: newURI }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to update redirect URI';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        // Map snake_case to camelCase
        return {
            id: data.id || data.ID,
            clientId: data.client_id || data.clientId || data.ClientID,
            name: data.name || data.Name,
            description: data.description || data.Description || '',
            redirectUris: data.redirect_uris || data.redirectUris || data.RedirectURIs || [],
            scopes: data.scopes || data.Scopes || [],
            status: data.status || data.Status || 0,
            createdAt: data.created_at || data.createdAt || data.CreatedAt,
            updatedAt: data.updated_at || data.updatedAt || data.UpdatedAt,
        };
    }

    /**
     * Delete redirect URI from OAuth client
     * Requires authentication
     */
    async deleteRedirectURI(clientId: string, uri: string): Promise<OAuthClient> {
        const response = await fetch(`${API_BASE}/oauth2/clients/${clientId}/redirect-uris`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ uri }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to delete redirect URI';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || error.message || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        // Map snake_case to camelCase
        return {
            id: data.id || data.ID,
            clientId: data.client_id || data.clientId || data.ClientID,
            name: data.name || data.Name,
            description: data.description || data.Description || '',
            redirectUris: data.redirect_uris || data.redirectUris || data.RedirectURIs || [],
            scopes: data.scopes || data.Scopes || [],
            status: data.status || data.Status || 0,
            createdAt: data.created_at || data.createdAt || data.CreatedAt,
            updatedAt: data.updated_at || data.updatedAt || data.UpdatedAt,
        };
    }

    /**
     * List access logs with filters
     * Returns logs with pagination metadata
     */
    async listAccessLogs(filters: AccessLogFilters = {}): Promise<{ logs: AccessLogEntry[]; totalCount: number; pageCount: number; currentPage: number; hasMore: boolean; limit: number; offset: number }> {
        const params = new URLSearchParams();
        if (filters.startDate) params.append('start_date', filters.startDate);
        if (filters.endDate) params.append('end_date', filters.endDate);
        if (filters.status !== undefined) params.append('status', filters.status.toString());
        if (filters.clientId) params.append('client_id', filters.clientId);
        if (filters.limit !== undefined) params.append('limit', filters.limit.toString());
        if (filters.page !== undefined) params.append('page', filters.page.toString());

        const response = await fetch(`${API_BASE}/access-logs?${params.toString()}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to fetch access logs';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        
        // Map backend response (PascalCase/snake_case) to frontend format (camelCase)
        const mapLogEntry = (entry: any): AccessLogEntry => {
            // Helper to parse comma-separated string to array
            const parseScopes = (scopes: any): string[] => {
                if (!scopes) return [];
                if (Array.isArray(scopes)) return scopes;
                if (typeof scopes === 'string') {
                    return scopes.split(',').map(s => s.trim()).filter(s => s.length > 0);
                }
                return [];
            };

            // Helper to convert UUID to string
            const uuidToString = (uuid: any): string => {
                if (!uuid) return '';
                if (typeof uuid === 'string') return uuid;
                if (typeof uuid === 'object' && uuid.toString) return uuid.toString();
                return String(uuid);
            };

            return {
                id: uuidToString(entry.id || entry.ID || ''),
                clientId: entry.client_id || entry.clientId || entry.ClientID || '',
                clientName: entry.client_name || entry.clientName || entry.ClientName || 'N/A',
                timestamp: entry.timestamp || entry.Timestamp || entry.created_at || entry.CreatedAt || '',
                status: entry.status || entry.Status || 0,
                accessStatus: entry.access_status || entry.accessStatus || entry.AccessStatus || 'pending',
                redirectUri: entry.redirect_uri || entry.redirectUri || entry.RedirectURI || '',
                scopes: parseScopes(entry.scopes || entry.Scopes),
                approvedScopes: parseScopes(entry.approved_scopes || entry.approvedScopes || entry.ApprovedScopes),
                rejectedScopes: parseScopes(entry.rejected_scopes || entry.rejectedScopes || entry.RejectedScopes),
                rejectionReason: entry.rejection_reason || entry.rejectionReason || entry.RejectionReason || '',
                consentExpiresAt: entry.consent_expires_at || entry.consentExpiresAt || entry.ConsentExpiresAt || '',
                codeExpiresAt: entry.code_expires_at || entry.codeExpiresAt || entry.CodeExpiresAt || '',
            };
        };
        
        // Handle both old format (array) and new format (object with logs, totalCount, pageCount, etc.)
        if (Array.isArray(data)) {
            return {
                logs: data.map(mapLogEntry),
                totalCount: data.length,
                pageCount: 1,
                currentPage: 1,
                hasMore: false,
                limit: filters.limit || 0,
                offset: 0,
            };
        }
        // New format: object with logs, totalCount, pageCount, currentPage, hasMore, limit, offset
        return {
            logs: (data.logs || []).map(mapLogEntry),
            totalCount: data.totalCount || data.total_count || 0,
            pageCount: data.pageCount || data.page_count || 1,
            currentPage: data.currentPage || data.current_page || 1,
            hasMore: data.hasMore || data.has_more || false,
            limit: data.limit || 0,
            offset: data.offset || 0,
        };
    }

    /**
     * Get access log statistics (no filters, all time statistics)
     */
    async getAccessLogStatistics(): Promise<AccessLogStatistics> {
        const response = await fetch(`${API_BASE}/access-logs/statistics`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to fetch access log statistics';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        // Map snake_case to camelCase
        return {
            total: data.total || 0,
            approved: data.approved || 0,
            pending: data.pending || 0,
            rejected: data.rejected || 0,
            successRate: data.success_rate || data.successRate || 0,
        };
    }

    /**
     * Export access logs as CSV
     */
    async exportAccessLogs(filters: AccessLogFilters = {}): Promise<Blob> {
        const params = new URLSearchParams();
        if (filters.startDate) params.append('start_date', filters.startDate);
        if (filters.endDate) params.append('end_date', filters.endDate);
        if (filters.status !== undefined) params.append('status', filters.status.toString());
        if (filters.clientId) params.append('client_id', filters.clientId);
        if (filters.limit !== undefined) params.append('limit', filters.limit.toString());
        if (filters.page !== undefined) params.append('page', filters.page.toString());

        const response = await fetch(`${API_BASE}/access-logs/export?${params.toString()}`, {
            method: 'GET',
            credentials: 'include',
        });

        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage = 'Failed to export access logs';
            try {
                const error = JSON.parse(errorText);
                errorMessage = error.error || errorMessage;
            } catch {
                errorMessage = errorText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        return await response.blob();
    }
}

export const developerApi = new DeveloperAPI();

