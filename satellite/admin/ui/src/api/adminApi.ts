// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

import { AdminHttpClient } from '@/utils/adminHttpClient';

// Types for the admin API responses
export interface User {
    id: string;
    fullName: string;
    email: string;
    status: number;
    createdAt: string;
    paidTier: boolean;
    projectStorageLimit: number;
    projectBandwidthLimit: number;
    // UTM tracking data
    source: string;
    utmSource: string;
    utmMedium: string;
    utmCampaign: string;
    utmTerm: string;
    utmContent: string;
    // Session data
    lastSessionExpiry: string | null;
    firstSessionExpiry: string | null;
    totalSessionCount: number;
    // Usage data
    storageUsed: number;
    bandwidthUsed: number;
    projectCount: number;
}

export interface UserListResponse {
    users: User[];
    pageCount: number;
    currentPage: number;
    totalCount: number;
    hasMore: boolean;
    limit: number;
    offset: number;
}

export interface Node {
    id: string;
    address: string;
    countryCode: string;
    createdAt: string;
    status: string;
    freeDisk: number;
    latency90: number;
    version: string;
    operatorEmail: string;
}

export interface NodeListResponse {
    nodes: Node[];
    pageCount: number;
    currentPage: number;
    totalCount: number;
    hasMore: boolean;
    limit: number;
    offset: number;
}

export interface NodeStats {
    totalNodes: number;
    onlineNodes: number;
    offlineNodes: number;
    disqualifiedNodes: number;
    suspendedNodes: number;
    exitingNodes: number;
    usedCapacity: number;
    averageLatency: number;
}

export interface Project {
    id: string;
    name: string;
    description: string;
    userAgent: string;
    owner: {
        id: string;
        fullName: string;
        email: string;
    };
    createdAt: string;
    defaultPlacement: number;
    rateLimit: number | null;
    burstLimit: number | null;
    maxBuckets: number | null;
    bandwidthLimit: number | null;
    bandwidthUsed: number;
    storageLimit: number | null;
    storageUsed: number | null;
    segmentLimit: number | null;
    segmentUsed: number | null;
}

export interface ProjectListResponse {
    projects: Project[];
    pageCount: number;
    currentPage: number;
    totalCount: number;
    hasMore: boolean;
    limit: number;
    offset: number;
}

export interface ProjectLimits {
    maxBuckets: number;
    storageLimit: number;
    bandwidthLimit: number;
    segmentLimit: number;
    rateLimit: number;
    burstLimit: number;
}

export interface ProjectLimitsUpdate {
    maxBuckets: number;
    storageLimit: number;
    bandwidthLimit: number;
    segmentLimit: number;
    rateLimit: number;
    burstLimit: number;
}

export interface APIKey {
    id: string;
    name: string;
    createdAt: string;
    lastUsed: string;
}

export interface UserLimits {
    projectLimit: number;
    projectStorageLimit: number;
    projectBandwidthLimit: number;
    defaultPlacement: number;
}

export interface UserLimitsUpdate {
    projectLimit: number;
    projectStorageLimit: number;
    projectBandwidthLimit: number;
    defaultPlacement: number;
}

class APIError extends Error {
    constructor(
        public readonly msg: string,
        public readonly responseStatusCode?: number,
    ) {
        super(msg);
    }
}

export class AdminApi {
    private readonly http: AdminHttpClient = new AdminHttpClient();
    private readonly ROOT_PATH: string = '/api';

    // User Management APIs
    public async getAllUsers(params?: {
        limit?: number;
        page?: number;
        status?: string;
        search?: string;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }): Promise<UserListResponse> {
        const queryParams = new URLSearchParams();
        if (params?.limit) queryParams.append('limit', params.limit.toString());
        if (params?.page) queryParams.append('page', params.page.toString());
        if (params?.status) queryParams.append('status', params.status);
        if (params?.search) queryParams.append('search', params.search);
        if (params?.sortBy) queryParams.append('sort_by', params.sortBy);
        if (params?.sortOrder) queryParams.append('sort_order', params.sortOrder);

        const fullPath = `${this.ROOT_PATH}/users${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as UserListResponse);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch users', response.status);
    }

    public async getUserByEmail(email: string): Promise<User> {
        const fullPath = `${this.ROOT_PATH}/users/${email}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as User);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch user', response.status);
    }

    public async getUserInfo(email: string): Promise<{
        user: {
            id: string;
            fullName: string;
            email: string;
            projectLimit: number;
            placement: number;
            paidTier: boolean;
            createdAt: string;
            status: number;
            userAgent: string;
        };
        projects: {
            id: string;
            publicId: string;
            name: string;
            description: string;
            ownerId: string;
            createdAt: string;
            storageLimit: number | null;
            bandwidthLimit: number | null;
            segmentLimit: number | null;
            storageUsed: number | null;
            bandwidthUsed: number;
            segmentUsed: number | null;
            storageUsedPercentage: number;
            defaultPlacement: number;
        }[];
    }> {
        const fullPath = `${this.ROOT_PATH}/users/${email}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as {
                user: {
                    id: string;
                    fullName: string;
                    email: string;
                    projectLimit: number;
                    placement: number;
                    paidTier: boolean;
                    createdAt: string;
                    status: number;
                    userAgent: string;
                };
                projects: {
                    id: string;
                    publicId: string;
                    name: string;
                    description: string;
                    ownerId: string;
                    createdAt: string;
                    storageLimit: number | null;
                    bandwidthLimit: number | null;
                    segmentLimit: number | null;
                    storageUsed: number | null;
                    bandwidthUsed: number;
                    segmentUsed: number | null;
                    storageUsedPercentage: number;
                    defaultPlacement: number;
                }[];
            });
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch user info', response.status);
    }

    public async getUserLimits(email: string): Promise<UserLimits> {
        const fullPath = `${this.ROOT_PATH}/users/${email}/limits`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as UserLimits);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch user limits', response.status);
    }

    public async updateUserLimits(email: string, limits: UserLimitsUpdate): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${email}/limits`;
        const response = await this.http.put(fullPath, JSON.stringify(limits));
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update user limits', response.status);
    }

    public async createUser(userData: {
        email: string;
        fullName: string;
        password: string;
        signupPromoCode?: string;
    }): Promise<User> {
        const fullPath = `${this.ROOT_PATH}/users`;
        const response = await this.http.post(fullPath, JSON.stringify(userData));
        if (response.ok) {
            return response.json().then((body) => body as User);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to create user', response.status);
    }

    public async updateUser(email: string, userData: {
        fullName: string;
        projectLimit: number;
        projectStorageLimit: number;
        projectBandwidthLimit: number;
        defaultPlacement: number;
        status?: number;
    }): Promise<User> {
        const fullPath = `${this.ROOT_PATH}/users/${email}`;
        const response = await this.http.put(fullPath, JSON.stringify(userData));
        if (response.ok) {
            return response.json().then((body) => body as User);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update user', response.status);
    }

    public async deleteUser(email: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${email}`;
        const response = await this.http.delete(fullPath, null);
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to delete user', response.status);
    }

    public async disableUserMFA(email: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/mfa`;
        const response = await this.http.delete(fullPath, null);
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to disable user MFA', response.status);
    }

    public async updateUserStatus(email: string, status: number): Promise<User> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/status`;
        const response = await this.http.put(fullPath, JSON.stringify({ status }));
        if (response.ok) {
            return response.json().then((body) => body as User);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update user status', response.status);
    }

    public async updateUsersUserAgent(email: string, userAgent: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/useragent`;
        const response = await this.http.patch(fullPath, JSON.stringify({ userAgent }));
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update user agent', response.status);
    }

    public async createGeofenceForAccount(email: string, placement: number): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/geofence`;
        const response = await this.http.patch(fullPath, JSON.stringify({ placement }));
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to create geofence for account', response.status);
    }

    public async deleteGeofenceForAccount(email: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/geofence`;
        const response = await this.http.delete(fullPath, null);
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to delete geofence for account', response.status);
    }

    public async updateFreeTrialExpiration(email: string, expirationDate: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/trial-expiration`;
        const response = await this.http.patch(fullPath, JSON.stringify({ expirationDate }));
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update free trial expiration', response.status);
    }

    public async billingFreezeUser(email: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/billing-freeze`;
        const response = await this.http.put(fullPath, JSON.stringify({}));
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to freeze user billing', response.status);
    }

    public async suspendUser(email: string): Promise<void> {
        return this.billingFreezeUser(email);
    }

    public async unsuspendUser(email: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/users/${email}/billing-freeze`;
        const response = await this.http.delete(fullPath, null);
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to unsuspend user', response.status);
    }

    public async deactivateUserAccount(email: string): Promise<User> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(email)}/deactivate-account`;
        const response = await this.http.put(fullPath, JSON.stringify({}));
        if (response.ok) {
            return response.json().then((body) => body as User);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to deactivate user account', response.status);
    }

    // Project Management APIs
    public async getAllProjects(params?: {
        limit?: number;
        page?: number;
        search?: string;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }): Promise<ProjectListResponse> {
        const queryParams = new URLSearchParams();
        if (params?.limit) queryParams.append('limit', params.limit.toString());
        if (params?.page) queryParams.append('page', params.page.toString());
        if (params?.search) queryParams.append('search', params.search);
        if (params?.sortBy) queryParams.append('sort_by', params.sortBy);
        if (params?.sortOrder) queryParams.append('sort_order', params.sortOrder);

        const fullPath = `${this.ROOT_PATH}/projects${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as ProjectListResponse);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch projects', response.status);
    }

    public async getProject(projectId: string): Promise<Project> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as Project);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch project', response.status);
    }

    public async getProjectLimits(projectId: string): Promise<ProjectLimits> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}/limit`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as ProjectLimits);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch project limits', response.status);
    }

    public async updateProjectLimits(projectId: string, limits: ProjectLimitsUpdate): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}/limit`;
        const response = await this.http.put(fullPath, JSON.stringify(limits));
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update project limits', response.status);
    }


    public async updateProject(projectId: string, projectData: {
        name: string;
        description: string;
        defaultPlacement: number;
    }): Promise<Project> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}`;
        const response = await this.http.put(fullPath, JSON.stringify(projectData));
        if (response.ok) {
            return response.json().then((body) => body as Project);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to update project', response.status);
    }

    public async deleteProject(projectId: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}`;
        const response = await this.http.delete(fullPath, null);
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to delete project', response.status);
    }

    public async getProjectUsage(projectId: string): Promise<{
        bandwidthUsed: number;
        storageUsed: number | null;
        segmentUsed: number | null;
    }> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}/usage`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as {
                bandwidthUsed: number;
                storageUsed: number | null;
                segmentUsed: number | null;
            });
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch project usage', response.status);
    }

    public async getProjectAPIKeys(projectId: string): Promise<APIKey[]> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}/apikeys`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as APIKey[]);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch project API keys', response.status);
    }

    public async createProjectAPIKey(projectId: string, keyData: { name: string }): Promise<APIKey> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}/apikeys`;
        const response = await this.http.post(fullPath, JSON.stringify(keyData));
        if (response.ok) {
            return response.json().then((body) => body as APIKey);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to create API key', response.status);
    }

    public async deleteProjectAPIKey(projectId: string, keyName: string): Promise<void> {
        const fullPath = `${this.ROOT_PATH}/projects/${projectId}/apikeys?name=${keyName}`;
        const response = await this.http.delete(fullPath, null);
        if (response.ok) {
            return;
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to delete API key', response.status);
    }

    // Node Management APIs
    public async getAllNodes(params?: {
        limit?: number;
        page?: number;
        status?: string;
        country?: string;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
    }): Promise<NodeListResponse> {
        const queryParams = new URLSearchParams();
        if (params?.limit) queryParams.append('limit', params.limit.toString());
        if (params?.page) queryParams.append('page', params.page.toString());
        if (params?.status) queryParams.append('status', params.status);
        if (params?.country) queryParams.append('country', params.country);
        if (params?.sortBy) queryParams.append('sort_by', params.sortBy);
        if (params?.sortOrder) queryParams.append('sort_order', params.sortOrder);

        const fullPath = `${this.ROOT_PATH}/nodes${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as NodeListResponse);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch nodes', response.status);
    }

    public async getNodeDetails(nodeId: string): Promise<Node> {
        const fullPath = `${this.ROOT_PATH}/nodes/${nodeId}`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as Node);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch node details', response.status);
    }

    public async getNodeStats(): Promise<NodeStats> {
        const fullPath = `${this.ROOT_PATH}/nodes/stats`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as NodeStats);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch node stats', response.status);
    }

    // Dashboard Statistics APIs
    public async getDashboardStats(): Promise<{
        totalAccounts: number;
        active: number;
        inactive: number;
        deleted: number;
        pendingDeletion: number;
        legalHold: number;
        pendingBotVerification: number;
        pro: number;
        free: number;
    }> {
        // This would need to be implemented in server.go
        // For now, we'll calculate from users data
        const users = await this.getAllUsers({ limit: 1000 });
        const stats = {
            totalAccounts: users.totalCount,
            active: 0,
            inactive: 0,
            deleted: 0,
            pendingDeletion: 0,
            legalHold: 0,
            pendingBotVerification: 0,
            pro: 0,
            free: 0,
        };

        // Count by status and account type
        users.users.forEach(user => {
            // Count by status (0=Inactive, 1=Active, 2=Deleted, 3=PendingDeletion, 4=LegalHold, 5=PendingBotVerification)
            switch (user.status) {
                case 0:
                    stats.inactive++;
                    break;
                case 1:
                    stats.active++;
                    break;
                case 2:
                    stats.deleted++;
                    break;
                case 3:
                    stats.pendingDeletion++;
                    break;
                case 4:
                    stats.legalHold++;
                    break;
                case 5:
                    stats.pendingBotVerification++;
                    break;
            }
            
            // Count by account type based on paidTier
            if (user.paidTier) {
                stats.pro++;
            } else {
                stats.free++;
            }
        });

        return stats;
    }

    // User Details API
    public async getUserDetails(userEmail: string): Promise<UserDetails> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(userEmail)}/details`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as UserDetails);
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch user details', response.status);
    }

    public async getUserLoginHistory(userEmail: string): Promise<{
        userEmail: string;
        total: number;
        sessions: LoginHistoryEntry[];
    }> {
        const fullPath = `${this.ROOT_PATH}/users/${encodeURIComponent(userEmail)}/login-history`;
        const response = await this.http.get(fullPath);
        if (response.ok) {
            return response.json().then((body) => body as {
                userEmail: string;
                total: number;
                sessions: LoginHistoryEntry[];
            });
        }
        const err = await response.json();
        throw new APIError(err.error || err.detail || 'Failed to fetch user login history', response.status);
    }
}

// User Details Types
export interface ProjectWithUsage {
    id: string;
    publicId: string;
    name: string;
    description: string;
    ownerId: string;
    createdAt: string;
    storageUsed: number;
    bandwidthUsed: number;
    segmentUsed: number;
}

export interface LoginHistoryEntry {
    id: string;
    ipAddress: string;
    userAgent: string;
    status: number;
    loginTime: string;
    expiresAt: string;
    isActive: boolean;
}

export interface UserDetails {
    id: string;
    fullName: string;
    email: string;
    status: number;
    createdAt: string;
    paidTier: boolean;
    projectStorageLimit: number;
    projectBandwidthLimit: number;
    projectSegmentLimit: number;
    defaultPlacement: number;
    source: string;
    utmSource: string;
    utmMedium: string;
    utmCampaign: string;
    utmTerm: string;
    utmContent: string;
    projects: ProjectWithUsage[];
}

// Export a singleton instance
export const adminApi = new AdminApi();
