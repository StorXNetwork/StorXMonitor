/**
 * TypeScript type definitions
 */

export interface Developer {
    id: string;
    fullName: string;
    email: string;
    companyName: string;
    createdAt: string;
    status: number;
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

