// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

import { BaseGql } from '@/api/baseGql';
import {
    AccessGrant,
    AccessGrantCursor,
    AccessGrantsApi,
    AccessGrantsPage,
    EdgeCredentials,
} from '@/types/accessGrants';
import { HttpClient } from '@/utils/httpClient';
import { APIError } from '@/utils/error';

/**
 * AccessGrantsApiGql is a graphql implementation of Access Grants API.
 * Exposes all access grants-related functionality
 */
export class AccessGrantsApiGql extends BaseGql implements AccessGrantsApi {
    private readonly client: HttpClient = new HttpClient();
    private readonly ROOT_PATH: string = '/api/v0/api-keys';

    /**
     * Fetch access grants.
     *
     * @returns AccessGrantsPage
     * @throws Error
     */
    public async get(projectId: string, cursor: AccessGrantCursor): Promise<AccessGrantsPage> {
        const path = `${this.ROOT_PATH}/list-paged?projectID=${projectId}&search=${cursor.search}&limit=${cursor.limit}&page=${cursor.page}&order=${cursor.order}&orderDirection=${cursor.orderDirection}`;
        const response = await this.client.get(path);

        if (!response.ok) {
            throw new APIError({
                status: response.status,
                message: 'Can not get API keys',
                requestID: response.headers.get('x-request-id'),
            });
        }

        const apiKeys = await response.json();

        return this.getAccessGrantsPage(apiKeys);
    }

    /**
     * Used to create access grant.
     *
     * @param projectId - stores current project id
     * @param name - name of access grant that will be created
     * @returns AccessGrant
     * @throws Error
     */
    public async create(projectId: string, name: string): Promise<AccessGrant> {
        const query =
            `mutation($projectId: String!, $name: String!) {
                createAPIKey(
                    publicId: $projectId,
                    name: $name
                ) {
                    key,
                    keyInfo {
                        id,
                        name,
                        createdAt
                    }
                }
            }`;

        const variables = {
            projectId,
            name,
        };

        const response = await this.mutate(query, variables);
        const key = response.data.createAPIKey.keyInfo;
        const secret: string = response.data.createAPIKey.key;

        return new AccessGrant(key.id, key.name, key.createdAt, secret);
    }

    /**
     * Used to delete access grant.
     *
     * @param ids - ids of access grants that will be deleted
     * @throws Error
     */
    public async delete(ids: string[]): Promise<void> {
        const query =
            `mutation($id: [String!]!) {
                deleteAPIKeys(id: $id) {
                    id
                }
            }`;

        const variables = {
            id: ids,
        };

        const response = await this.mutate(query, variables);

        return response.data.deleteAPIKeys;
    }

    /**
     * Fetch all API key names.
     *
     * @returns string[]
     * @throws Error
     */
    public async getAllAPIKeyNames(projectId: string): Promise<string[]> {
        const path = `${this.ROOT_PATH}/api-key-names?projectID=${projectId}`;
        const response = await this.client.get(path);

        if (!response.ok) {
            throw new APIError({
                status: response.status,
                message: 'Can not get access grant names',
                requestID: response.headers.get('x-request-id'),
            });
        }

        const result = await response.json();

        return result ? result : [];
    }

    /**
     * Used to delete access grant by name and project ID.
     *
     * @param name - name of the access grant that will be deleted
     * @param projectID - id of the project where access grant was created
     * @throws Error
     */
    public async deleteByNameAndProjectID(name: string, projectID: string): Promise<void> {
        const path = `${this.ROOT_PATH}/delete-by-name?name=${name}&publicID=${projectID}`;
        const response = await this.client.delete(path);

        if (response.ok || response.status === 204) {
            return;
        }

        throw new APIError({
            status: response.status,
            message: 'Can not delete access grant',
            requestID: response.headers.get('x-request-id'),
        });
    }

    /**
     * Used to get gateway credentials using access grant.
     *
     * @param accessGrant - generated access grant
     * @param requestURL - URL to which gateway credential requests are sent
     * @param isPublic - optional status
     * @throws Error
     */
    public async getGatewayCredentials(accessGrant: string, requestURL: string, isPublic?: boolean): Promise<EdgeCredentials> {
        const path = `${requestURL}/v1/access`;
        const body = {
            access_grant: accessGrant,
            public: isPublic || false,
        };
        const response = await this.client.post(path, JSON.stringify(body));
        if (!response.ok) {
            throw new APIError({
                status: response.status,
                message: 'Can not get gateway credentials',
                requestID: response.headers.get('x-request-id'),
            });
        }

        const result = await response.json();

        return new EdgeCredentials(
            result.id,
            new Date(result.created_at),
            result.access_key_id,
            result.secret_key,
            result.endpoint,
        );
    }

    /**
     * Method for mapping access grants page from json to AccessGrantsPage type.
     *
     * @param page anonymous object from json
     */
    private getAccessGrantsPage(page: any): AccessGrantsPage { // eslint-disable-line @typescript-eslint/no-explicit-any
        if (!(page && page.apiKeys)) {
            return new AccessGrantsPage();
        }

        const accessGrantsPage: AccessGrantsPage = new AccessGrantsPage();

        accessGrantsPage.accessGrants = page.apiKeys.map(key => new AccessGrant(
            key.id,
            key.name,
            new Date(key.createdAt),
            '',
        ));

        accessGrantsPage.search = page.search;
        accessGrantsPage.limit = page.limit;
        accessGrantsPage.order = page.order;
        accessGrantsPage.orderDirection = page.orderDirection;
        accessGrantsPage.pageCount = page.pageCount;
        accessGrantsPage.currentPage = page.currentPage;
        accessGrantsPage.totalCount = page.totalCount;

        return accessGrantsPage;
    }
}
