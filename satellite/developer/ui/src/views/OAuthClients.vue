<template>
    <div>
        <v-container>
            <v-row>
                <v-col cols="12">
                    <div class="d-flex justify-space-between align-center mb-4">
                        <h1 class="text-h4">OAuth Clients</h1>
                        <v-btn color="primary" @click="showCreateDialog = true">
                            <v-icon start>mdi-plus</v-icon>
                            Create Client
                        </v-btn>
                    </div>
                </v-col>
            </v-row>

            <v-row>
                <v-col cols="12">
                    <v-card>
                        <v-card-text>
                            <v-data-table
                                :headers="headers"
                                :items="clients"
                                :loading="loading"
                                class="elevation-1"
                            >
                                <template v-slot:item.status="{ item }">
                                    <v-chip
                                        :color="item.status === 1 ? 'success' : 'error'"
                                        size="small"
                                    >
                                        {{ item.status === 1 ? 'Active' : 'Inactive' }}
                                    </v-chip>
                                </template>

                                <template v-slot:item.actions="{ item }">
                                    <v-btn
                                        icon="mdi-delete"
                                        size="small"
                                        variant="text"
                                        @click="deleteClient(item.id)"
                                    />
                                </template>
                            </v-data-table>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>
        </v-container>

        <!-- Create OAuth Client Dialog -->
        <v-dialog v-model="showCreateDialog" max-width="600">
            <v-card>
                <v-card-title>Create OAuth Client</v-card-title>
                <v-card-text>
                    <v-form ref="createForm" @submit.prevent="createClient">
                        <v-text-field
                            v-model="newClient.name"
                            label="Client Name"
                            variant="outlined"
                            required
                            class="mb-2"
                        />

                        <v-textarea
                            v-model="newClient.redirectUrisText"
                            label="Redirect URIs (one per line)"
                            variant="outlined"
                            rows="4"
                            required
                            class="mb-2"
                        />
                    </v-form>
                </v-card-text>
                <v-card-actions>
                    <v-spacer />
                    <v-btn @click="showCreateDialog = false">Cancel</v-btn>
                    <v-btn color="primary" @click="createClient" :loading="creating">
                        Create
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>

        <!-- Client Secret Dialog -->
        <v-dialog v-model="showSecretDialog" max-width="500">
            <v-card>
                <v-card-title>OAuth Client Created</v-card-title>
                <v-card-text>
                    <v-alert type="warning" variant="tonal" class="mb-4">
                        <strong>Important:</strong> Save your client secret now. You won't be able to see it again!
                    </v-alert>
                    <v-text-field
                        :model-value="newClientSecret.clientId"
                        label="Client ID"
                        readonly
                        variant="outlined"
                        class="mb-2"
                    />
                    <v-text-field
                        :model-value="newClientSecret.clientSecret"
                        label="Client Secret"
                        readonly
                        variant="outlined"
                        type="password"
                    />
                </v-card-text>
                <v-card-actions>
                    <v-spacer />
                    <v-btn color="primary" @click="showSecretDialog = false">Close</v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>
    </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { developerApi, type OAuthClient } from '@/api/developerApi';
import { formatDateTime } from '@/utils/formatters';

const clients = ref<OAuthClient[]>([]);
const loading = ref(false);
const creating = ref(false);
const showCreateDialog = ref(false);
const showSecretDialog = ref(false);
const newClient = ref({ name: '', redirectUrisText: '' });
const newClientSecret = ref({ clientId: '', clientSecret: '' });
const createForm = ref();

const headers = [
    { title: 'Name', key: 'name' },
    { title: 'Client ID', key: 'clientId' },
    { title: 'Status', key: 'status' },
    { title: 'Created', key: 'createdAt', value: (item: OAuthClient) => formatDateTime(item.createdAt) },
    { title: 'Actions', key: 'actions', sortable: false },
];

onMounted(() => {
    loadClients();
});

async function loadClients() {
    loading.value = true;
    try {
        clients.value = await developerApi.listOAuthClients();
    } catch (error) {
        console.error('Failed to load OAuth clients:', error);
    } finally {
        loading.value = false;
    }
}

async function createClient() {
    const { valid } = await createForm.value.validate();
    if (!valid) return;

    creating.value = true;
    try {
        const redirectUris = newClient.value.redirectUrisText
            .split('\n')
            .map(uri => uri.trim())
            .filter(uri => uri.length > 0);

        const result = await developerApi.createOAuthClient(newClient.value.name, redirectUris);
        newClientSecret.value = result;
        showCreateDialog.value = false;
        showSecretDialog.value = true;
        newClient.value = { name: '', redirectUrisText: '' };
        await loadClients();
    } catch (error) {
        console.error('Failed to create OAuth client:', error);
    } finally {
        creating.value = false;
    }
}

async function deleteClient(id: string) {
    if (!confirm('Are you sure you want to delete this OAuth client?')) return;

    try {
        await developerApi.deleteOAuthClient(id);
        await loadClients();
    } catch (error) {
        console.error('Failed to delete OAuth client:', error);
    }
}
</script>

