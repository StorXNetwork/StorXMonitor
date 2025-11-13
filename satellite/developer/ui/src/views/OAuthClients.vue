<template>
    <div class="oauth-clients-page">
        <!-- Page Header -->
        <div class="page-header">
            <div class="header-content">
                <div>
                    <h1 class="page-title">OAuth Applications</h1>
                    <p class="page-subtitle">Manage your OAuth2 client applications and credentials</p>
                </div>
                <div class="header-actions">
                    <v-btn
                        variant="outlined"
                        prepend-icon="mdi-download"
                        @click="exportToCSV"
                        :disabled="filteredClients.length === 0"
                    >
                        Export CSV
                    </v-btn>
                    <v-btn
                        variant="outlined"
                        prepend-icon="mdi-refresh"
                        @click="loadClients"
                        :loading="loading"
                    >
                        Refresh
                    </v-btn>
                    <v-btn
                        color="primary"
                        prepend-icon="mdi-plus-circle"
                        @click="openCreateDialog"
                    >
                        New Application
                    </v-btn>
                </div>
            </div>
        </div>

        <v-container fluid class="pa-4">
            <!-- Statistics Cards -->
            <v-row class="mb-4">
                <v-col cols="12" sm="6" md="3">
                    <v-card class="stat-card stat-card-primary" elevation="0" variant="outlined">
                        <v-card-text class="d-flex align-center">
                            <div class="stat-icon-wrapper stat-icon-primary">
                                <v-icon size="28" color="primary">mdi-application</v-icon>
                            </div>
                            <div class="ml-4">
                                <div class="stat-label">Total Applications</div>
                                <div class="stat-value text-primary">{{ stats.total }}</div>
                            </div>
                        </v-card-text>
                    </v-card>
                </v-col>
                <v-col cols="12" sm="6" md="3">
                    <v-card class="stat-card stat-card-success" elevation="0" variant="outlined">
                        <v-card-text class="d-flex align-center">
                            <div class="stat-icon-wrapper stat-icon-success">
                                <v-icon size="28" color="success">mdi-check-circle</v-icon>
                            </div>
                            <div class="ml-4">
                                <div class="stat-label">Active</div>
                                <div class="stat-value text-success">{{ stats.active }}</div>
                            </div>
                        </v-card-text>
                    </v-card>
                </v-col>
                <v-col cols="12" sm="6" md="3">
                    <v-card class="stat-card stat-card-warning" elevation="0" variant="outlined">
                        <v-card-text class="d-flex align-center">
                            <div class="stat-icon-wrapper stat-icon-warning">
                                <v-icon size="28" color="warning">mdi-pause-circle</v-icon>
                            </div>
                            <div class="ml-4">
                                <div class="stat-label">Inactive</div>
                                <div class="stat-value text-warning">{{ stats.inactive }}</div>
                            </div>
                        </v-card-text>
                    </v-card>
                </v-col>
                <v-col cols="12" sm="6" md="3">
                    <v-card class="stat-card stat-card-info" elevation="0" variant="outlined">
                        <v-card-text class="d-flex align-center">
                            <div class="stat-icon-wrapper stat-icon-info">
                                <v-icon size="28" color="info">mdi-calendar-month</v-icon>
                            </div>
                            <div class="ml-4">
                                <div class="stat-label">This Month</div>
                                <div class="stat-value text-info">{{ stats.thisMonth }}</div>
                            </div>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>

            <!-- Filters Card -->
            <v-card class="filters-card mb-4" elevation="0" variant="outlined">
                <v-card-text class="pa-4">
                    <div class="d-flex justify-space-between align-center mb-3">
                        <div class="d-flex align-center">
                            <v-icon class="mr-2" size="20">mdi-filter-variant</v-icon>
                            <span class="text-subtitle-1 font-weight-medium">Filters</span>
                        </div>
                        <v-btn
                            variant="text"
                            size="small"
                            :prepend-icon="showAdvancedFilters ? 'mdi-chevron-up' : 'mdi-chevron-down'"
                            @click="showAdvancedFilters = !showAdvancedFilters"
                        >
                            {{ showAdvancedFilters ? 'Hide' : 'Show' }} Advanced
                        </v-btn>
                    </div>
                    <v-row>
                        <v-col cols="12" md="6">
                            <v-text-field
                                v-model="searchQuery"
                                label="Search applications"
                                prepend-inner-icon="mdi-magnify"
                                variant="outlined"
                                density="compact"
                                clearable
                                hide-details
                                @update:model-value="applyFilters"
                            />
                        </v-col>
                        <v-col cols="12" md="3">
                            <v-select
                                v-model="statusFilter"
                                label="Status"
                                :items="statusOptions"
                                variant="outlined"
                                density="compact"
                                clearable
                                hide-details
                                @update:model-value="applyFilters"
                            />
                        </v-col>
                        <v-col cols="12" md="3">
                            <v-btn
                                variant="text"
                                size="small"
                                prepend-icon="mdi-filter-off"
                                @click="clearFilters"
                                :disabled="!hasActiveFilters"
                            >
                                Clear Filters
                            </v-btn>
                        </v-col>
                    </v-row>
                    <v-expand-transition>
                        <v-row v-if="showAdvancedFilters" class="mt-2">
                            <v-col cols="12" md="6">
                                <v-text-field
                                    v-model="dateRange.start"
                                    label="Created After"
                                    type="date"
                                    variant="outlined"
                                    density="compact"
                                    hide-details
                                    @update:model-value="applyFilters"
                                />
                            </v-col>
                            <v-col cols="12" md="6">
                                <v-text-field
                                    v-model="dateRange.end"
                                    label="Created Before"
                                    type="date"
                                    variant="outlined"
                                    density="compact"
                                    hide-details
                                    @update:model-value="applyFilters"
                                />
                            </v-col>
                        </v-row>
                    </v-expand-transition>
                </v-card-text>
            </v-card>

            <!-- Applications Table -->
            <v-card class="table-card" elevation="0" variant="outlined">
                <v-card-text class="pa-0">
                    <v-data-table
                        :headers="headers"
                        :items="filteredClients"
                        :loading="loading"
                        :sort-by="[{ key: 'createdAt', order: 'desc' }]"
                        class="admin-data-table"
                        item-value="id"
                        :items-per-page="25"
                        :items-per-page-options="[10, 25, 50, 100]"
                    >
                        <template v-slot:item.name="{ item }">
                            <div class="d-flex align-center py-2">
                                <div class="app-icon-wrapper">
                                    <v-icon size="24" color="primary">mdi-application</v-icon>
                                </div>
                                <div class="ml-3">
                                    <div class="app-name">{{ item.name }}</div>
                                    <div v-if="item.description" class="app-description">
                                        {{ truncate(item.description, 50) }}
                                    </div>
                                </div>
                            </div>
                        </template>

                        <template v-slot:item.clientId="{ item }">
                            <div class="d-flex align-center">
                                <code class="client-id-code">{{ truncate(item.clientId, 20) }}</code>
                                <v-btn
                                    icon="mdi-content-copy"
                                    size="x-small"
                                    variant="text"
                                    @click="copyToClipboard(item.clientId)"
                                    class="copy-btn ml-1"
                                />
                            </div>
                        </template>

                        <template v-slot:item.status="{ item }">
                            <StatusChip :status="item.status" />
                        </template>

                        <template v-slot:item.redirectUris="{ item }">
                            <div v-if="item.redirectUris && item.redirectUris.length > 0" class="uris-cell">
                                <v-tooltip v-for="(uri, idx) in item.redirectUris.slice(0, 1)" :key="idx">
                                    <template v-slot:activator="{ props }">
                                        <v-chip
                                            v-bind="props"
                                            size="x-small"
                                            variant="outlined"
                                            color="primary"
                                            class="mr-1 mb-1"
                                        >
                                            {{ truncate(uri, 20) }}
                                        </v-chip>
                                    </template>
                                    <span>{{ uri }}</span>
                                </v-tooltip>
                                <v-chip
                                    v-if="item.redirectUris.length > 1"
                                    size="x-small"
                                    variant="text"
                                    class="mr-1 mb-1"
                                >
                                    +{{ item.redirectUris.length - 1 }} more
                                </v-chip>
                            </div>
                            <span v-else class="text-medium-emphasis">—</span>
                        </template>

                        <template v-slot:item.scopes="{ item }">
                            <div v-if="item.scopes && item.scopes.length > 0" class="scopes-cell">
                                <v-chip
                                    v-for="(scope, idx) in item.scopes.slice(0, 2)"
                                    :key="idx"
                                    size="x-small"
                                    variant="tonal"
                                    color="primary"
                                    class="mr-1 mb-1"
                                >
                                    {{ scope }}
                                </v-chip>
                                <v-chip
                                    v-if="item.scopes.length > 2"
                                    size="x-small"
                                    variant="text"
                                    class="mr-1 mb-1"
                                >
                                    +{{ item.scopes.length - 2 }}
                                </v-chip>
                            </div>
                            <span v-else class="text-medium-emphasis">—</span>
                        </template>

                        <template v-slot:item.createdAt="{ item }">
                            <div class="date-cell">
                                <div class="date-value">{{ formatDate(item.createdAt) }}</div>
                                <div class="date-time">{{ formatTime(item.createdAt) }}</div>
                            </div>
                        </template>

                        <template v-slot:item.actions="{ item }">
                            <ActionMenu>
                                <v-list-item
                                    prepend-icon="mdi-eye-outline"
                                    title="View Details"
                                    @click="viewClient(item)"
                                />
                                <v-list-item
                                    prepend-icon="mdi-pencil-outline"
                                    title="Edit"
                                    @click="editClient(item)"
                                />
                                <v-list-item
                                    prepend-icon="mdi-key-variant"
                                    title="Regenerate Secret"
                                    @click="regenerateSecret(item)"
                                />
                                <v-list-item
                                    :prepend-icon="item.status === 1 ? 'mdi-pause' : 'mdi-play'"
                                    :title="item.status === 1 ? 'Deactivate' : 'Activate'"
                                    @click="toggleStatus(item)"
                                />
                                <v-divider class="my-1" />
                                <v-list-item
                                    prepend-icon="mdi-delete-outline"
                                    title="Delete"
                                    class="text-error"
                                    @click="confirmDelete(item)"
                                />
                            </ActionMenu>
                        </template>

                        <template v-slot:no-data>
                            <div class="text-center py-12">
                                <v-icon size="64" color="grey-lighten-1" class="mb-4">mdi-application-outline</v-icon>
                                <div class="text-h6 text-medium-emphasis mb-2">No OAuth Applications</div>
                                <div class="text-body-2 text-medium-emphasis mb-4">
                                    Get started by creating your first OAuth application
                                </div>
                                <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateDialog">
                                    Create Application
                                </v-btn>
                            </div>
                        </template>
                    </v-data-table>
                </v-card-text>
            </v-card>
        </v-container>

        <!-- Create/Edit Dialog -->
        <v-dialog v-model="showClientDialog" max-width="700" persistent scrollable>
            <v-card>
                <v-card-title class="dialog-header">
                    <div class="d-flex align-center">
                        <v-icon class="mr-3" size="28" color="primary">
                            {{ editingClient ? 'mdi-pencil' : 'mdi-plus-circle' }}
                        </v-icon>
                        <span class="text-h6">{{ editingClient ? 'Edit Application' : 'Create OAuth Application' }}</span>
                    </div>
                    <v-btn icon="mdi-close" variant="text" size="small" @click="closeClientDialog" />
                </v-card-title>
                <v-divider />
                <v-card-text class="dialog-content">
                    <v-form ref="clientFormRef" v-model="formValid">
                        <div class="form-section">
                            <div class="section-label">Application Information</div>
                            <v-text-field
                                v-model="clientForm.name"
                                label="Application Name *"
                                variant="outlined"
                                :rules="[rules.required]"
                                prepend-inner-icon="mdi-application"
                                class="mb-4"
                                hint="A descriptive name for your OAuth application"
                                persistent-hint
                            />

                            <v-textarea
                                v-model="clientForm.description"
                                label="Description"
                                variant="outlined"
                                rows="3"
                                prepend-inner-icon="mdi-text"
                                hint="Optional description of what this application does"
                                persistent-hint
                                class="mb-4"
                            />
                        </div>

                        <div class="form-section">
                            <div class="section-label">Configuration</div>
                            <v-textarea
                                v-model="clientForm.redirectUrisText"
                                label="Redirect URIs *"
                                variant="outlined"
                                rows="4"
                                prepend-inner-icon="mdi-link"
                                :rules="[rules.required, rules.redirectUris]"
                                hint="One URI per line. Must be HTTPS (except localhost for development)"
                                persistent-hint
                                class="mb-4"
                            />

                            <v-textarea
                                v-model="clientForm.scopesText"
                                label="Scopes"
                                variant="outlined"
                                rows="3"
                                prepend-inner-icon="mdi-shield-check"
                                hint="One scope per line (e.g., files:read, files:write, buckets:read)"
                                persistent-hint
                                class="mb-4"
                            />
                        </div>
                    </v-form>
                </v-card-text>
                <v-divider />
                <v-card-actions class="dialog-actions">
                    <v-spacer />
                    <v-btn variant="text" @click="closeClientDialog">Cancel</v-btn>
                    <v-btn
                        color="primary"
                        @click="saveClient"
                        :loading="saving"
                        :disabled="!formValid"
                        prepend-icon="mdi-content-save"
                    >
                        {{ editingClient ? 'Update' : 'Create' }}
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>

        <!-- View Details Dialog -->
        <v-dialog v-model="showViewDialog" max-width="700" scrollable>
            <v-card>
                <v-card-title class="dialog-header">
                    <div class="d-flex align-center">
                        <v-icon class="mr-3" size="28" color="primary">mdi-information</v-icon>
                        <span class="text-h6">Application Details</span>
                    </div>
                    <v-btn icon="mdi-close" variant="text" size="small" @click="showViewDialog = false" />
                </v-card-title>
                <v-divider />
                <v-card-text class="dialog-content">
                    <div v-if="loading" class="text-center py-8">
                        <v-progress-circular indeterminate color="primary" />
                        <p class="mt-4 text-body-2 text-medium-emphasis">Loading client details...</p>
                    </div>
                    <div v-else-if="viewingClient" class="detail-section">
                        <div class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-application</v-icon>
                                Application Name
                            </div>
                            <div class="detail-value">{{ viewingClient.name }}</div>
                        </div>
                        <div v-if="viewingClient.description" class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-text</v-icon>
                                Description
                            </div>
                            <div class="detail-value">{{ viewingClient.description }}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-identifier</v-icon>
                                Client ID
                            </div>
                            <div class="detail-value">
                                <code class="client-id-display">{{ viewingClient.clientId }}</code>
                                <v-btn
                                    icon="mdi-content-copy"
                                    size="small"
                                    variant="text"
                                    @click="copyToClipboard(viewingClient.clientId)"
                                    class="ml-2"
                                />
                            </div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-toggle-switch</v-icon>
                                Status
                            </div>
                            <div class="detail-value">
                                <StatusChip :status="viewingClient.status" />
                            </div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-link</v-icon>
                                Redirect URIs
                            </div>
                            <div class="detail-value">
                                <div v-for="(uri, idx) in viewingClient.redirectUris" :key="idx" class="uri-item">
                                    <code>{{ uri }}</code>
                                </div>
                            </div>
                        </div>
                        <div v-if="viewingClient.scopes && viewingClient.scopes.length > 0" class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-shield-check</v-icon>
                                Scopes
                            </div>
                            <div class="detail-value">
                                <v-chip
                                    v-for="(scope, idx) in viewingClient.scopes"
                                    :key="idx"
                                    size="small"
                                    variant="tonal"
                                    color="primary"
                                    class="mr-1 mb-1"
                                >
                                    {{ scope }}
                                </v-chip>
                            </div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-calendar-plus</v-icon>
                                Created
                            </div>
                            <div class="detail-value">{{ formatDateTime(viewingClient.createdAt) }}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">
                                <v-icon size="18" class="mr-2">mdi-calendar-edit</v-icon>
                                Last Updated
                            </div>
                            <div class="detail-value">{{ formatDateTime(viewingClient.updatedAt) }}</div>
                        </div>
                    </div>
                    <div v-else class="text-center py-8">
                        <v-icon size="48" color="error" class="mb-4">mdi-alert-circle</v-icon>
                        <p class="text-body-1">Failed to load client details</p>
                    </div>
                </v-card-text>
                <v-divider />
                <v-card-actions class="dialog-actions">
                    <v-spacer />
                    <v-btn color="primary" @click="showViewDialog = false">Close</v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>

        <!-- Secret Display Dialog -->
        <v-dialog v-model="showSecretDialog" max-width="650" persistent>
            <v-card>
                <v-card-title class="dialog-header">
                    <div class="d-flex align-center">
                        <v-icon class="mr-3" size="28" color="warning">mdi-alert</v-icon>
                        <span class="text-h6">{{ secretDialogTitle }}</span>
                    </div>
                </v-card-title>
                <v-divider />
                <v-card-text class="dialog-content">
                    <v-alert type="warning" variant="tonal" class="mb-6">
                        <div class="d-flex align-start">
                            <v-icon class="mr-2 mt-1">mdi-alert-circle</v-icon>
                            <div>
                                <strong>Important Security Notice</strong>
                                <div class="mt-2">
                                    Save your client secret immediately. You won't be able to view it again after closing this dialog.
                                    Store it securely in your application configuration.
                                </div>
                            </div>
                        </div>
                    </v-alert>
                    <div class="secret-fields">
                        <div class="secret-field">
                            <label class="secret-label">
                                <v-icon size="18" class="mr-2">mdi-identifier</v-icon>
                                Client ID
                            </label>
                            <v-text-field
                                :model-value="secretData.clientId"
                                readonly
                                variant="outlined"
                                density="comfortable"
                                class="secret-input"
                            >
                                <template v-slot:append-inner>
                                    <v-btn
                                        icon="mdi-content-copy"
                                        variant="text"
                                        size="small"
                                        @click="copyToClipboard(secretData.clientId)"
                                    />
                                </template>
                            </v-text-field>
                        </div>
                        <div class="secret-field">
                            <label class="secret-label">
                                <v-icon size="18" class="mr-2">mdi-key</v-icon>
                                Client Secret
                            </label>
                            <v-text-field
                                :model-value="secretData.clientSecret"
                                readonly
                                variant="outlined"
                                density="comfortable"
                                :type="showSecret ? 'text' : 'password'"
                                class="secret-input secret-input-field"
                                hide-details
                            >
                                <template v-slot:append-inner>
                                    <div class="secret-actions">
                                        <v-btn
                                            :icon="showSecret ? 'mdi-eye-off' : 'mdi-eye'"
                                            variant="text"
                                            size="small"
                                            @click="showSecret = !showSecret"
                                            class="secret-action-btn"
                                        />
                                        <v-btn
                                            icon="mdi-content-copy"
                                            variant="text"
                                            size="small"
                                            @click="copyToClipboard(secretData.clientSecret)"
                                            class="secret-action-btn"
                                        />
                                    </div>
                                </template>
                            </v-text-field>
                        </div>
                    </div>
                </v-card-text>
                <v-divider />
                <v-card-actions class="dialog-actions">
                    <v-spacer />
                    <v-btn color="primary" prepend-icon="mdi-check" @click="showSecretDialog = false">
                        I've Saved It
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>

        <!-- Delete Confirmation Dialog -->
        <v-dialog v-model="showDeleteDialog" max-width="550">
            <v-card>
                <v-card-title class="dialog-header">
                    <div class="d-flex align-center">
                        <v-icon class="mr-3" size="28" color="error">mdi-alert-circle</v-icon>
                        <span class="text-h6 text-error">Confirm Deletion</span>
                    </div>
                </v-card-title>
                <v-divider />
                <v-card-text class="dialog-content">
                    <v-alert type="error" variant="tonal" class="mb-4">
                        This action cannot be undone.
                    </v-alert>
                    <p class="text-body-1 mb-2">
                        Are you sure you want to delete <strong>{{ deletingClient?.name }}</strong>?
                    </p>
                    <p class="text-body-2 text-medium-emphasis">
                        All existing access tokens for this application will be invalidated immediately.
                    </p>
                </v-card-text>
                <v-divider />
                <v-card-actions class="dialog-actions">
                    <v-spacer />
                    <v-btn variant="text" @click="showDeleteDialog = false">Cancel</v-btn>
                    <v-btn
                        color="error"
                        prepend-icon="mdi-delete"
                        @click="deleteClient"
                        :loading="deleting"
                    >
                        Delete Application
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>

        <!-- Regenerate Secret Confirmation Dialog -->
        <v-dialog v-model="showRegenerateSecretDialog" max-width="550">
            <v-card>
                <v-card-title class="dialog-header">
                    <div class="d-flex align-center">
                        <v-icon class="mr-3" size="28" color="warning">mdi-key-variant</v-icon>
                        <span class="text-h6 text-warning">Regenerate Client Secret</span>
                    </div>
                </v-card-title>
                <v-divider />
                <v-card-text class="dialog-content">
                    <v-alert type="warning" variant="tonal" class="mb-4">
                        <strong>Important:</strong> The old client secret will be invalidated immediately and cannot be recovered.
                    </v-alert>
                    <p class="text-body-1 mb-2">
                        Are you sure you want to regenerate the client secret for <strong>{{ regeneratingClient?.name }}</strong>?
                    </p>
                    <p class="text-body-2 text-medium-emphasis">
                        All applications using the current secret will stop working until you update them with the new secret. Make sure to save the new secret immediately after regeneration.
                    </p>
                </v-card-text>
                <v-divider />
                <v-card-actions class="dialog-actions">
                    <v-spacer />
                    <v-btn variant="text" @click="showRegenerateSecretDialog = false">Cancel</v-btn>
                    <v-btn
                        color="warning"
                        prepend-icon="mdi-key-variant"
                        @click="confirmRegenerateSecret"
                        :loading="regenerating"
                    >
                        Regenerate Secret
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>
    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { developerApi, type OAuthClient } from '@/api/developerApi';
import { formatDateTime, formatDate, formatTime } from '@/utils/formatters';
import StatusChip from '@/components/StatusChip.vue';
import ActionMenu from '@/components/ActionMenu.vue';

// Data
const clients = ref<OAuthClient[]>([]);
const loading = ref(false);
const saving = ref(false);
const deleting = ref(false);
const showClientDialog = ref(false);
const showViewDialog = ref(false);
const showSecretDialog = ref(false);
const showDeleteDialog = ref(false);
const showRegenerateSecretDialog = ref(false);
const showAdvancedFilters = ref(false);
const showSecret = ref(true); // Show secret by default since it's a one-time view
const editingClient = ref<OAuthClient | null>(null);
const viewingClient = ref<OAuthClient | null>(null);
const deletingClient = ref<OAuthClient | null>(null);
const regeneratingClient = ref<OAuthClient | null>(null);
const regenerating = ref(false);
const secretData = ref({ clientId: '', clientSecret: '' });
const secretDialogTitle = ref('OAuth Application Created');

// Filters
const searchQuery = ref('');
const statusFilter = ref<number | null>(null);
const dateRange = ref({ start: '', end: '' });

// Form
const clientForm = ref({
    name: '',
    description: '',
    redirectUrisText: '',
    scopesText: '',
});
const formValid = ref(false);
const clientFormRef = ref();

// Rules
const rules = {
    required: (v: string) => !!v || 'This field is required',
    redirectUris: (v: string) => {
        if (!v) return true;
        const uris = v.split('\n').map(u => u.trim()).filter(u => u);
        if (uris.length === 0) return 'At least one redirect URI is required';
        const invalid = uris.find(uri => {
            try {
                const url = new URL(uri);
                return url.protocol !== 'https:' && !uri.startsWith('http://localhost');
            } catch {
                return true;
            }
        });
        return !invalid || 'All URIs must be valid HTTPS URLs (or localhost for development)';
    },
};

// Statistics
const stats = computed(() => {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    return {
        total: clients.value.length,
        active: clients.value.filter(c => c.status === 1).length,
        inactive: clients.value.filter(c => c.status === 0).length,
        thisMonth: clients.value.filter(c => new Date(c.createdAt) >= startOfMonth).length,
    };
});

// Status options
const statusOptions = [
    { title: 'Active', value: 1 },
    { title: 'Inactive', value: 0 },
];

// Table headers
const headers = [
    { title: 'APPLICATION', key: 'name', sortable: true },
    { title: 'CLIENT ID', key: 'clientId', sortable: true },
    { title: 'STATUS', key: 'status', sortable: true },
    { title: 'REDIRECT URIS', key: 'redirectUris', sortable: false },
    { title: 'SCOPES', key: 'scopes', sortable: false },
    { title: 'CREATED', key: 'createdAt', sortable: true },
    { title: '', key: 'actions', sortable: false, width: '50px', align: 'end' as const },
];

// Filtered clients
const filteredClients = computed(() => {
    let filtered = [...clients.value];

    if (searchQuery.value) {
        const query = searchQuery.value.toLowerCase();
        filtered = filtered.filter(
            c =>
                c.name.toLowerCase().includes(query) ||
                c.clientId.toLowerCase().includes(query) ||
                (c.description && c.description.toLowerCase().includes(query))
        );
    }

    if (statusFilter.value !== null) {
        filtered = filtered.filter(c => c.status === statusFilter.value);
    }

    if (dateRange.value.start) {
        const start = new Date(dateRange.value.start);
        filtered = filtered.filter(c => new Date(c.createdAt) >= start);
    }
    if (dateRange.value.end) {
        const end = new Date(dateRange.value.end);
        end.setHours(23, 59, 59, 999);
        filtered = filtered.filter(c => new Date(c.createdAt) <= end);
    }

    return filtered;
});

const hasActiveFilters = computed(() => {
    return !!(searchQuery.value || statusFilter.value !== null || dateRange.value.start || dateRange.value.end);
});

// Methods
function truncate(text: string, length: number): string {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

function applyFilters() {
    // Filters are applied reactively via computed property
}

function clearFilters() {
    searchQuery.value = '';
    statusFilter.value = null;
    dateRange.value = { start: '', end: '' };
    showAdvancedFilters.value = false;
}

function openCreateDialog() {
    editingClient.value = null;
    clientForm.value = {
        name: '',
        description: '',
        redirectUrisText: '',
        scopesText: '',
    };
    showClientDialog.value = true;
}

function editClient(client: OAuthClient) {
    editingClient.value = client;
    clientForm.value = {
        name: client.name,
        description: client.description || '',
        redirectUrisText: client.redirectUris.join('\n'),
        scopesText: (client.scopes || []).join('\n'),
    };
    showClientDialog.value = true;
}

async function viewClient(client: OAuthClient) {
    loading.value = true;
    try {
        // Fetch full client details from API to ensure we have all data
        viewingClient.value = await developerApi.getOAuthClient(client.id);
        showViewDialog.value = true;
    } catch (error: any) {
        console.error('Failed to load client details:', error);
        alert(error.message || 'Failed to load client details');
    } finally {
        loading.value = false;
    }
}

function closeClientDialog() {
    showClientDialog.value = false;
    editingClient.value = null;
    clientForm.value = {
        name: '',
        description: '',
        redirectUrisText: '',
        scopesText: '',
    };
}

async function saveClient() {
    const { valid } = await clientFormRef.value.validate();
    if (!valid) return;

    saving.value = true;
    try {
        const redirectUris = clientForm.value.redirectUrisText
            .split('\n')
            .map(uri => uri.trim())
            .filter(uri => uri.length > 0);
        const scopes = clientForm.value.scopesText
            .split('\n')
            .map(scope => scope.trim())
            .filter(scope => scope.length > 0);

        if (editingClient.value) {
            await developerApi.updateOAuthClient(editingClient.value.id, {
                name: clientForm.value.name,
                description: clientForm.value.description || undefined,
                redirectUris,
                scopes: scopes.length > 0 ? scopes : undefined,
            });
        } else {
            const result = await developerApi.createOAuthClient(
                clientForm.value.name,
                redirectUris,
                clientForm.value.description || undefined,
                scopes.length > 0 ? scopes : undefined
            );
            secretData.value = result;
            secretDialogTitle.value = 'OAuth Application Created';
            showSecret.value = true; // Show secret by default so user can see it
            showSecretDialog.value = true;
        }
        closeClientDialog();
        await loadClients();
    } catch (error: any) {
        alert(error.message || 'Failed to save application');
    } finally {
        saving.value = false;
    }
}

function regenerateSecret(client: OAuthClient) {
    regeneratingClient.value = client;
    showRegenerateSecretDialog.value = true;
}

async function confirmRegenerateSecret() {
    if (!regeneratingClient.value) return;
    regenerating.value = true;
    try {
        const result = await developerApi.regenerateOAuthClientSecret(regeneratingClient.value.id);
        secretData.value = result;
        secretDialogTitle.value = 'Client Secret Regenerated';
        showSecret.value = true; // Show secret by default so user can see it
        showRegenerateSecretDialog.value = false;
        regeneratingClient.value = null;
        showSecretDialog.value = true;
        await loadClients();
    } catch (error: any) {
        alert(error.message || 'Failed to regenerate secret');
    } finally {
        regenerating.value = false;
    }
}

async function toggleStatus(client: OAuthClient) {
    const newStatus = client.status === 1 ? 0 : 1;
    try {
        await developerApi.updateOAuthClientStatus(client.id, newStatus);
        await loadClients();
    } catch (error: any) {
        alert(error.message || 'Failed to update status');
    }
}

function confirmDelete(client: OAuthClient) {
    deletingClient.value = client;
    showDeleteDialog.value = true;
}

async function deleteClient() {
    if (!deletingClient.value) return;
    deleting.value = true;
    try {
        await developerApi.deleteOAuthClient(deletingClient.value.id);
        showDeleteDialog.value = false;
        deletingClient.value = null;
        await loadClients();
    } catch (error: any) {
        alert(error.message || 'Failed to delete application');
    } finally {
        deleting.value = false;
    }
}

function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    // Could add toast notification here
}

function exportToCSV() {
    const headers = ['Name', 'Client ID', 'Status', 'Description', 'Redirect URIs', 'Scopes', 'Created', 'Updated'];
    const rows = filteredClients.value.map(client => [
        client.name,
        client.clientId,
        client.status === 1 ? 'Active' : 'Inactive',
        client.description || '',
        client.redirectUris.join('; '),
        (client.scopes || []).join('; '),
        formatDateTime(client.createdAt),
        formatDateTime(client.updatedAt),
    ]);

    const csv = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `oauth-applications-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
}

async function loadClients() {
    loading.value = true;
    try {
        clients.value = await developerApi.listOAuthClients();
    } catch (error: any) {
        alert(error.message || 'Failed to load OAuth applications');
    } finally {
        loading.value = false;
    }
}

onMounted(() => {
    loadClients();
});
</script>

<style scoped lang="scss">
.oauth-clients-page {
    padding: 0;
    background: #f5f7fa;
    min-height: 100vh;
}

// Page Header
.page-header {
    background: #ffffff;
    padding: 24px 0;
    margin-bottom: 24px;
    border-bottom: 1px solid rgba(0, 0, 0, 0.08);
}

.header-content {
    max-width: 100%;
    margin: 0 auto;
    padding: 0 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}

.page-title {
    font-size: 24px;
    font-weight: 600;
    color: #111827;
    margin: 0 0 4px 0;
    line-height: 1.2;
}

.page-subtitle {
    font-size: 14px;
    color: #6b7280;
    margin: 0;
}

.header-actions {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}

// Statistics Cards
.stat-card {
    border-radius: 8px;
    transition: all 0.2s ease;
    height: 100%;
}

.stat-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stat-icon-wrapper {
    width: 48px;
    height: 48px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.stat-icon-primary {
    background: rgba(102, 126, 234, 0.1);
}

.stat-icon-success {
    background: rgba(76, 175, 80, 0.1);
}

.stat-icon-warning {
    background: rgba(255, 152, 0, 0.1);
}

.stat-icon-info {
    background: rgba(33, 150, 243, 0.1);
}

.stat-label {
    font-size: 12px;
    color: #6b7280;
    font-weight: 500;
    margin-bottom: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-value {
    font-size: 24px;
    font-weight: 700;
    line-height: 1.2;
}

// Filters Card
.filters-card {
    border-radius: 8px;
    background: #ffffff;
}

// Table Card
.table-card {
    border-radius: 8px;
    background: #ffffff;
    overflow: hidden;
}

:deep(.admin-data-table) {
    .v-data-table__thead {
        background: #f5f7fa;
    }

    .v-data-table__th {
        font-weight: 600;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #6b7280;
        padding: 16px;
    }

    .v-data-table__td {
        padding: 16px;
        border-bottom: 1px solid rgba(0, 0, 0, 0.08);
    }

    .v-data-table__tr:hover {
        background: #f9fafb;
    }
}

.app-icon-wrapper {
    width: 40px;
    height: 40px;
    border-radius: 8px;
    background: rgba(102, 126, 234, 0.1);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}

.app-name {
    font-weight: 600;
    font-size: 14px;
    color: #111827;
    margin-bottom: 2px;
}

.app-description {
    font-size: 12px;
    color: #6b7280;
    line-height: 1.4;
}

.client-id-code {
    background: #f3f4f6;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    color: #111827;
}

.copy-btn {
    opacity: 0;
    transition: opacity 0.2s;
}

.d-flex:hover .copy-btn {
    opacity: 1;
}

.uris-cell,
.scopes-cell {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
}

.date-cell {
    display: flex;
    flex-direction: column;
}

.date-value {
    font-size: 13px;
    font-weight: 500;
    color: #111827;
}

.date-time {
    font-size: 11px;
    color: #6b7280;
    margin-top: 2px;
}

// Dialogs
.dialog-header {
    padding: 20px 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #f9fafb;
    border-bottom: 1px solid rgba(0, 0, 0, 0.08);
}

.dialog-content {
    padding: 24px;
    max-height: 70vh;
    overflow-y: auto;
}

.dialog-actions {
    padding: 16px 24px;
    background: #f9fafb;
    border-top: 1px solid rgba(0, 0, 0, 0.08);
}

.form-section {
    margin-bottom: 24px;
}

.section-label {
    font-size: 13px;
    font-weight: 600;
    color: #374151;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid rgba(0, 0, 0, 0.08);
}

.detail-section {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.detail-item {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.detail-label {
    font-size: 12px;
    font-weight: 600;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
}

.detail-value {
    font-size: 14px;
    color: #111827;
    font-weight: 500;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
}

.client-id-display {
    background: #f3f4f6;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 13px;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    color: #111827;
}

.uri-item {
    margin-bottom: 8px;
    code {
        background: #f3f4f6;
        padding: 6px 10px;
        border-radius: 6px;
        font-size: 12px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        color: #111827;
    }
}

.secret-fields {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.secret-field {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.secret-label {
    font-size: 13px;
    font-weight: 600;
    color: #374151;
    display: flex;
    align-items: center;
    margin-bottom: 8px;
}

.secret-input-wrapper {
    position: relative;
}

.secret-input {
    :deep(.v-field__input) {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        letter-spacing: 0.5px;
        color: #111827;
    }
    
    :deep(input) {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        letter-spacing: 0.5px;
        color: #111827 !important;
    }
}

.secret-input-field {
    :deep(.v-field__input) {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        letter-spacing: 0.5px;
        color: #111827;
    }
    
    :deep(input) {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        letter-spacing: 0.5px;
        color: #111827 !important;
    }
}

.secret-actions {
    display: flex;
    align-items: center;
    gap: 4px;
}

.secret-action-btn {
    min-width: 32px;
    width: 32px;
    height: 32px;
}

// Responsive
@media (max-width: 960px) {
    .header-content {
        flex-direction: column;
        align-items: flex-start;
    }

    .header-actions {
        width: 100%;
        justify-content: flex-start;
    }
}
</style>
