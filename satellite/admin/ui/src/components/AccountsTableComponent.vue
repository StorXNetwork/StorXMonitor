// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-card variant="flat" rounded="xlg" border class="mb-4" elevation="0" style="background: #ffffff;">
        <!-- Filter Section -->
        <v-card-text class="pa-6">
            <!-- Header -->
            <div class="d-flex align-center justify-space-between mb-6">
                <div class="d-flex align-center gap-3">
                    <div class="d-flex align-center justify-center" style="width: 40px; height: 40px; background: linear-gradient(135deg, rgba(var(--v-theme-primary), 0.1), rgba(var(--v-theme-primary), 0.05)); border-radius: 12px;">
                        <v-icon icon="mdi-filter-variant" size="24" color="primary"></v-icon>
                    </div>
                    <div>
                        <span class="text-h6 font-weight-bold" style="color: #1e1e1e;">Filters</span>
                        <v-chip v-if="activeFiltersCount > 0" size="small" color="primary" variant="flat" class="ml-3">
                            {{ activeFiltersCount }} active
                        </v-chip>
                    </div>
                </div>
                <v-btn
                    v-if="activeFiltersCount > 0"
                    variant="outlined"
                    color="error"
                    size="small"
                    prepend-icon="mdi-close-circle"
                    @click="clearAllFilters"
                    style="border-radius: 8px;"
                >
                    Clear All
                </v-btn>
            </div>

            <!-- Quick Filters Row -->
            <div class="mb-8">
                <div class="d-flex flex-wrap align-center quick-filters-container">
                    <v-text-field
                        v-model="search"
                        label="Search users"
                        prepend-inner-icon="mdi-magnify"
                        variant="outlined"
                        density="comfortable"
                        hide-details
                        clearable
                        rounded="lg"
                        class="flex-grow-1"
                        style="min-width: 300px; max-width: 450px;"
                        @input="debouncedLoadUsers"
                    />

                    <v-select
                        v-model="statusFilter"
                        label="Status"
                        prepend-inner-icon="mdi-account-check-outline"
                        variant="outlined"
                        density="comfortable"
                        hide-details
                        clearable
                        rounded="lg"
                        :items="statusOptions"
                        item-title="text"
                        item-value="value"
                        style="min-width: 180px; max-width: 220px;"
                        @update:model-value="loadUsers"
                    />

                    <v-select
                        v-model="tierFilter"
                        label="Tier"
                        prepend-inner-icon="mdi-crown-outline"
                        variant="outlined"
                        density="comfortable"
                        hide-details
                        clearable
                        rounded="lg"
                        :items="tierOptions"
                        item-title="text"
                        item-value="value"
                        style="min-width: 160px; max-width: 200px;"
                        @update:model-value="loadUsers"
                    />

                    <v-select
                        v-model="sourceFilter"
                        label="Signup Source"
                        prepend-inner-icon="mdi-source-commit"
                        variant="outlined"
                        density="comfortable"
                        hide-details
                        clearable
                        rounded="lg"
                        :items="sourceOptions"
                        item-title="text"
                        item-value="value"
                        style="min-width: 200px; max-width: 250px;"
                        @update:model-value="debouncedLoadUsers"
                    />

                    <v-select
                        v-model="createdDateRange"
                        label="Created Date"
                        prepend-inner-icon="mdi-calendar-range"
                        :items="createdDateRangeOptions"
                        item-title="text"
                        item-value="value"
                        variant="outlined"
                        density="comfortable"
                        hide-details
                        clearable
                        rounded="lg"
                        style="min-width: 180px; max-width: 220px;"
                        @update:model-value="handleCreatedDateRangeChange"
                    />
                    
                    <div v-if="createdDateRange === 'custom'" class="d-flex align-center gap-3">
                        <v-text-field
                            v-model="createdAfterCustom"
                            label="Created After"
                            prepend-inner-icon="mdi-calendar-start"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            type="date"
                            rounded="lg"
                            style="min-width: 180px; max-width: 220px;"
                            @update:model-value="debouncedLoadUsers"
                        />
                        <v-icon icon="mdi-arrow-right" size="20" color="primary"></v-icon>
                        <v-text-field
                            v-model="createdBeforeCustom"
                            label="Created Before"
                            prepend-inner-icon="mdi-calendar-end"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            type="date"
                            rounded="lg"
                            style="min-width: 180px; max-width: 220px;"
                            @update:model-value="debouncedLoadUsers"
                        />
                    </div>
                </div>
            </div>

            <!-- Active Filter Chips -->
            <div v-if="activeFiltersCount > 0" class="d-flex flex-wrap align-center gap-2 mb-6 pa-4" style="background: linear-gradient(135deg, rgba(var(--v-theme-primary), 0.08), rgba(var(--v-theme-primary), 0.03)); border: 1px solid rgba(var(--v-theme-primary), 0.15); border-radius: 16px;">
                <span class="text-body-2 font-weight-medium mr-2" style="color: rgba(var(--v-theme-primary), 0.9);">Active filters:</span>
                <v-chip
                    v-if="statusFilter"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="statusFilter = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-account-check-outline" size="16"></v-icon>
                    Status: {{ getStatusText(parseInt(statusFilter)) }}
                </v-chip>
                <v-chip
                    v-if="tierFilter"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="tierFilter = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-crown-outline" size="16"></v-icon>
                    Tier: {{ tierFilter === 'paid' ? 'Paid' : 'Free' }}
                </v-chip>
                <v-chip
                    v-if="storageMin || storageMax"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="storageMin = null; storageMax = null; loadUsers()"
                >
                    <v-icon start icon="mdi-harddisk" size="16"></v-icon>
                    Storage: {{ formatStorageRange() }}
                </v-chip>
                <v-chip
                    v-if="sourceFilter"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="sourceFilter = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-source-commit" size="16"></v-icon>
                    Source: {{ sourceFilter }}
                </v-chip>
                <v-chip
                    v-if="createdDateRange && createdDateRange !== 'custom'"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="createdDateRange = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-calendar-range" size="16"></v-icon>
                    Created: {{ createdDateRangeOptions.find(opt => opt.value === createdDateRange)?.text || createdDateRange }}
                </v-chip>
                <v-chip
                    v-if="createdDateRange === 'custom' && (createdAfterCustom || createdBeforeCustom)"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="createdDateRange = ''; createdAfterCustom = ''; createdBeforeCustom = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-calendar-range" size="16"></v-icon>
                    Created: {{ createdAfterCustom || 'Any' }} - {{ createdBeforeCustom || 'Any' }}
                </v-chip>
                <v-chip
                    v-if="hasActiveSession"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="hasActiveSession = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-login" size="16"></v-icon>
                    Active Session: {{ hasActiveSession === 'true' ? 'Yes' : 'No' }}
                </v-chip>
                <v-chip
                    v-if="lastSessionAfter || lastSessionBefore"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="lastSessionAfter = ''; lastSessionBefore = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-clock-outline" size="16"></v-icon>
                    Last Session: {{ lastSessionAfter || 'Any' }} - {{ lastSessionBefore || 'Any' }}
                </v-chip>
                <v-chip
                    v-if="sessionCountMin || sessionCountMax"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="sessionCountMin = null; sessionCountMax = null; loadUsers()"
                >
                    <v-icon start icon="mdi-counter" size="16"></v-icon>
                    Sessions: {{ sessionCountMin || 0 }} - {{ sessionCountMax || '∞' }}
                </v-chip>
            </div>

            <!-- Advanced Filters Section -->
            <v-expand-transition>
                <v-card v-if="showAdvancedFilters" elevation="0" class="pa-6" rounded="xl" style="background: linear-gradient(135deg, rgba(var(--v-theme-primary), 0.04), rgba(var(--v-theme-primary), 0.01)); border: 1px solid rgba(var(--v-theme-primary), 0.12);">
                    <div class="d-flex align-center justify-space-between mb-6">
                        <div class="d-flex align-center gap-3">
                            <div class="d-flex align-center justify-center" style="width: 36px; height: 36px; background: rgba(var(--v-theme-primary), 0.1); border-radius: 10px;">
                                <v-icon icon="mdi-tune-variant" size="20" color="primary"></v-icon>
                            </div>
                            <span class="text-h6 font-weight-bold" style="color: #1e1e1e;">Advanced Filters</span>
                        </div>
                        <v-btn
                            icon
                            size="small"
                            variant="text"
                            @click="showAdvancedFilters = false"
                            style="border-radius: 8px;"
                        >
                            <v-icon>mdi-chevron-up</v-icon>
                        </v-btn>
                    </div>

                    <div class="d-flex flex-column gap-5">
                        <!-- Storage Section -->
                        <div class="filter-group">
                            <div class="filter-group-header mb-5">
                                <v-icon icon="mdi-database" size="20" color="primary" class="mr-2"></v-icon>
                                <span class="text-subtitle-1 font-weight-semibold" style="color: #1e1e1e;">Storage</span>
                            </div>
                            <div class="d-flex align-center gap-5">
                                <v-text-field
                                    v-model.number="storageMin"
                                    label="Min Storage"
                                    prepend-inner-icon="mdi-harddisk"
                                    variant="outlined"
                                    density="comfortable"
                                    hide-details
                                    type="number"
                                    rounded="lg"
                                    class="flex-grow-1"
                                    style="max-width: 250px;"
                                    @input="debouncedLoadUsers"
                                />
                                <v-icon icon="mdi-arrow-right" size="24" color="primary" class="mx-3"></v-icon>
                                <v-text-field
                                    v-model.number="storageMax"
                                    label="Max Storage"
                                    prepend-inner-icon="mdi-harddisk-plus"
                                    variant="outlined"
                                    density="comfortable"
                                    hide-details
                                    type="number"
                                    rounded="lg"
                                    class="flex-grow-1"
                                    style="max-width: 250px;"
                                    @input="debouncedLoadUsers"
                                />
                            </div>
                        </div>

                        <!-- Divider -->
                        <v-divider class="my-5" style="opacity: 0.3;"></v-divider>

                        <!-- Session Filters Section -->
                        <div class="filter-group">
                            <div class="filter-group-header mb-6">
                                <div class="d-flex align-center justify-center mr-2" style="width: 32px; height: 32px; background: rgba(var(--v-theme-primary), 0.1); border-radius: 8px;">
                                    <v-icon icon="mdi-login" size="18" color="primary"></v-icon>
                                </div>
                                <span class="text-subtitle-1 font-weight-semibold" style="color: #1e1e1e;">Session Filters</span>
                            </div>

                            <div class="d-flex flex-column gap-5">
                                <!-- Active Session Filter -->
                                <div class="session-filter-item">
                                    <v-select
                                        v-model="hasActiveSession"
                                        label="Active Session"
                                        prepend-inner-icon="mdi-login"
                                        :items="activeSessionOptions"
                                        item-title="text"
                                        item-value="value"
                                        variant="outlined"
                                        density="comfortable"
                                        hide-details
                                        clearable
                                        rounded="lg"
                                        style="max-width: 280px;"
                                        @update:model-value="debouncedLoadUsers"
                                    />
                                </div>

                                <!-- Last Session Date Range -->
                                <div class="d-flex align-center gap-5 session-filter-item">
                                    <v-text-field
                                        v-model="lastSessionAfter"
                                        label="Last Session After"
                                        prepend-inner-icon="mdi-clock-start"
                                        variant="outlined"
                                        density="comfortable"
                                        hide-details
                                        type="date"
                                        rounded="lg"
                                        class="flex-grow-1"
                                        style="max-width: 250px;"
                                        @update:model-value="debouncedLoadUsers"
                                    />
                                    <v-icon icon="mdi-arrow-right" size="24" color="primary" class="mx-3"></v-icon>
                                    <v-text-field
                                        v-model="lastSessionBefore"
                                        label="Last Session Before"
                                        prepend-inner-icon="mdi-clock-end"
                                        variant="outlined"
                                        density="comfortable"
                                        hide-details
                                        type="date"
                                        rounded="lg"
                                        class="flex-grow-1"
                                        style="max-width: 250px;"
                                        @update:model-value="debouncedLoadUsers"
                                    />
                                </div>

                                <!-- Session Count Range -->
                                <div class="d-flex align-center gap-5 session-filter-item">
                                    <v-text-field
                                        v-model.number="sessionCountMin"
                                        label="Min Sessions"
                                        prepend-inner-icon="mdi-counter"
                                        variant="outlined"
                                        density="comfortable"
                                        hide-details
                                        type="number"
                                        rounded="lg"
                                        class="flex-grow-1"
                                        style="max-width: 250px;"
                                        @input="debouncedLoadUsers"
                                    />
                                    <v-icon icon="mdi-arrow-right" size="24" color="primary" class="mx-3"></v-icon>
                                    <v-text-field
                                        v-model.number="sessionCountMax"
                                        label="Max Sessions"
                                        prepend-inner-icon="mdi-counter"
                                        variant="outlined"
                                        density="comfortable"
                                        hide-details
                                        type="number"
                                        rounded="lg"
                                        class="flex-grow-1"
                                        style="max-width: 250px;"
                                        @input="debouncedLoadUsers"
                                    />
                                </div>
                            </div>
                        </div>
                    </div>
                </v-card>
            </v-expand-transition>

            <!-- Advanced Filters Toggle -->
            <div class="d-flex justify-center mt-6">
                <v-btn
                    variant="outlined"
                    color="primary"
                    size="default"
                    :prepend-icon="showAdvancedFilters ? 'mdi-chevron-up' : 'mdi-chevron-down'"
                    @click="showAdvancedFilters = !showAdvancedFilters"
                    style="border-radius: 10px; text-transform: none; font-weight: 500; padding: 8px 24px;"
                >
                    {{ showAdvancedFilters ? 'Hide Advanced Filters' : 'Show Advanced Filters' }}
                </v-btn>
            </div>
        </v-card-text>
    </v-card>

    <!-- Data Table Card -->
    <v-card variant="flat" rounded="xlg" border>

        <!-- Loading state -->
        <div v-if="loading" class="d-flex justify-center align-center py-8">
            <v-progress-circular indeterminate color="primary" size="64" />
            <p class="ml-4">Loading users...</p>
        </div>

        <!-- Error state -->
        <v-alert v-else-if="error" type="error" variant="tonal" class="ma-4">
            <v-alert-title>Error loading users</v-alert-title>
            {{ error }}
        </v-alert>

        <!-- Data table -->
        <v-data-table-server
            v-else
            v-model="selected" v-model:sort-by="sortBy" :headers="headers" :items="displayUsers"
            density="comfortable" hover
            :items-per-page="itemsPerPage === -1 ? totalCount : itemsPerPage"
            :items-per-page-options="[
                { title: '10', value: 10 },
                { title: '25', value: 25 },
                { title: '50', value: 50 },
                { title: '100', value: 100 },
                { title: 'All', value: -1 }
            ]"
            :page="currentPage"
            :items-length="totalCount"
            @update:page="handlePageChange"
            @update:items-per-page="handleItemsPerPageChange"
        >
            <template #item.email="{ item }">
                <div class="text-no-wrap">
                    <v-btn
                        variant="outlined" color="default" size="small" class="mr-1 text-caption" density="comfortable" icon
                        width="24" height="24"
                    >
                        <AccountActionsMenu :user-email="item.raw.email" @refresh-accounts="loadUsers" />
                        <v-icon icon="mdi-dots-horizontal" />
                    </v-btn>
                    <v-chip
                        variant="text" color="default" size="small" 
                        class="font-weight-bold pl-1 ml-1 cursor-pointer"
                        @click="navigateToAccountDetails(item.raw.email)"
                    >
                        <template #prepend>
                            <svg class="mr-2" width="24" height="24" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <rect x="0.5" y="0.5" width="31" height="31" rx="10" stroke="currentColor" stroke-opacity="0.2" />
                                <path
                                    d="M16.0695 8.34998C18.7078 8.34998 20.8466 10.4888 20.8466 13.1271C20.8466 14.7102 20.0765 16.1134 18.8905 16.9826C21.2698 17.8565 23.1437 19.7789 23.9536 22.1905C23.9786 22.265 24.0026 22.34 24.0256 22.4154L24.0593 22.5289C24.2169 23.0738 23.9029 23.6434 23.3579 23.801C23.2651 23.8278 23.1691 23.8414 23.0725 23.8414H8.91866C8.35607 23.8414 7.89999 23.3853 7.89999 22.8227C7.89999 22.7434 7.90926 22.6644 7.92758 22.5873L7.93965 22.5412C7.97276 22.4261 8.00827 22.3119 8.04612 22.1988C8.86492 19.7523 10.7783 17.8081 13.2039 16.9494C12.0432 16.0781 11.2924 14.6903 11.2924 13.1271C11.2924 10.4888 13.4312 8.34998 16.0695 8.34998ZM16.0013 17.9724C13.1679 17.9724 10.6651 19.7017 9.62223 22.264L9.59178 22.34H22.4107L22.4102 22.3388C21.3965 19.7624 18.9143 18.0092 16.0905 17.973L16.0013 17.9724ZM16.0695 9.85135C14.2604 9.85135 12.7938 11.3179 12.7938 13.1271C12.7938 14.9362 14.2604 16.4028 16.0695 16.4028C17.8786 16.4028 19.3452 14.9362 19.3452 13.1271C19.3452 11.3179 17.8786 9.85135 16.0695 9.85135Z"
                                    fill="currentColor"
                                />
                            </svg>
                        </template>
                        {{ item.raw.email }}
                    </v-chip>
                </div>
            </template>


            <template #item.status="{ item }">
                <v-chip
                    :color="getColor(item.raw.status)" variant="tonal" size="small" class="font-weight-medium"
                    @click="setSearch(item.raw.status)"
                >
                    {{ item.raw.status }}
                </v-chip>
            </template>

            <template #item.paidTier="{ item }">
                <v-chip variant="tonal" color="default" size="small" @click="setSearch(item.raw.paidTier)">
                    {{ item.raw.paidTier }}
                </v-chip>
            </template>

            <template #item.source="{ item }">
                <v-chip variant="outlined" color="info" size="small">
                    {{ item.raw.source }}
                </v-chip>
            </template>

            <template #item.utmSource="{ item }">
                <span class="text-caption">{{ item.raw.utmSource }}</span>
            </template>

            <template #item.utmMedium="{ item }">
                <span class="text-caption">{{ item.raw.utmMedium }}</span>
            </template>

            <template #item.utmCampaign="{ item }">
                <span class="text-caption">{{ item.raw.utmCampaign }}</span>
            </template>

            <template #item.lastSessionExpiry="{ item }">
                <span class="text-no-wrap text-caption">
                    {{ item.raw.lastSessionExpiry }}
                </span>
            </template>

            <template #item.totalSessionCount="{ item }">
                <v-chip variant="tonal" color="success" size="small">
                    {{ item.raw.totalSessionCount }}
                </v-chip>
            </template>

            <template #item.createdAt="{ item }">
                <span class="text-no-wrap">
                    {{ item.raw.createdAt }}
                </span>
            </template>
        </v-data-table-server>
    </v-card>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue';
import { useRouter } from 'vue-router';
import { VCard, VTextField, VSelect, VBtn, VIcon, VChip, VProgressCircular, VAlert, VAlertTitle, VExpandTransition } from 'vuetify/components';
import { VDataTableServer } from 'vuetify/labs/components';

import AccountActionsMenu from '@/components/AccountActionsMenu.vue';
import { adminApi, type User } from '@/api/adminApi';
import { useAppStore } from '@/store/app';

// Props
const props = defineProps<{
    refreshTrigger?: number;
}>();

// Emits
const emit = defineEmits<{
    'stats-updated': [stats: {
        totalAccounts: number;
        active: number;
        inactive: number;
        deleted: number;
        pendingDeletion: number;
        legalHold: number;
        pendingBotVerification: number;
        pro: number;
        free: number;
    }];
    'export-requested': [users: any[]];
}>();

const router = useRouter();
const appStore = useAppStore();

const search = ref<string>('');
const statusFilter = ref<string>('');
const tierFilter = ref<string>('');
const storageMin = ref<number | null>(null);
const storageMax = ref<number | null>(null);
const sourceFilter = ref<string>('');
const createdDateRange = ref<string>('');
const createdAfterCustom = ref<string>('');
const createdBeforeCustom = ref<string>('');
const hasActiveSession = ref<string>('');
const lastSessionAfter = ref<string>('');
const lastSessionBefore = ref<string>('');
const sessionCountMin = ref<number | null>(null);
const sessionCountMax = ref<number | null>(null);
const showAdvancedFilters = ref(false);
const selected = ref<string[]>([]);
const sortBy = ref([{ key: 'email', order: 'asc' as const }]);
const loading = ref(true);
const error = ref<string | null>(null);
const users = ref<User[]>([]);
const currentPage = ref(1);
const totalPages = ref(1);
const totalCount = ref(0);
const itemsPerPage = ref(50);

const statusOptions = [
    { text: 'All Status', value: '' },
    { text: 'Active', value: '1' },
    { text: 'Inactive', value: '0' },
    { text: 'Deleted', value: '2' },
    { text: 'Pending Deletion', value: '3' },
    { text: 'Legal Hold', value: '4' },
    { text: 'Pending Bot Verification', value: '5' },
];

const tierOptions = [
    { text: 'All Tiers', value: '' },
    { text: 'Paid', value: 'paid' },
    { text: 'Free', value: 'free' },
];

const sourceOptions = [
    { text: 'All Sources', value: '' },
    { text: 'Google', value: 'Google' },
    { text: 'LinkedIn', value: 'LinkedIn' },
    { text: 'Apple', value: 'Apple' },
    { text: 'Referral', value: 'Referral' },
    { text: 'Other', value: 'Other' },
];

const activeSessionOptions = [
    { text: 'All', value: '' },
    { text: 'Has Active Session', value: 'true' },
    { text: 'No Active Session', value: 'false' },
];

const createdDateRangeOptions = [
    { text: 'All Time', value: '' },
    { text: 'Today', value: 'today' },
    { text: 'Yesterday', value: 'yesterday' },
    { text: 'Last Week', value: 'last_week' },
    { text: 'Last Month', value: 'last_month' },
    { text: 'Last Year', value: 'last_year' },
    { text: 'Custom', value: 'custom' },
];

const headers = [
    { title: 'Account', key: 'email' },
    { title: 'Storage', key: 'storageUsed' },
    { title: 'Download', key: 'bandwidthUsed' },
    { title: 'Status', key: 'status' },
    { title: 'Tier', key: 'paidTier' },
    { title: 'Source', key: 'source' },
    { title: 'UTM Source', key: 'utmSource' },
    { title: 'UTM Medium', key: 'utmMedium' },
    { title: 'UTM Campaign', key: 'utmCampaign' },
    { title: 'Last Session', key: 'lastSessionExpiry' },
    { title: 'Sessions', key: 'totalSessionCount' },
    { title: 'Created', key: 'createdAt', align: 'start' as const },
];

// Debounce function for search inputs
let debounceTimer: ReturnType<typeof setTimeout> | null = null;
const debouncedLoadUsers = () => {
    if (debounceTimer) {
        clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
        loadUsers();
    }, 500);
};

// Handle created date range change
const handleCreatedDateRangeChange = () => {
    if (createdDateRange.value !== 'custom') {
        createdAfterCustom.value = '';
        createdBeforeCustom.value = '';
    }
    debouncedLoadUsers();
};

// Clear all filters
const clearAllFilters = () => {
    search.value = '';
    statusFilter.value = '';
    tierFilter.value = '';
    storageMin.value = null;
    storageMax.value = null;
    sourceFilter.value = '';
    createdDateRange.value = '';
    createdAfterCustom.value = '';
    createdBeforeCustom.value = '';
    hasActiveSession.value = '';
    lastSessionAfter.value = '';
    lastSessionBefore.value = '';
    sessionCountMin.value = null;
    sessionCountMax.value = null;
    loadUsers();
};

// Clear advanced filters only
const clearAdvancedFilters = () => {
    storageMin.value = null;
    storageMax.value = null;
    hasActiveSession.value = '';
    lastSessionAfter.value = '';
    lastSessionBefore.value = '';
    sessionCountMin.value = null;
    sessionCountMax.value = null;
    loadUsers();
};

// Count active filters
const activeFiltersCount = computed(() => {
    let count = 0;
    if (search.value) count++;
    if (statusFilter.value) count++;
    if (tierFilter.value) count++;
    if (storageMin.value || storageMax.value) count++;
    if (sourceFilter.value) count++;
    if (createdDateRange.value && createdDateRange.value !== 'custom') count++;
    if (createdDateRange.value === 'custom' && (createdAfterCustom.value || createdBeforeCustom.value)) count++;
    if (hasActiveSession.value) count++;
    if (lastSessionAfter.value || lastSessionBefore.value) count++;
    if (sessionCountMin.value || sessionCountMax.value) count++;
    return count;
});

// Format storage range for chip display
const formatStorageRange = () => {
    const min = storageMin.value ? formatBytes(storageMin.value) : '0';
    const max = storageMax.value ? formatBytes(storageMax.value) : '∞';
    return `${min} - ${max}`;
};

// Load users data
let isLoading = false; // Prevent multiple simultaneous calls
const loadUsers = async () => {
    // Prevent duplicate calls
    if (isLoading) {
        return;
    }
    
    try {
        isLoading = true;
        loading.value = true;
        error.value = null;

        // Handle "All" option - send -1 for limit when "All" is selected
        const limitValue = itemsPerPage.value === -1 ? -1 : itemsPerPage.value;
        
        // Ensure page is at least 1 (Vuetify uses 1-based pagination)
        const pageValue = Math.max(1, currentPage.value);

        // Calculate created date range
        let createdRangeValue: string | undefined;
        let createdAfterValue: string | undefined;
        let createdBeforeValue: string | undefined;
        
        if (createdDateRange.value && createdDateRange.value !== 'custom') {
            // Use preset value - send only one parameter
            createdRangeValue = createdDateRange.value;
        } else if (createdDateRange.value === 'custom') {
            // Use custom dates - send separate after/before
            createdAfterValue = createdAfterCustom.value || undefined;
            createdBeforeValue = createdBeforeCustom.value || undefined;
        }

        const response = await adminApi.getAllUsers({
            limit: limitValue,
            page: pageValue,
            search: search.value || undefined,
            status: statusFilter.value || undefined,
            tier: tierFilter.value ? (tierFilter.value as 'paid' | 'free') : undefined,
            storageMin: storageMin.value ?? undefined,
            storageMax: storageMax.value ?? undefined,
            source: sourceFilter.value || undefined,
            createdRange: createdRangeValue,
            createdAfter: createdAfterValue,
            createdBefore: createdBeforeValue,
            hasActiveSession: hasActiveSession.value ? hasActiveSession.value === 'true' : undefined,
            lastSessionAfter: lastSessionAfter.value || undefined,
            lastSessionBefore: lastSessionBefore.value || undefined,
            sessionCountMin: sessionCountMin.value ?? undefined,
            sessionCountMax: sessionCountMax.value ?? undefined,
            sortBy: sortBy.value[0]?.key || 'email',
            sortOrder: sortBy.value[0]?.order || 'asc',
        });

        users.value = response.users;
        totalPages.value = response.pageCount;
        totalCount.value = response.totalCount;
        
        // Sync currentPage with backend response to ensure consistency
        if (response.currentPage && response.currentPage !== currentPage.value) {
            currentPage.value = response.currentPage;
        }
    } catch (err) {
        console.error('Failed to load users:', err);
        error.value = err instanceof Error ? err.message : 'Unknown error occurred';
    } finally {
        loading.value = false;
        isLoading = false;
    }
};

// Computed properties for display
const displayUsers = computed(() => {
    return users.value.map(user => ({
        ...user,
        status: getStatusText(user.status),
        storageUsed: formatBytes(user.storageUsed),
        bandwidthUsed: formatBytes(user.bandwidthUsed),
        createdAt: formatDate(user.createdAt),
        paidTier: user.paidTier ? 'Paid' : 'Free',
        source: user.source || 'N/A',
        utmSource: user.utmSource || 'N/A',
        utmMedium: user.utmMedium || 'N/A',
        utmCampaign: user.utmCampaign || 'N/A',
        lastSessionExpiry: user.lastSessionExpiry ? formatDate(user.lastSessionExpiry) : 'Never',
        totalSessionCount: user.totalSessionCount || 0,
    }));
});

// Helper functions
const getStatusText = (status: number): string => {
    switch (status) {
        case 0: return 'Inactive';
        case 1: return 'Active';
        case 2: return 'Deleted';
        case 3: return 'Pending Deletion';
        case 4: return 'Legal Hold';
        case 5: return 'Pending Bot Verification';
        default: return 'Unknown';
    }
};


const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    });
};

const getColor = (type: string) => {
    if (type === 'Active') return 'success';
    if (type === 'Inactive') return 'default';
    if (type === 'Deleted') return 'error';
    if (type === 'Pending Deletion') return 'warning';
    if (type === 'Legal Hold') return 'warning';
    if (type === 'Pending Bot Verification') return 'warning';
    if (type === 'Paid') return 'success';
    if (type === 'Never') return 'warning';
    return 'default';
};

const setSearch = (searchText: string) => {
    search.value = searchText;
    loadUsers();
};

// Pagination handlers
const handlePageChange = (page: number) => {
    // Vuetify uses 1-based pagination, ensure page is at least 1
    if (page < 1) {
        currentPage.value = 1;
    } else {
        currentPage.value = page;
    }
    loadUsers();
};

const handleItemsPerPageChange = (itemsPerPageValue: number) => {
    itemsPerPage.value = itemsPerPageValue;
    currentPage.value = 1;
    loadUsers();
};


// Watch for refresh trigger
watch(() => props.refreshTrigger, () => {
    if (props.refreshTrigger && props.refreshTrigger > 0) {
        loadUsers();
    }
});

// Navigation function
const navigateToAccountDetails = async (email: string) => {
    try {
        // Store the email in localStorage or a global store for the AccountDetails page to use
        localStorage.setItem('selectedUserEmail', email);
        // Navigate to account details page
        router.push('/account-details');
    } catch (error) {
        console.error('Failed to navigate to account details:', error);
    }
};


// Export filtered users
const exportFilteredUsers = () => {
    // Emit the current filtered users data
    emit('export-requested', users.value);
};

// Expose method to parent component
defineExpose({
    exportFilteredUsers
});

// Load data on component mount
onMounted(() => {
    loadUsers();
});
</script>

<style scoped>
.filter-group {
    padding: 0;
    margin-bottom: 8px;
}

.filter-group-header {
    display: flex;
    align-items: center;
    padding-bottom: 12px;
    margin-bottom: 16px;
    border-bottom: 1px solid rgba(var(--v-theme-primary), 0.12);
}

.session-filter-item {
    margin-top: 20px;
}

.quick-filters-container {
    gap: 15px;
}
</style>