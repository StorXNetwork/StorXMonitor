// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-card variant="flat" rounded="xlg" border class="mb-4">
        <!-- Filter Section -->
        <v-card-text class="pa-4">
            <div class="d-flex align-center justify-space-between mb-4">
                <div class="d-flex align-center gap-2">
                    <v-icon icon="mdi-filter" size="20" color="primary"></v-icon>
                    <span class="text-h6 font-weight-medium">Filters</span>
                    <v-chip v-if="activeFiltersCount > 0" size="small" color="primary" variant="flat" class="ml-2">
                        {{ activeFiltersCount }} active
                    </v-chip>
                </div>
                <v-btn
                    v-if="activeFiltersCount > 0"
                    variant="text"
                    color="error"
                    size="small"
                    prepend-icon="mdi-close-circle"
                    @click="clearAllFilters"
                >
                    Clear All
                </v-btn>
            </div>

            <!-- Quick Filters Row -->
            <div class="d-flex flex-wrap align-center gap-3 mb-3">
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
                    style="min-width: 280px; max-width: 400px;"
                    @input="debouncedLoadUsers"
                />
                
                <v-text-field
                    v-model="emailFilter"
                    label="Email"
                    prepend-inner-icon="mdi-email-outline"
                    variant="outlined"
                    density="comfortable"
                    hide-details
                    clearable
                    rounded="lg"
                    style="min-width: 220px; max-width: 300px;"
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
                    style="min-width: 160px; max-width: 200px;"
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
                    style="min-width: 140px; max-width: 180px;"
                    @update:model-value="loadUsers"
                />
            </div>

            <!-- Active Filter Chips -->
            <div v-if="activeFiltersCount > 0" class="d-flex flex-wrap align-center gap-2 mb-3 pa-3" style="background-color: rgba(var(--v-theme-primary), 0.05); border-radius: 12px;">
                <span class="text-caption text-medium-emphasis mr-2">Active filters:</span>
                <v-chip
                    v-if="emailFilter"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="emailFilter = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-email-outline" size="16"></v-icon>
                    Email: {{ emailFilter }}
                </v-chip>
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
                    v-if="utmSource"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="utmSource = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-source-branch" size="16"></v-icon>
                    UTM Source: {{ utmSource }}
                </v-chip>
                <v-chip
                    v-if="utmMedium"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="utmMedium = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-source-merge" size="16"></v-icon>
                    UTM Medium: {{ utmMedium }}
                </v-chip>
                <v-chip
                    v-if="utmCampaign"
                    size="small"
                    closable
                    color="primary"
                    variant="tonal"
                    @click:close="utmCampaign = ''; loadUsers()"
                >
                    <v-icon start icon="mdi-bullhorn" size="16"></v-icon>
                    UTM Campaign: {{ utmCampaign }}
                </v-chip>
            </div>

            <!-- Advanced Filters Section -->
            <v-expand-transition>
                <v-card v-if="showAdvancedFilters" variant="tonal" color="primary" class="pa-4" rounded="lg">
                    <div class="d-flex align-center justify-space-between mb-3">
                        <div class="d-flex align-center gap-2">
                            <v-icon icon="mdi-tune" size="20" color="primary"></v-icon>
                            <span class="text-subtitle-1 font-weight-medium">Advanced Filters</span>
                        </div>
                        <v-btn
                            icon
                            size="small"
                            variant="text"
                            @click="showAdvancedFilters = false"
                        >
                            <v-icon>mdi-chevron-up</v-icon>
                        </v-btn>
                    </div>

                    <div class="d-flex flex-wrap align-center gap-3">
                        <!-- Storage Range -->
                        <div class="d-flex align-center gap-2" style="min-width: 100%;">
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
                                style="max-width: 200px;"
                                @input="debouncedLoadUsers"
                            />
                            <v-icon icon="mdi-arrow-right" size="20" class="mx-2"></v-icon>
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
                                style="max-width: 200px;"
                                @input="debouncedLoadUsers"
                            />
                            <v-chip v-if="storageMin || storageMax" size="small" color="info" variant="flat" class="ml-2">
                                {{ formatBytes(storageMin || 0) }} - {{ formatBytes(storageMax || 0) }}
                            </v-chip>
                        </div>

                        <!-- UTM Parameters -->
                        <v-text-field
                            v-model="utmSource"
                            label="UTM Source"
                            prepend-inner-icon="mdi-source-branch"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            clearable
                            rounded="lg"
                            style="min-width: 200px; max-width: 250px;"
                            @input="debouncedLoadUsers"
                        />

                        <v-text-field
                            v-model="utmMedium"
                            label="UTM Medium"
                            prepend-inner-icon="mdi-source-merge"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            clearable
                            rounded="lg"
                            style="min-width: 200px; max-width: 250px;"
                            @input="debouncedLoadUsers"
                        />

                        <v-text-field
                            v-model="utmCampaign"
                            label="UTM Campaign"
                            prepend-inner-icon="mdi-bullhorn"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            clearable
                            rounded="lg"
                            style="min-width: 200px; max-width: 250px;"
                            @input="debouncedLoadUsers"
                        />

                        <v-text-field
                            v-model="utmTerm"
                            label="UTM Term"
                            prepend-inner-icon="mdi-tag-outline"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            clearable
                            rounded="lg"
                            style="min-width: 200px; max-width: 250px;"
                            @input="debouncedLoadUsers"
                        />

                        <v-text-field
                            v-model="utmContent"
                            label="UTM Content"
                            prepend-inner-icon="mdi-content-copy"
                            variant="outlined"
                            density="comfortable"
                            hide-details
                            clearable
                            rounded="lg"
                            style="min-width: 200px; max-width: 250px;"
                            @input="debouncedLoadUsers"
                        />
                    </div>
                </v-card>
            </v-expand-transition>

            <!-- Advanced Filters Toggle -->
            <div class="d-flex justify-center mt-3">
                <v-btn
                    variant="text"
                    color="primary"
                    size="small"
                    :prepend-icon="showAdvancedFilters ? 'mdi-chevron-up' : 'mdi-chevron-down'"
                    @click="showAdvancedFilters = !showAdvancedFilters"
                >
                    {{ showAdvancedFilters ? 'Hide' : 'Show' }} Advanced Filters
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
        <v-data-table
            v-else
            v-model="selected" v-model:sort-by="sortBy" :headers="headers" :items="displayUsers"
            density="comfortable" hover
            :items-per-page="itemsPerPage"
            :page="currentPage"
            :server-items-length="totalCount"
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
        </v-data-table>
    </v-card>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue';
import { useRouter } from 'vue-router';
import { VCard, VTextField, VSelect, VBtn, VIcon, VChip, VProgressCircular, VAlert, VAlertTitle, VExpandTransition } from 'vuetify/components';
import { VDataTable } from 'vuetify/labs/components';

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
const emailFilter = ref<string>('');
const statusFilter = ref<string>('');
const tierFilter = ref<string>('');
const storageMin = ref<number | null>(null);
const storageMax = ref<number | null>(null);
const utmSource = ref<string>('');
const utmMedium = ref<string>('');
const utmCampaign = ref<string>('');
const utmTerm = ref<string>('');
const utmContent = ref<string>('');
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

// Clear all filters
const clearAllFilters = () => {
    search.value = '';
    emailFilter.value = '';
    statusFilter.value = '';
    tierFilter.value = '';
    storageMin.value = null;
    storageMax.value = null;
    utmSource.value = '';
    utmMedium.value = '';
    utmCampaign.value = '';
    utmTerm.value = '';
    utmContent.value = '';
    loadUsers();
};

// Clear advanced filters only
const clearAdvancedFilters = () => {
    storageMin.value = null;
    storageMax.value = null;
    utmSource.value = '';
    utmMedium.value = '';
    utmCampaign.value = '';
    utmTerm.value = '';
    utmContent.value = '';
    loadUsers();
};

// Count active filters
const activeFiltersCount = computed(() => {
    let count = 0;
    if (emailFilter.value) count++;
    if (statusFilter.value) count++;
    if (tierFilter.value) count++;
    if (storageMin.value || storageMax.value) count++;
    if (utmSource.value) count++;
    if (utmMedium.value) count++;
    if (utmCampaign.value) count++;
    if (utmTerm.value) count++;
    if (utmContent.value) count++;
    return count;
});

// Format storage range for chip display
const formatStorageRange = () => {
    const min = storageMin.value ? formatBytes(storageMin.value) : '0';
    const max = storageMax.value ? formatBytes(storageMax.value) : '∞';
    return `${min} - ${max}`;
};

// Load users data
const loadUsers = async () => {
    try {
        loading.value = true;
        error.value = null;

        const response = await adminApi.getAllUsers({
            limit: itemsPerPage.value,
            page: currentPage.value,
            search: search.value || undefined,
            email: emailFilter.value || undefined,
            status: statusFilter.value || undefined,
            tier: tierFilter.value ? (tierFilter.value as 'paid' | 'free') : undefined,
            storageMin: storageMin.value ?? undefined,
            storageMax: storageMax.value ?? undefined,
            utmSource: utmSource.value || undefined,
            utmMedium: utmMedium.value || undefined,
            utmCampaign: utmCampaign.value || undefined,
            utmTerm: utmTerm.value || undefined,
            utmContent: utmContent.value || undefined,
            sortBy: sortBy.value[0]?.key || 'email',
            sortOrder: sortBy.value[0]?.order || 'asc',
        });

        users.value = response.users;
        totalPages.value = response.pageCount;
        totalCount.value = response.totalCount;
        
        // Don't emit stats update - stats should come from backend API (getDashboardStats)
        // Filtered table data should not override the real stats
    } catch (err) {
        console.error('Failed to load users:', err);
        error.value = err instanceof Error ? err.message : 'Unknown error occurred';
    } finally {
        loading.value = false;
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
    currentPage.value = page;
    loadUsers();
};

const handleItemsPerPageChange = (itemsPerPageValue: number) => {
    itemsPerPage.value = itemsPerPageValue;
    currentPage.value = 1;
    loadUsers();
};

// Emit stats update - REMOVED: Stats should come from backend API, not from filtered table data
// The stats cards should show total counts, not filtered counts
// const emitStatsUpdate = () => {
//     // Don't emit filtered stats - stats should come from getDashboardStats API
// };

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