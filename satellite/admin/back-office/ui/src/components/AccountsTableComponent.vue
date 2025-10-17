// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-card variant="flat" rounded="xlg" border>
        <div class="d-flex justify-between mx-2 mt-2" style="max-width: 1200px; margin: 0 auto;">
            <div></div>
            <div class="d-flex align-center gap-4" style="max-width: 700px;">
        <v-text-field
            v-model="search" label="Search" prepend-inner-icon="mdi-magnify" single-line variant="solo-filled" flat
                    hide-details clearable density="compact" rounded="lg"
                    style="min-width: 350px;"
                    @input="loadUsers"
                />
                <v-select
                    v-model="statusFilter" label="Status" prepend-inner-icon="mdi-filter" single-line variant="outlined" flat
                    hide-details clearable density="compact" rounded="lg"
                    style="width: 250px;"
                    :items="statusOptions" item-title="text" item-value="value"
                    @update:model-value="loadUsers"
                />
            </div>
        </div>

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
                        <AccountActionsMenu :user-email="item.raw.email" />
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
import { VCard, VTextField, VSelect, VBtn, VIcon, VChip, VProgressCircular, VAlert, VAlertTitle } from 'vuetify/components';
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
const statusFilter = ref<string>('');
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

// Load users data
const loadUsers = async () => {
    try {
        loading.value = true;
        error.value = null;

        const response = await adminApi.getAllUsers({
            limit: itemsPerPage.value,
            page: currentPage.value,
            search: search.value || undefined,
            status: statusFilter.value || undefined,
            sortBy: sortBy.value[0]?.key || 'email',
            sortOrder: sortBy.value[0]?.order || 'asc',
        });

        users.value = response.users;
        totalPages.value = response.pageCount;
        totalCount.value = response.totalCount;
        
        // Emit stats update
        emitStatsUpdate();
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

// Emit stats update
const emitStatsUpdate = () => {
    const stats = {
        totalAccounts: totalCount.value,
        active: users.value.filter(u => u.status === 1).length,
        inactive: users.value.filter(u => u.status === 0).length,
        deleted: users.value.filter(u => u.status === 2).length,
        pendingDeletion: users.value.filter(u => u.status === 3).length,
        legalHold: users.value.filter(u => u.status === 4).length,
        pendingBotVerification: users.value.filter(u => u.status === 5).length,
        pro: users.value.filter(u => u.paidTier).length,
        free: users.value.filter(u => !u.paidTier).length,
    };
    emit('stats-updated', stats);
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