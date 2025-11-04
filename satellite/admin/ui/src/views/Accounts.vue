// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-container fluid>
        <!-- Header Section -->
        <v-row>
            <v-col cols="6">
                <PageTitleComponent title="Accounts" />
                <PageSubtitleComponent subtitle="All accounts on North America US1." />
            </v-col>

            <v-col cols="6" class="d-flex justify-end align-center">
                <v-btn variant="outlined" color="default" @click="exportUsers">
                    <v-icon icon="mdi-download" class="mr-2" />
                    Export CSV
                </v-btn>
                <v-btn variant="outlined" color="default" class="ml-2" @click="refreshData">
                    <v-icon icon="mdi-refresh" class="mr-2" />
                    Refresh
                </v-btn>
                <v-btn variant="outlined" color="default" class="ml-2">
                    <svg width="16" height="16" class="mr-2" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path
                            d="M10 1C14.9706 1 19 5.02944 19 10C19 14.9706 14.9706 19 10 19C5.02944 19 1 14.9706 1 10C1 5.02944 5.02944 1 10 1ZM10 2.65C5.94071 2.65 2.65 5.94071 2.65 10C2.65 14.0593 5.94071 17.35 10 17.35C14.0593 17.35 17.35 14.0593 17.35 10C17.35 5.94071 14.0593 2.65 10 2.65ZM10.7496 6.8989L10.7499 6.91218L10.7499 9.223H12.9926C13.4529 9.223 13.8302 9.58799 13.8456 10.048C13.8602 10.4887 13.5148 10.8579 13.0741 10.8726L13.0608 10.8729L10.7499 10.873L10.75 13.171C10.75 13.6266 10.3806 13.996 9.925 13.996C9.48048 13.996 9.11807 13.6444 9.10066 13.2042L9.1 13.171L9.09985 10.873H6.802C6.34637 10.873 5.977 10.5036 5.977 10.048C5.977 9.60348 6.32857 9.24107 6.76882 9.22366L6.802 9.223H9.09985L9.1 6.98036C9.1 6.5201 9.46499 6.14276 9.925 6.12745C10.3657 6.11279 10.7349 6.45818 10.7496 6.8989Z"
                            fill="currentColor"
                        />
                    </svg>
                    New Account
                    <NewAccountDialog @account-created="refreshData" />
                </v-btn>
            </v-col>
        </v-row>

        <!-- Statistics Cards -->
        <v-row class="d-flex align-center justify-center mt-2">
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent
                    title="Total Accounts" 
                    subtitle="All Users" 
                    :data="formatNumber(stats.totalAccounts)" 
                    color="primary" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent
                    title="Active" 
                    subtitle="Accounts" 
                    :data="formatNumber(stats.active)" 
                    color="success" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent
                    title="Inactive" 
                    subtitle="Accounts" 
                    :data="formatNumber(stats.inactive)" 
                    color="default" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent 
                    title="Pro" 
                    subtitle="Accounts" 
                    :data="formatNumber(stats.pro)" 
                    color="success" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent 
                    title="Free" 
                    subtitle="Accounts" 
                    :data="formatNumber(stats.free)" 
                    color="default" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent 
                    title="Deleted" 
                    subtitle="Accounts" 
                    :data="formatNumber(stats.deleted)" 
                    color="error" 
                />
            </v-col>
        </v-row>

        <!-- Loading state for stats -->
        <v-row v-if="statsLoading" class="d-flex align-center justify-center mt-2">
            <v-col cols="12" class="text-center">
                <v-progress-circular indeterminate color="primary" size="32" />
                <p class="mt-2">Loading account statistics...</p>
            </v-col>
        </v-row>

        <!-- Error state for stats -->
        <v-row v-if="statsError" class="mt-4">
            <v-col cols="12">
                <v-alert type="error" variant="tonal">
                    <v-alert-title>Error loading statistics</v-alert-title>
                    {{ statsError }}
                </v-alert>
            </v-col>
        </v-row>

        <!-- User Management Table -->
        <AccountsTableComponent 
            ref="tableComponent"
            class="my-5" 
            :refresh-trigger="refreshTrigger"
            @stats-updated="handleStatsUpdate"
            @export-requested="handleExportRequest"
        />
    </v-container>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { VContainer, VRow, VCol, VBtn, VProgressCircular, VAlert, VAlertTitle, VIcon } from 'vuetify/components';

import { useAppStore } from '@/store/app';
import { useNotificationsStore } from '@/store/notifications';

import PageTitleComponent from '@/components/PageTitleComponent.vue';
import PageSubtitleComponent from '@/components/PageSubtitleComponent.vue';
import CardStatsComponent from '@/components/CardStatsComponent.vue';
import AccountsTableComponent from '@/components/AccountsTableComponent.vue';
import NewAccountDialog from '@/components/NewAccountDialog.vue';
import { adminApi } from '@/api/adminApi';

// Reactive data
const statsLoading = ref(true);
const statsError = ref<string | null>(null);
const refreshTrigger = ref(0);
const tableComponent = ref<any>(null);
const stats = ref({
    totalAccounts: 0,
    active: 0,
    inactive: 0,
    deleted: 0,
    pendingDeletion: 0,
    legalHold: 0,
    pendingBotVerification: 0,
    pro: 0,
    free: 0,
});

// Load statistics
const loadStats = async () => {
    try {
        statsLoading.value = true;
        statsError.value = null;
        
        const dashboardStats = await adminApi.getDashboardStats();
        stats.value = dashboardStats;
    } catch (err) {
        console.error('Failed to load account statistics:', err);
        statsError.value = err instanceof Error ? err.message : 'Unknown error occurred';
    } finally {
        statsLoading.value = false;
    }
};

// Refresh all data
const refreshData = () => {
    refreshTrigger.value++;
    loadStats();
};

// Handle stats update from table component
// NOTE: This is disabled because stats should come from backend API, not filtered table data
// The stats cards should always show total counts, regardless of filters applied
const handleStatsUpdate = (newStats: typeof stats.value) => {
    // Don't update stats from filtered table - keep the real stats from backend
    // stats.value = newStats; // Commented out to prevent overriding real stats
};

// Format number with commas
const formatNumber = (num: number): string => {
    return num.toLocaleString();
};

// Export users data as CSV
const exportUsers = async () => {
    // Call the table component's export method
    if (tableComponent.value) {
        tableComponent.value.exportFilteredUsers();
    }
};

// Handle export request from table component
const handleExportRequest = (users: any[]) => {
    try {
        // Create CSV content from filtered users
        const csvContent = convertToCSV(users);
        
        // Create and download file
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'users_export.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Failed to export users:', error);
        statsError.value = 'Failed to export users. Please try again.';
    }
};

// Convert users data to CSV format
const convertToCSV = (users: any[]) => {
    if (!users || users.length === 0) return '';
    
    // CSV headers
    const headers = [
        'ID', 'Full Name', 'Email', 'Status', 'Created At', 'Paid Tier',
        'Project Storage Limit', 'Project Bandwidth Limit', 'Storage Used',
        'Bandwidth Used', 'Segment Used', 'Project Count', 'Source',
        'UTM Source', 'UTM Medium', 'UTM Campaign', 'UTM Term', 'UTM Content',
        'Last Session Expiry', 'First Session Expiry', 'Total Sessions'
    ];
    
    // Convert data to CSV rows
    const rows = users.map(user => [
        user.id || '',
        user.fullName || '',
        user.email || '',
        user.status || '',
        user.createdAt || '',
        user.paidTier ? 'true' : 'false',
        user.projectStorageLimit || '',
        user.projectBandwidthLimit || '',
        user.storageUsed || '',
        user.bandwidthUsed || '',
        user.segmentUsed || '',
        user.projectCount || '',
        user.source || '',
        user.utmSource || '',
        user.utmMedium || '',
        user.utmCampaign || '',
        user.utmTerm || '',
        user.utmContent || '',
        user.lastSessionExpiry || '',
        user.firstSessionExpiry || '',
        user.totalSessionCount || ''
    ]);
    
    // Combine headers and rows
    const csvContent = [headers, ...rows]
        .map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
        .join('\n');
    
    return csvContent;
};

// Load data on component mount
onMounted(() => {
    loadStats();
});
</script>
