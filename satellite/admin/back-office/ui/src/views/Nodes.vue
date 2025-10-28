// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-container fluid class="pa-6">
        <!-- Header Section -->
        <v-row class="mb-6">
            <v-col cols="12">
                <div class="d-flex align-center justify-space-between">
                    <div>
                        <h1 class="text-h4 font-weight-bold mb-2">Storage Nodes</h1>
                        <p class="text-h6 text-medium-emphasis">Monitor and manage storage nodes in the network</p>
                    </div>
                    <div class="d-flex gap-6">
                        <v-btn 
                            variant="outlined" 
                            color="default" 
                            prepend-icon="mdi-download"
                            @click="exportNodes"
                        >
                            Export CSV
                        </v-btn>
                        <v-btn 
                            variant="outlined" 
                            color="default" 
                            prepend-icon="mdi-refresh"
                            @click="refreshData"
                        >
                            Refresh
                        </v-btn>
                    </div>
                </div>
            </v-col>
        </v-row>

        <!-- Statistics Cards -->
        <v-row class="d-flex align-center justify-center mt-2">
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent
                    title="Total Nodes" 
                    subtitle="All Nodes" 
                    :data="formatNumber(stats.totalNodes)" 
                    color="primary" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent
                    title="Online" 
                    subtitle="Nodes" 
                    :data="formatNumber(stats.onlineNodes)" 
                    color="success" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent
                    title="Offline" 
                    subtitle="Nodes" 
                    :data="formatNumber(stats.offlineNodes)" 
                    color="error" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent 
                    title="Disqualified" 
                    subtitle="Nodes" 
                    :data="formatNumber(stats.disqualifiedNodes)" 
                    color="warning" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent 
                    title="Suspended" 
                    subtitle="Nodes" 
                    :data="formatNumber(stats.suspendedNodes)" 
                    color="default" 
                />
            </v-col>
            <v-col cols="12" sm="6" md="4" lg="2">
                <CardStatsComponent 
                    title="Exiting" 
                    subtitle="Nodes" 
                    :data="formatNumber(stats.exitingNodes)" 
                    color="info" 
                />
            </v-col>
        </v-row>

        <!-- Loading state for stats -->
        <v-row v-if="statsLoading" class="d-flex align-center justify-center mt-2">
            <v-col cols="12" class="text-center">
                <v-progress-circular indeterminate color="primary" size="32" />
                <p class="mt-2">Loading node statistics...</p>
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

        <!-- Node Management Table -->
        <NodesTableComponent 
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
import NodesTableComponent from '@/components/NodesTableComponent.vue';
import { adminApi, NodeStats } from '@/api/adminApi';

// Reactive data
const statsLoading = ref(true);
const statsError = ref<string | null>(null);
const refreshTrigger = ref(0);
const tableComponent = ref<any>(null);
const stats = ref<NodeStats>({
    totalNodes: 0,
    onlineNodes: 0,
    offlineNodes: 0,
    disqualifiedNodes: 0,
    suspendedNodes: 0,
    exitingNodes: 0,
    usedCapacity: 0,
    averageLatency: 0,
});

// Load statistics
const loadStats = async () => {
    try {
        statsLoading.value = true;
        statsError.value = null;
        
        const nodeStats = await adminApi.getNodeStats();
        stats.value = nodeStats;
    } catch (err) {
        console.error('Failed to load node statistics:', err);
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
const handleStatsUpdate = (newStats: NodeStats) => {
    stats.value = newStats;
};

// Format number with commas
const formatNumber = (num: number): string => {
    return num.toLocaleString();
};

// Export nodes data as CSV
const exportNodes = async () => {
    try {
        // Get current filters from table component
        const filters = tableComponent.value?.getCurrentFilters?.() || {};
        
        // Build query parameters
        const params = new URLSearchParams();
        params.append('format', 'csv');
        
        if (filters.status) params.append('status', filters.status);
        if (filters.country) params.append('country', filters.country);
        if (filters.sortBy) params.append('sort_by', filters.sortBy);
        if (filters.sortOrder) params.append('sort_order', filters.sortOrder);
        
        // Make API call to backend export
        const response = await fetch(`/api/nodes?${params.toString()}`, {
            method: 'GET',
            headers: {
                'Authorization': 'very-secret-token',
                'Content-Type': 'application/json',
            },
        });
        
        if (!response.ok) {
            throw new Error(`Export failed: ${response.statusText}`);
        }
        
        // Create and download file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'nodes_export.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Failed to export nodes:', error);
        statsError.value = 'Failed to export nodes. Please try again.';
    }
};

// Handle export request from table component (fallback)
const handleExportRequest = (nodes: any[]) => {
    // This is now handled by the backend export
    console.log('Export request received, but using backend export instead');
};

// Load data on component mount
onMounted(() => {
    loadStats();
});
</script>
