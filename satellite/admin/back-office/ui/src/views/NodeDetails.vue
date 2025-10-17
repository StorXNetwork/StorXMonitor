// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-container fluid class="pa-6">
        <!-- Header Section -->
        <v-row class="mb-6">
            <v-col cols="12">
                <div class="d-flex align-center justify-space-between">
                    <div>
                        <h1 class="text-h4 font-weight-bold mb-2">Node Details</h1>
                        <p class="text-h6 text-medium-emphasis">
                            Node ID: <span class="font-mono text-body-1">{{ nodeId }}</span>
                        </p>
                    </div>
                    <div class="d-flex gap-8">
                        <v-btn 
                            variant="outlined" 
                            color="default" 
                            prepend-icon="mdi-arrow-left"
                            @click="goBack"
                        >
                            Back to Nodes
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

        <!-- Loading State -->
        <v-row v-if="loading" class="d-flex align-center justify-center py-12">
            <v-col cols="12" class="text-center">
                <v-progress-circular 
                    indeterminate 
                    color="primary" 
                    size="80" 
                    width="6"
                />
                <p class="mt-6 text-h5 text-medium-emphasis">Loading node details...</p>
            </v-col>
        </v-row>

        <!-- Error State -->
        <v-row v-else-if="error" class="mt-4">
            <v-col cols="12">
                <v-alert 
                    type="error" 
                    variant="tonal" 
                    prominent
                    class="rounded-xl"
                >
                    <v-alert-title class="text-h6">Error loading node details</v-alert-title>
                    <p class="mt-2">{{ error }}</p>
                </v-alert>
            </v-col>
        </v-row>

        <!-- Node Details -->
        <div v-else-if="node">
            <!-- Status Overview Cards -->
            <v-row class="mb-6">
                <v-col cols="12" md="3">
                    <v-card 
                        variant="flat" 
                        :border="true" 
                        rounded="xl" 
                        class="h-100"
                        :class="`border-${getStatusColor(node.status)}`"
                    >
                        <v-card-text class="pa-6">
                            <div class="d-flex align-center mb-4">
                                <v-avatar 
                                    :color="getStatusColor(node.status)" 
                                    size="48"
                                    class="mr-4"
                                >
                                    <v-icon color="white" size="24">mdi-server</v-icon>
                                </v-avatar>
                                <div>
                                    <h3 class="text-h6 font-weight-medium">Status</h3>
                                    <p class="text-caption text-medium-emphasis">Current state</p>
                                </div>
                            </div>
                            <v-chip 
                                :color="getStatusColor(node.status)" 
                                variant="tonal" 
                                size="large" 
                                rounded="lg"
                                class="font-weight-medium"
                            >
                                {{ formatStatus(node.status) }}
                            </v-chip>
                        </v-card-text>
                    </v-card>
                </v-col>

                <v-col cols="12" md="3">
                    <v-card variant="flat" :border="true" rounded="xl" class="h-100">
                        <v-card-text class="pa-6">
                            <div class="d-flex align-center mb-4">
                                <v-avatar color="primary" size="48" class="mr-4">
                                    <v-icon color="white" size="24">mdi-map-marker</v-icon>
                                </v-avatar>
                                <div>
                                    <h3 class="text-h6 font-weight-medium">Location</h3>
                                    <p class="text-caption text-medium-emphasis">Geographic region</p>
                                </div>
                            </div>
                            <v-chip 
                                v-if="node.countryCode && node.countryCode !== ''"
                                variant="outlined" 
                                size="large" 
                                rounded="lg"
                                class="font-weight-medium"
                            >
                                {{ node.countryCode }}
                            </v-chip>
                            <span v-else class="text-body-1 text-medium-emphasis">N/A</span>
                        </v-card-text>
                    </v-card>
                </v-col>

                <v-col cols="12" md="3">
                    <v-card variant="flat" :border="true" rounded="xl" class="h-100">
                        <v-card-text class="pa-6">
                            <div class="d-flex align-center mb-4">
                                <v-avatar color="success" size="48" class="mr-4">
                                    <v-icon color="white" size="24">mdi-harddisk</v-icon>
                                </v-avatar>
                                <div>
                                    <h3 class="text-h6 font-weight-medium">Free Space</h3>
                                    <p class="text-caption text-medium-emphasis">Available storage</p>
                                </div>
                            </div>
                            <p class="text-h5 font-weight-bold">{{ formatBytes(node.freeDisk) }}</p>
                        </v-card-text>
                    </v-card>
                </v-col>

                <v-col cols="12" md="3">
                    <v-card variant="flat" :border="true" rounded="xl" class="h-100">
                        <v-card-text class="pa-6">
                            <div class="d-flex align-center mb-4">
                                <v-avatar color="info" size="48" class="mr-4">
                                    <v-icon color="white" size="24">mdi-speedometer</v-icon>
                                </v-avatar>
                                <div>
                                    <h3 class="text-h6 font-weight-medium">Latency</h3>
                                    <p class="text-caption text-medium-emphasis">90th percentile</p>
                                </div>
                            </div>
                            <p class="text-h5 font-weight-bold">{{ formatLatency(node.latency90) }}</p>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>

            <!-- Detailed Information -->
            <v-row class="mb-6">
                <v-col cols="12" md="6">
                    <v-card variant="flat" :border="true" rounded="xl" class="h-100">
                        <v-card-title class="pa-6 pb-2">
                            <div class="d-flex align-center">
                                <v-avatar color="primary" size="40" class="mr-3">
                                    <v-icon color="white" size="20">mdi-information</v-icon>
                                </v-avatar>
                                <h2 class="text-h5 font-weight-medium">Basic Information</h2>
                            </div>
                        </v-card-title>
                        <v-card-text class="pa-6 pt-2">
                            <v-list class="pa-0">
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="primary" class="mr-4">mdi-ip-network</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Address</v-list-item-title>
                                    <v-list-item-subtitle class="font-mono text-body-1 mt-1">{{ node.address }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-divider class="my-2" />
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="primary" class="mr-4">mdi-calendar</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Created At</v-list-item-title>
                                    <v-list-item-subtitle class="text-body-1 mt-1">{{ formatDateTime(node.createdAt) }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-divider class="my-2" />
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="primary" class="mr-4">mdi-tag</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Version</v-list-item-title>
                                    <v-list-item-subtitle class="text-body-1 mt-1">
                                        <v-chip 
                                            :color="getVersionColor(node.version)" 
                                            variant="tonal" 
                                            size="small" 
                                            rounded="lg"
                                        >
                                            {{ node.version || 'Unknown' }}
                                        </v-chip>
                                    </v-list-item-subtitle>
                                </v-list-item>
                                <v-divider class="my-2" />
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="primary" class="mr-4">mdi-email</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Operator Email</v-list-item-title>
                                    <v-list-item-subtitle class="text-body-1 mt-1">{{ node.operatorEmail || 'N/A' }}</v-list-item-subtitle>
                                </v-list-item>
                            </v-list>
                        </v-card-text>
                    </v-card>
                </v-col>

                <v-col cols="12" md="6">
                    <v-card variant="flat" :border="true" rounded="xl" class="h-100">
                        <v-card-title class="pa-6 pb-2">
                            <div class="d-flex align-center">
                                <v-avatar color="success" size="40" class="mr-3">
                                    <v-icon color="white" size="20">mdi-chart-line</v-icon>
                                </v-avatar>
                                <h2 class="text-h5 font-weight-medium">Performance Metrics</h2>
                            </div>
                        </v-card-title>
                        <v-card-text class="pa-6 pt-2">
                            <v-list class="pa-0">
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="success" class="mr-4">mdi-harddisk</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Free Disk Space</v-list-item-title>
                                    <v-list-item-subtitle class="text-h5 font-weight-bold text-success mt-1">{{ formatBytes(node.freeDisk) }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-divider class="my-2" />
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="info" class="mr-4">mdi-speedometer</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Latency (90th percentile)</v-list-item-title>
                                    <v-list-item-subtitle class="text-h5 font-weight-bold text-info mt-1">{{ formatLatency(node.latency90) }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-divider class="my-2" />
                                <v-list-item class="px-0 py-3">
                                    <template #prepend>
                                        <v-icon color="primary" class="mr-4">mdi-server</v-icon>
                                    </template>
                                    <v-list-item-title class="text-body-1 font-weight-medium">Node ID</v-list-item-title>
                                    <v-list-item-subtitle class="font-mono text-body-2 mt-1 text-truncate">{{ node.id }}</v-list-item-subtitle>
                                </v-list-item>
                            </v-list>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>

            <!-- Node Actions -->
            <v-row>
                <v-col cols="12">
                    <v-card variant="flat" :border="true" rounded="xl">
                        <v-card-title class="pa-6 pb-2">
                            <div class="d-flex align-center">
                                <v-avatar color="warning" size="40" class="mr-3">
                                    <v-icon color="white" size="20">mdi-cog</v-icon>
                                </v-avatar>
                                <h2 class="text-h5 font-weight-medium">Node Actions</h2>
                            </div>
                        </v-card-title>
                        <v-card-text class="pa-6 pt-2">
                            <div class="d-flex flex-wrap gap-10">
                                <v-btn 
                                    variant="outlined" 
                                    color="primary"
                                    size="large"
                                    :disabled="node.status === 'disqualified' || node.status === 'suspended'"
                                    prepend-icon="mdi-pause"
                                    @click="handleNodeAction('suspend')"
                                >
                                    Suspend Node
                                </v-btn>
                                <v-btn 
                                    variant="outlined" 
                                    color="warning"
                                    size="large"
                                    :disabled="node.status === 'disqualified'"
                                    prepend-icon="mdi-close-circle"
                                    @click="handleNodeAction('disqualify')"
                                >
                                    Disqualify Node
                                </v-btn>
                                <v-btn 
                                    variant="outlined" 
                                    color="error"
                                    size="large"
                                    :disabled="node.status === 'exiting'"
                                    prepend-icon="mdi-exit-to-app"
                                    @click="handleNodeAction('exit')"
                                >
                                    Initiate Exit
                                </v-btn>
                            </div>
                            <v-alert 
                                v-if="node.status === 'disqualified'"
                                type="warning" 
                                variant="tonal" 
                                class="mt-4"
                                rounded="lg"
                            >
                                <v-alert-title>Node Disqualified</v-alert-title>
                                This node has been disqualified and cannot perform certain actions.
                            </v-alert>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>
        </div>
    </v-container>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { VContainer, VRow, VCol, VCard, VCardText, VCardTitle, VBtn, VIcon, VProgressCircular, VAlert, VAlertTitle, VChip, VList, VListItem, VListItemTitle, VListItemSubtitle } from 'vuetify/components';

import PageTitleComponent from '@/components/PageTitleComponent.vue';
import PageSubtitleComponent from '@/components/PageSubtitleComponent.vue';
import { adminApi, Node } from '@/api/adminApi';

// Route and router
const route = useRoute();
const router = useRouter();

// Reactive data
const loading = ref(true);
const error = ref<string | null>(null);
const node = ref<Node | null>(null);
const nodeId = ref<string>('');

// Get node ID from route params
nodeId.value = route.params.id as string;

// Load node details
const loadNodeDetails = async () => {
    try {
        loading.value = true;
        error.value = null;
        
        const nodeDetails = await adminApi.getNodeDetails(nodeId.value);
        node.value = nodeDetails;
    } catch (err) {
        console.error('Failed to load node details:', err);
        error.value = err instanceof Error ? err.message : 'Unknown error occurred';
    } finally {
        loading.value = false;
    }
};

// Refresh data
const refreshData = () => {
    loadNodeDetails();
};

// Go back to nodes list
const goBack = () => {
    router.push('/nodes');
};

// Handle node actions
const handleNodeAction = (action: string) => {
    console.log(`Node action: ${action} for node ${nodeId.value}`);
    // TODO: Implement node actions
    alert(`Node action "${action}" not yet implemented`);
};

// Utility functions
const getStatusColor = (status: string): string => {
    switch (status) {
        case 'online': return 'success';
        case 'offline': return 'error';
        case 'disqualified': return 'warning';
        case 'suspended': return 'default';
        case 'exiting': return 'info';
        default: return 'default';
    }
};

const formatStatus = (status: string): string => {
    return status.charAt(0).toUpperCase() + status.slice(1);
};

const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatLatency = (latency: number): string => {
    if (latency === 0) return 'N/A';
    return `${latency}ms`;
};

const formatDateTime = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
};

const getVersionColor = (version: string): string => {
    if (!version || version === 'Unknown') return 'default';
    // You can add logic here to color-code different versions
    return 'primary';
};

// Load data on mount
onMounted(() => {
    loadNodeDetails();
});
</script>
