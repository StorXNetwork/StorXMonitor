// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-card variant="flat" :border="true" rounded="xlg">
        <div class="d-flex justify-between mx-2 mt-2" style="max-width: 1400px; margin: 0 auto;">
            <div></div>
            <div class="d-flex align-center gap-6" style="max-width: 1000px;">
                <v-text-field
                    v-model="search"
                    label="Search"
                    prepend-inner-icon="mdi-magnify"
                    single-line
                    variant="solo-filled"
                    flat
                    hide-details
                    clearable
                    density="compact"
                    rounded="lg"
                    style="min-width: 400px;"
                />
                        <v-select
                            v-model="statusFilter"
                            label="Status"
                            prepend-inner-icon="mdi-filter"
                            single-line
                            variant="outlined"
                            flat
                            hide-details
                            clearable
                            density="compact"
                            rounded="lg"
                            style="width: 180px;"
                            :items="statusOptions"
                            item-title="title"
                            item-value="value"
                        />
                        <v-select
                            v-model="countryFilter"
                            label="Country"
                            prepend-inner-icon="mdi-earth"
                            single-line
                            variant="outlined"
                            flat
                            hide-details
                            clearable
                            density="compact"
                            rounded="lg"
                            style="width: 180px;"
                            :items="countryOptions"
                            item-title="title"
                            item-value="value"
                        />
                        <v-select
                            v-model="sortBy"
                            label="Sort By"
                            prepend-inner-icon="mdi-sort"
                            single-line
                            variant="outlined"
                            flat
                            hide-details
                            density="compact"
                            rounded="lg"
                            style="width: 180px;"
                            :items="sortOptions"
                            item-title="title"
                            item-value="value"
                        />
                        <v-select
                            v-model="sortOrder"
                            label="Order"
                            single-line
                            variant="outlined"
                            flat
                            hide-details
                            density="compact"
                            rounded="lg"
                            style="width: 150px;"
                            :items="orderOptions"
                            item-title="title"
                            item-value="value"
                        />
            </div>
        </div>

        <!-- Data Table -->
        <v-data-table
            v-model="selected"
            :headers="headers"
            :items="filteredNodes"
            :loading="loading"
            class="elevation-1"
            item-key="id"
            density="comfortable"
            show-expand
            hover
            @item-click="handleItemClick"
        >
            <!-- Status Column -->
            <template #item.status="{ item }">
                <v-chip 
                    :color="getStatusColor(item.raw.status)" 
                    variant="tonal" 
                    size="small" 
                    rounded="lg"
                >
                    {{ formatStatus(item.raw.status) }}
                </v-chip>
            </template>

            <!-- Address Column -->
            <template #item.address="{ item }">
                <span class="font-mono text-caption">{{ truncateAddress(item.raw.address) }}</span>
            </template>

            <!-- Country Column -->
            <template #item.countryCode="{ item }">
                <v-chip 
                    v-if="item.raw.countryCode && item.raw.countryCode !== ''"
                    variant="outlined" 
                    size="small" 
                    rounded="lg"
                >
                    {{ item.raw.countryCode }}
                </v-chip>
                <span v-else class="text-grey text-caption">N/A</span>
            </template>

            <!-- Free Disk Column -->
            <template #item.freeDisk="{ item }">
                <span class="text-no-wrap">
                    {{ formatBytes(item.raw.freeDisk) }}
                </span>
            </template>

            <!-- Latency Column -->
            <template #item.latency90="{ item }">
                <span class="text-no-wrap">
                    {{ formatLatency(item.raw.latency90) }}
                </span>
            </template>

            <!-- Version Column -->
            <template #item.version="{ item }">
                <v-chip 
                    :color="getVersionColor(item.raw.version)" 
                    variant="tonal" 
                    size="small" 
                    rounded="lg"
                >
                    {{ item.raw.version || 'Unknown' }}
                </v-chip>
            </template>

            <!-- Created At Column -->
            <template #item.createdAt="{ item }">
                <span class="text-no-wrap">
                    {{ formatDateTime(item.raw.createdAt) }}
                </span>
            </template>

            <!-- Actions Column -->
            <template #item.actions="{ item }">
                <v-btn
                    variant="text"
                    size="small"
                    color="primary"
                    @click.stop="viewNodeDetails(item.raw.id)"
                >
                    View Details
                </v-btn>
            </template>

            <!-- Expanded Row -->
            <template #expanded-row="{ columns, item }">
                <tr>
                    <td :colspan="columns.length">
                        <div class="pa-4">
                            <h4>Node Details</h4>
                            <v-row>
                                <v-col cols="12" md="6">
                                    <p><strong>Node ID:</strong> {{ item.raw.id }}</p>
                                    <p><strong>Address:</strong> {{ item.raw.address }}</p>
                                    <p><strong>Country:</strong> {{ item.raw.countryCode }}</p>
                                    <p><strong>Status:</strong> {{ formatStatus(item.raw.status) }}</p>
                                </v-col>
                                <v-col cols="12" md="6">
                                    <p><strong>Free Disk:</strong> {{ formatBytes(item.raw.freeDisk) }}</p>
                                    <p><strong>Latency (90th):</strong> {{ formatLatency(item.raw.latency90) }}</p>
                                    <p><strong>Version:</strong> {{ item.raw.version || 'Unknown' }}</p>
                                    <p><strong>Operator Email:</strong> {{ item.raw.operatorEmail || 'N/A' }}</p>
                                </v-col>
                            </v-row>
                        </div>
                    </td>
                </tr>
            </template>

            <!-- No Data -->
            <template #no-data>
                <div class="text-center pa-4">
                    <v-icon size="64" color="grey-lighten-1">mdi-server-network-off</v-icon>
                    <p class="text-h6 mt-2">No nodes found</p>
                    <p class="text-body-2 text-grey">
                        <span v-if="search || statusFilter || countryFilter">
                            Try adjusting your search or filter criteria
                        </span>
                        <span v-else>
                            No storage nodes are currently available
                        </span>
                    </p>
                    <v-btn 
                        v-if="search || statusFilter || countryFilter"
                        variant="outlined" 
                        color="primary" 
                        class="mt-2"
                        @click="clearFilters"
                    >
                        Clear Filters
                    </v-btn>
                </div>
            </template>
        </v-data-table>

        <!-- Node Count Info -->
        <v-card-actions v-if="nodes.length > 0" class="justify-center">
            <div class="d-flex align-center">
                <span class="text-body-2 text-grey">
                    <span v-if="filteredNodes.length > 0">
                        Showing {{ filteredNodes.length }} of {{ nodes.length }} nodes
                        <span v-if="search || statusFilter || countryFilter">(filtered)</span>
                    </span>
                    <span v-else>
                        No nodes match your filters
                    </span>
                </span>
            </div>
        </v-card-actions>
    </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRouter } from 'vue-router';
import { VCard, VCardText, VCardActions, VTextField, VSelect, VChip, VBtn, VIcon } from 'vuetify/components';
import { VDataTable } from 'vuetify/labs/components';
import { adminApi, Node, NodeListResponse, NodeStats } from '@/api/adminApi';

// Props
const props = defineProps<{
    refreshTrigger?: number;
}>();

// Emits
const emit = defineEmits<{
    'stats-updated': [stats: NodeStats];
    'export-requested': [nodes: Node[]];
}>();

// Router
const router = useRouter();

// Reactive data
const search = ref<string>('');
const selected = ref<string[]>([]);
const loading = ref(false);
const nodes = ref<Node[]>([]);
const statusFilter = ref<string>('');
const countryFilter = ref<string>('');
const sortBy = ref<string>('createdAt');
const sortOrder = ref<string>('desc');

// Pagination
const pagination = ref({
    currentPage: 1,
    pageCount: 0,
    totalCount: 0,
    limit: 50,
    hasMore: false,
});

// Table headers
const headers = [
    { title: 'Node ID', key: 'id', align: 'start' as const },
    { title: 'Status', key: 'status', align: 'center' as const },
    { title: 'Address', key: 'address', align: 'start' as const },
    { title: 'Country', key: 'countryCode', align: 'center' as const },
    { title: 'Free Disk', key: 'freeDisk', align: 'end' as const },
    { title: 'Latency (90th)', key: 'latency90', align: 'end' as const },
    { title: 'Version', key: 'version', align: 'center' as const },
    { title: 'Created At', key: 'createdAt', align: 'start' as const },
    { title: 'Actions', key: 'actions', align: 'center' as const, sortable: false },
    { title: '', key: 'data-table-expand' },
];

// Filter options
const statusOptions = [
    { title: 'All', value: '' },
    { title: 'Online', value: 'online' },
    { title: 'Offline', value: 'offline' },
    { title: 'Disqualified', value: 'disqualified' },
    { title: 'Suspended', value: 'suspended' },
    { title: 'Exiting', value: 'exiting' },
];

const countryOptions = [
    { title: 'All', value: '' },
    { title: 'US', value: 'US' },
    { title: 'CA', value: 'CA' },
    { title: 'GB', value: 'GB' },
    { title: 'DE', value: 'DE' },
    { title: 'FR', value: 'FR' },
    { title: 'JP', value: 'JP' },
    { title: 'AU', value: 'AU' },
    { title: 'Other', value: 'other' },
];

const sortOptions = [
    { title: 'Created At', value: 'createdAt' },
    { title: 'Status', value: 'status' },
    { title: 'Address', value: 'address' },
    { title: 'Country', value: 'countryCode' },
    { title: 'Free Disk', value: 'freeDisk' },
    { title: 'Latency', value: 'latency90' },
    { title: 'Version', value: 'version' },
];

const orderOptions = [
    { title: 'Ascending', value: 'asc' },
    { title: 'Descending', value: 'desc' },
];

// Computed filtered nodes
const filteredNodes = computed(() => {
    let filtered = [...nodes.value];
    
    // Apply search filter
    if (search.value) {
        const searchLower = search.value.toLowerCase();
        filtered = filtered.filter(node => 
            node.id.toLowerCase().includes(searchLower) ||
            node.address.toLowerCase().includes(searchLower) ||
            (node.countryCode && node.countryCode.toLowerCase().includes(searchLower)) ||
            node.status.toLowerCase().includes(searchLower) ||
            (node.version && node.version.toLowerCase().includes(searchLower)) ||
            (node.operatorEmail && node.operatorEmail.toLowerCase().includes(searchLower))
        );
    }
    
    // Apply status filter
    if (statusFilter.value) {
        filtered = filtered.filter(node => node.status === statusFilter.value);
    }
    
    // Apply country filter
    if (countryFilter.value) {
        if (countryFilter.value === 'other') {
            filtered = filtered.filter(node => 
                !node.countryCode || 
                node.countryCode === '' || 
                !['US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU'].includes(node.countryCode)
            );
        } else {
            filtered = filtered.filter(node => node.countryCode === countryFilter.value);
        }
    }
    
    // Apply sorting
    filtered.sort((a, b) => {
        let aValue: any;
        let bValue: any;
        
        switch (sortBy.value) {
            case 'createdAt':
                aValue = new Date(a.createdAt).getTime();
                bValue = new Date(b.createdAt).getTime();
                break;
            case 'status':
                aValue = a.status;
                bValue = b.status;
                break;
            case 'address':
                aValue = a.address;
                bValue = b.address;
                break;
            case 'countryCode':
                aValue = a.countryCode || '';
                bValue = b.countryCode || '';
                break;
            case 'freeDisk':
                aValue = a.freeDisk;
                bValue = b.freeDisk;
                break;
            case 'latency90':
                aValue = a.latency90;
                bValue = b.latency90;
                break;
            case 'version':
                aValue = a.version || '';
                bValue = b.version || '';
                break;
            default:
                aValue = a.createdAt;
                bValue = b.createdAt;
        }
        
        if (sortOrder.value === 'asc') {
            return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
        } else {
            return aValue < bValue ? 1 : aValue > bValue ? -1 : 0;
        }
    });
    
    return filtered;
});

// Load nodes data
const loadNodes = async () => {
    try {
        loading.value = true;
        
        const response = await adminApi.getAllNodes();
        nodes.value = response.nodes;

        // Load stats for the parent component
        await loadStats();
    } catch (error) {
        console.error('Failed to load nodes:', error);
        nodes.value = [];
    } finally {
        loading.value = false;
    }
};

// Load node statistics
const loadStats = async () => {
    try {
        const stats = await adminApi.getNodeStats();
        emit('stats-updated', stats);
    } catch (error) {
        console.error('Failed to load node stats:', error);
    }
};

// Watch for refresh trigger
watch(() => props.refreshTrigger, () => {
    loadNodes();
});

// Handle item click
const handleItemClick = (event: any, item: any) => {
    console.log('Clicked node:', item);
};

// View node details
const viewNodeDetails = (nodeId: string) => {
    // Navigate to node details page using router
    router.push(`/node-details/${nodeId}`);
};

// Clear all filters
const clearFilters = () => {
    search.value = '';
    statusFilter.value = '';
    countryFilter.value = '';
    sortBy.value = 'createdAt';
    sortOrder.value = 'desc';
};

// Export filtered nodes
const exportFilteredNodes = () => {
    emit('export-requested', filteredNodes.value);
};

// Get current filters for export
const getCurrentFilters = () => {
    return {
        status: statusFilter.value,
        country: countryFilter.value,
        sortBy: sortBy.value,
        sortOrder: sortOrder.value,
        search: search.value
    };
};

// Expose methods for parent component
defineExpose({
    exportFilteredNodes,
    getCurrentFilters
});

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
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
};

const truncateAddress = (address: string): string => {
    if (address.length <= 20) return address;
    return address.substring(0, 17) + '...';
};

const getVersionColor = (version: string): string => {
    if (!version || version === 'Unknown') return 'default';
    // You can add logic here to color-code different versions
    return 'primary';
};

// Load data on mount
onMounted(() => {
    loadNodes();
});
</script>
