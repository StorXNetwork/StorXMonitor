<template>
    <div class="access-logs-page">
        <!-- Page Header -->
        <div class="page-header">
            <div class="header-content">
                <div>
                    <h1 class="page-title">Access Logs</h1>
                    <p class="page-subtitle">Monitor API access attempts for your OAuth applications</p>
                </div>
                <div class="header-actions">
                    <v-btn
                        variant="outlined"
                        prepend-icon="mdi-download"
                        @click="exportLogs"
                        :disabled="logs.length === 0 || loading"
                        :loading="exporting"
                    >
                        Export CSV
                    </v-btn>
                    <v-btn
                        variant="outlined"
                        prepend-icon="mdi-refresh"
                        @click="loadLogs"
                        :loading="loading"
                    >
                        Refresh
                    </v-btn>
                </div>
            </div>
        </div>

        <v-container fluid class="pa-4">
            <!-- Statistics Cards - All in one line -->
            <div class="stats-row mb-4">
                <v-card class="stat-card stat-card-primary" elevation="0" variant="outlined">
                    <v-card-text class="d-flex align-center">
                        <div class="stat-icon-wrapper stat-icon-primary">
                            <v-icon size="28" color="primary">mdi-chart-line</v-icon>
                        </div>
                        <div class="ml-4">
                            <div class="stat-label">Total Requests</div>
                            <div class="stat-value text-primary">{{ statistics.total }}</div>
                        </div>
                    </v-card-text>
                </v-card>
                <v-card class="stat-card stat-card-success" elevation="0" variant="outlined">
                    <v-card-text class="d-flex align-center">
                        <div class="stat-icon-wrapper stat-icon-success">
                            <v-icon size="28" color="success">mdi-check-circle</v-icon>
                        </div>
                        <div class="ml-4">
                            <div class="stat-label">Approved</div>
                            <div class="stat-value text-success">{{ statistics.approved }}</div>
                        </div>
                    </v-card-text>
                </v-card>
                <v-card class="stat-card stat-card-warning" elevation="0" variant="outlined">
                    <v-card-text class="d-flex align-center">
                        <div class="stat-icon-wrapper stat-icon-warning">
                            <v-icon size="28" color="warning">mdi-clock-outline</v-icon>
                        </div>
                        <div class="ml-4">
                            <div class="stat-label">Pending</div>
                            <div class="stat-value text-warning">{{ statistics.pending }}</div>
                        </div>
                    </v-card-text>
                </v-card>
                <v-card class="stat-card stat-card-error" elevation="0" variant="outlined">
                    <v-card-text class="d-flex align-center">
                        <div class="stat-icon-wrapper stat-icon-error">
                            <v-icon size="28" color="error">mdi-close-circle</v-icon>
                        </div>
                        <div class="ml-4">
                            <div class="stat-label">Rejected</div>
                            <div class="stat-value text-error">{{ statistics.rejected }}</div>
                        </div>
                    </v-card-text>
                </v-card>
                <v-card class="stat-card stat-card-info" elevation="0" variant="outlined">
                    <v-card-text class="d-flex align-center">
                        <div class="stat-icon-wrapper stat-icon-info">
                            <v-icon size="28" color="info">mdi-percent</v-icon>
                        </div>
                        <div class="ml-4">
                            <div class="stat-label">Success Rate</div>
                            <div class="stat-value text-info">{{ successRateFormatted }}%</div>
                        </div>
                    </v-card-text>
                </v-card>
            </div>

            <!-- Filters Card -->
            <v-card class="filters-card mb-4" elevation="0" variant="outlined">
                <v-card-text class="pa-4">
                    <div class="d-flex justify-space-between align-center mb-3">
                        <div class="d-flex align-center">
                            <v-icon class="mr-2" size="20">mdi-filter-variant</v-icon>
                            <span class="text-subtitle-2 font-weight-medium">Filters</span>
                        </div>
                    </div>

                    <v-row>
                        <!-- Date Range Dropdown -->
                        <v-col cols="12" md="3">
                            <v-select
                                v-model="dateRangePreset"
                                :items="dateRangeOptions"
                                label="Created Date"
                                variant="outlined"
                                density="compact"
                                prepend-inner-icon="mdi-calendar-range"
                                clearable
                                @update:model-value="handleDateRangeChange"
                            />
                        </v-col>

                        <!-- Custom Start Date (shown when Custom is selected) -->
                        <v-col cols="12" md="3" v-if="dateRangePreset === 'custom'">
                            <v-text-field
                                v-model="filters.startDate"
                                label="Start Date"
                                type="date"
                                variant="outlined"
                                density="compact"
                                prepend-inner-icon="mdi-calendar-start"
                                clearable
                                @update:model-value="applyFilters"
                            />
                        </v-col>

                        <!-- Custom End Date (shown when Custom is selected) -->
                        <v-col cols="12" md="3" v-if="dateRangePreset === 'custom'">
                            <v-text-field
                                v-model="filters.endDate"
                                label="End Date"
                                type="date"
                                variant="outlined"
                                density="compact"
                                prepend-inner-icon="mdi-calendar-end"
                                clearable
                                @update:model-value="applyFilters"
                            />
                        </v-col>

                        <!-- Status Filter -->
                        <v-col cols="12" md="3">
                            <v-select
                                v-model="filters.status"
                                :items="statusOptions"
                                label="Status"
                                variant="outlined"
                                density="compact"
                                prepend-inner-icon="mdi-filter"
                                clearable
                                @update:model-value="applyFilters"
                            />
                        </v-col>

                        <!-- Client ID Search -->
                        <v-col cols="12" md="3">
                            <v-text-field
                                v-model="filters.clientId"
                                label="Client ID"
                                variant="outlined"
                                density="compact"
                                prepend-inner-icon="mdi-identifier"
                                placeholder="Search by Client ID"
                                clearable
                                @update:model-value="applyFilters"
                            />
                        </v-col>

                    </v-row>
                </v-card-text>
            </v-card>

            <!-- Logs Table -->
            <v-card elevation="0" variant="outlined" class="table-card">
                <!-- Data Table with horizontal scroll only -->
                <div class="table-wrapper-horizontal">
                    <v-data-table
                        :key="`table-${currentPage}-${itemsPerPage}-${logs.length}`"
                        :headers="tableHeaders"
                        :items="logs"
                        :loading="loading"
                        :items-per-page="-1"
                        :server-items-length="totalCount"
                        hide-default-footer
                        class="admin-data-table access-logs-table"
                        item-value="id"
                        :density="'comfortable'"
                        no-data-text="No access logs found"
                    >
                    <template v-slot:item.timestamp="{ item }">
                        <div class="d-flex flex-column">
                            <span class="text-body-2 font-weight-medium text-grey-darken-1">{{ formatDateTime(item.timestamp) }}</span>
                            <span class="text-caption text-grey">{{ formatTime(item.timestamp) }}</span>
                        </div>
                    </template>

                    <template v-slot:item.clientName="{ item }">
                        <span class="text-body-2 font-weight-medium text-grey-darken-2">{{ item.clientName || 'N/A' }}</span>
                    </template>

                    <template v-slot:item.clientId="{ item }">
                        <code class="client-id-code">{{ item.clientId || 'N/A' }}</code>
                    </template>

                    <template v-slot:item.accessStatus="{ item }">
                        <v-chip
                            :color="getStatusColor(item.accessStatus)"
                            size="small"
                            variant="flat"
                            class="status-chip"
                        >
                            <v-icon start size="16">{{ getStatusIcon(item.accessStatus) }}</v-icon>
                            {{ item.accessStatus }}
                        </v-chip>
                    </template>

                    <template v-slot:item.redirectUri="{ item }">
                        <code class="redirect-uri-code">{{ item.redirectUri || 'N/A' }}</code>
                    </template>

                    <template v-slot:item.scopes="{ item }">
                        <div class="d-flex flex-wrap ga-1">
                            <v-chip
                                v-for="scope in (item.scopes || [])"
                                :key="scope"
                                size="x-small"
                                variant="flat"
                                color="primary"
                                class="scope-chip"
                            >
                                {{ scope }}
                            </v-chip>
                            <span v-if="!item.scopes || item.scopes.length === 0" class="text-caption text-grey">—</span>
                        </div>
                    </template>

                    <template v-slot:item.approvedScopes="{ item }">
                        <div class="d-flex flex-wrap ga-1">
                            <v-chip
                                v-for="scope in (item.approvedScopes || [])"
                                :key="scope"
                                size="x-small"
                                variant="flat"
                                color="success"
                                class="scope-chip"
                            >
                                {{ scope }}
                            </v-chip>
                            <span v-if="!item.approvedScopes || item.approvedScopes.length === 0" class="text-caption text-grey">—</span>
                        </div>
                    </template>

                    <template v-slot:item.rejectedScopes="{ item }">
                        <div class="d-flex flex-wrap ga-1">
                            <v-chip
                                v-for="scope in (item.rejectedScopes || [])"
                                :key="scope"
                                size="x-small"
                                variant="flat"
                                color="error"
                                class="scope-chip"
                            >
                                {{ scope }}
                            </v-chip>
                            <span v-if="!item.rejectedScopes || item.rejectedScopes.length === 0" class="text-caption text-grey">—</span>
                        </div>
                    </template>

                    <template v-slot:item.codeExpiresAt="{ item }">
                        <span v-if="item.codeExpiresAt" class="text-body-2 text-grey-darken-1">
                            {{ formatDateTime(item.codeExpiresAt) }}
                        </span>
                        <span v-else class="text-caption text-grey">—</span>
                    </template>

                    <template v-slot:item.consentExpiresAt="{ item }">
                        <span v-if="item.consentExpiresAt" class="text-body-2 text-grey-darken-1">
                            {{ formatDateTime(item.consentExpiresAt) }}
                        </span>
                        <span v-else class="text-caption text-grey">—</span>
                    </template>

                    <template v-slot:item.rejectionReason="{ item }">
                        <span v-if="item.rejectionReason" class="text-body-2 text-error font-weight-medium">
                            {{ item.rejectionReason }}
                        </span>
                        <span v-else class="text-caption text-grey">—</span>
                    </template>

                    <template v-slot:no-data>
                        <div class="text-center py-12">
                            <v-icon size="64" color="grey-lighten-1" class="mb-4">mdi-file-document-outline</v-icon>
                            <p class="text-h6 text-medium-emphasis mb-2">No access logs found</p>
                            <p class="text-body-2 text-medium-emphasis">
                                {{ hasActiveFilters ? 'Try adjusting your filters' : 'Access logs will appear here once your OAuth applications receive requests' }}
                            </p>
                        </div>
                    </template>

                    <template v-slot:loading>
                        <div class="text-center py-8">
                            <v-progress-circular indeterminate color="primary" />
                            <p class="mt-4 text-body-2 text-medium-emphasis">Loading access logs...</p>
                        </div>
                    </template>
                    </v-data-table>
                </div>

                <!-- Pagination Controls -->
                <v-card-actions class="px-4 py-3 bg-grey-lighten-5">
                    <div class="d-flex align-center justify-space-between flex-wrap" style="width: 100%;">
                        <div class="d-flex align-center ga-3">
                            <span class="text-body-2 text-medium-emphasis">Items per page:</span>
                            <v-select
                                v-model="itemsPerPage"
                                :items="itemsPerPageOptions"
                                :item-title="(item) => item === -1 ? 'All' : item.toString()"
                                :item-value="(item) => item"
                                density="compact"
                                variant="outlined"
                                hide-details
                                style="max-width: 100px;"
                                @update:model-value="handleItemsPerPageChange"
                            />
                        </div>

                        <div class="d-flex align-center ga-4">
                            <span class="text-body-2 text-medium-emphasis">
                                {{ paginationRange }}
                            </span>
                            <div class="d-flex align-center ga-1">
                                <v-btn
                                    icon="mdi-page-first"
                                    variant="text"
                                    size="small"
                                    :disabled="currentPage === 1 || loading"
                                    @click="goToFirstPage"
                                />
                                <v-btn
                                    icon="mdi-chevron-left"
                                    variant="text"
                                    size="small"
                                    :disabled="currentPage === 1 || loading"
                                    @click="goToPreviousPage"
                                />
                                <v-btn
                                    icon="mdi-chevron-right"
                                    variant="text"
                                    size="small"
                                    :disabled="isLastPage || loading"
                                    @click="goToNextPage"
                                />
                                <v-btn
                                    icon="mdi-page-last"
                                    variant="text"
                                    size="small"
                                    :disabled="isLastPage || loading"
                                    @click="goToLastPage"
                                />
                            </div>
                        </div>
                    </div>
                </v-card-actions>
            </v-card>
        </v-container>
    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { developerApi, type AccessLogEntry, type AccessLogStatistics, type AccessLogFilters } from '@/api/developerApi';
import { formatDateTime, formatTime } from '@/utils/formatters';

// State
const loading = ref(false);
const exporting = ref(false);
const logs = ref<AccessLogEntry[]>([]);
const totalCount = ref(0);
const statistics = ref<AccessLogStatistics>({
    total: 0,
    approved: 0,
    pending: 0,
    rejected: 0,
    successRate: 0,
});
// Date range preset
const dateRangePreset = ref<string | undefined>(undefined);

// Date range options
const dateRangeOptions = [
    { title: 'All Time', value: undefined },
    { title: 'Today', value: 'today' },
    { title: 'Yesterday', value: 'yesterday' },
    { title: 'Last Week', value: 'lastWeek' },
    { title: 'Last Month', value: 'lastMonth' },
    { title: 'Last Year', value: 'lastYear' },
    { title: 'Custom', value: 'custom' },
];

// Pagination state
const itemsPerPage = ref(50);
const currentPage = ref(1);
const itemsPerPageOptions = [10, 25, 50, 100, -1]; // -1 means "All"

// Filters
const filters = ref<AccessLogFilters>({
    startDate: undefined,
    endDate: undefined,
    status: undefined,
    clientId: undefined,
    limit: 50, // Default to 50 items per page
    page: 1, // Default to page 1
});

// Table headers - all columns from OAuth2Request (excluding User ID and Code for security)
const tableHeaders = [
    { title: 'Timestamp', key: 'timestamp', sortable: false, width: '160px' },
    { title: 'Client Name', key: 'clientName', sortable: false, width: '150px' },
    { title: 'Client ID', key: 'clientId', sortable: false, width: '180px' },
    { title: 'Status', key: 'accessStatus', sortable: false, width: '120px' },
    { title: 'Redirect URI', key: 'redirectUri', sortable: false, width: '220px' },
    { title: 'Scopes', key: 'scopes', sortable: false, width: '150px' },
    { title: 'Approved Scopes', key: 'approvedScopes', sortable: false, width: '150px' },
    { title: 'Rejected Scopes', key: 'rejectedScopes', sortable: false, width: '150px' },
    { title: 'Code Expires At', key: 'codeExpiresAt', sortable: false, width: '160px' },
    { title: 'Consent Expires At', key: 'consentExpiresAt', sortable: false, width: '160px' },
    { title: 'Rejection Reason', key: 'rejectionReason', sortable: false, width: '200px' },
];

// Status options
const statusOptions = [
    { title: 'All', value: undefined },
    { title: 'Pending', value: 0 },
    { title: 'Approved', value: 1 },
    { title: 'Rejected', value: 2 },
];

// Computed
const successRateFormatted = computed(() => {
    const rate = statistics.value.successRate;
    if (isNaN(rate) || !isFinite(rate)) {
        return '0.0';
    }
    return rate.toFixed(1);
});

const hasActiveFilters = computed(() => {
    return !!(
        filters.value.startDate ||
        filters.value.endDate ||
        filters.value.status !== undefined ||
        filters.value.clientId ||
        dateRangePreset.value
    );
});

// Pagination computed properties
const totalPages = computed(() => {
    if (itemsPerPage.value === -1 || totalCount.value === 0) return 1;
    return Math.ceil(totalCount.value / itemsPerPage.value);
});

const isLastPage = computed(() => {
    return currentPage.value >= totalPages.value || loading.value;
});

const paginationRange = computed(() => {
    if (totalCount.value === 0) return '0-0 of 0';
    if (itemsPerPage.value === -1) {
        return `1-${totalCount.value} of ${totalCount.value}`;
    }
    // Calculate correct range based on current page
    // Page 1: 1-50, Page 2: 51-100, Page 3: 101-150, etc.
    const start = (currentPage.value - 1) * itemsPerPage.value + 1;
    const end = Math.min(currentPage.value * itemsPerPage.value, totalCount.value);
    return `${start}-${end} of ${totalCount.value}`;
});

// Pagination handlers
const handleItemsPerPageChange = () => {
    currentPage.value = 1; // Reset to first page when changing items per page
    loadLogs();
};

const goToFirstPage = () => {
    if (currentPage.value !== 1 && !loading.value) {
        currentPage.value = 1;
        loadLogs();
    }
};

const goToPreviousPage = () => {
    const prevPage = currentPage.value - 1;
    if (prevPage >= 1 && !loading.value) {
        currentPage.value = prevPage;
        loadLogs();
    }
};

const goToNextPage = () => {
    if (loading.value) {
        console.log('[AccessLogs] goToNextPage: Already loading, skipping');
        return;
    }
    const nextPage = currentPage.value + 1;
    const maxPage = totalPages.value;
    console.log('[AccessLogs] goToNextPage: Current page:', currentPage.value, 'Next page:', nextPage, 'Max page:', maxPage);
    if (nextPage <= maxPage && maxPage > 0) {
        currentPage.value = nextPage;
        console.log('[AccessLogs] goToNextPage: Updated currentPage to:', currentPage.value);
        loadLogs();
    } else {
        console.log('[AccessLogs] goToNextPage: Cannot go to next page - condition failed');
    }
};

const goToLastPage = () => {
    const lastPage = totalPages.value;
    if (currentPage.value !== lastPage && !loading.value && lastPage > 0) {
        currentPage.value = lastPage;
        loadLogs();
    }
};

// Methods
// Handle date range preset change
const handleDateRangeChange = (preset: string | undefined) => {
    // Get current date in UTC to avoid timezone issues
    const now = new Date();
    const todayUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    
    // Clear dates first
    filters.value.startDate = undefined;
    filters.value.endDate = undefined;
    
    if (!preset || preset === 'custom') {
        // Custom or cleared - dates will be set manually
        if (preset !== 'custom') {
            dateRangePreset.value = undefined;
        }
        return;
    }
    
    let startDate: Date;
    let endDate: Date;
    
    switch (preset) {
        case 'today':
            startDate = new Date(Date.UTC(todayUTC.getUTCFullYear(), todayUTC.getUTCMonth(), todayUTC.getUTCDate(), 0, 0, 0, 0));
            endDate = new Date(Date.UTC(todayUTC.getUTCFullYear(), todayUTC.getUTCMonth(), todayUTC.getUTCDate(), 23, 59, 59, 999));
            break;
        case 'yesterday':
            const yesterdayUTC = new Date(todayUTC);
            yesterdayUTC.setUTCDate(yesterdayUTC.getUTCDate() - 1);
            startDate = new Date(Date.UTC(yesterdayUTC.getUTCFullYear(), yesterdayUTC.getUTCMonth(), yesterdayUTC.getUTCDate(), 0, 0, 0, 0));
            endDate = new Date(Date.UTC(yesterdayUTC.getUTCFullYear(), yesterdayUTC.getUTCMonth(), yesterdayUTC.getUTCDate(), 23, 59, 59, 999));
            break;
        case 'lastWeek':
            const lastWeekUTC = new Date(todayUTC);
            lastWeekUTC.setUTCDate(lastWeekUTC.getUTCDate() - 7);
            startDate = new Date(Date.UTC(lastWeekUTC.getUTCFullYear(), lastWeekUTC.getUTCMonth(), lastWeekUTC.getUTCDate(), 0, 0, 0, 0));
            endDate = new Date(Date.UTC(todayUTC.getUTCFullYear(), todayUTC.getUTCMonth(), todayUTC.getUTCDate(), 23, 59, 59, 999));
            break;
        case 'lastMonth':
            const lastMonthUTC = new Date(todayUTC);
            lastMonthUTC.setUTCMonth(lastMonthUTC.getUTCMonth() - 1);
            startDate = new Date(Date.UTC(lastMonthUTC.getUTCFullYear(), lastMonthUTC.getUTCMonth(), lastMonthUTC.getUTCDate(), 0, 0, 0, 0));
            endDate = new Date(Date.UTC(todayUTC.getUTCFullYear(), todayUTC.getUTCMonth(), todayUTC.getUTCDate(), 23, 59, 59, 999));
            break;
        case 'lastYear':
            const lastYearUTC = new Date(todayUTC);
            lastYearUTC.setUTCFullYear(lastYearUTC.getUTCFullYear() - 1);
            startDate = new Date(Date.UTC(lastYearUTC.getUTCFullYear(), lastYearUTC.getUTCMonth(), lastYearUTC.getUTCDate(), 0, 0, 0, 0));
            endDate = new Date(Date.UTC(todayUTC.getUTCFullYear(), todayUTC.getUTCMonth(), todayUTC.getUTCDate(), 23, 59, 59, 999));
            break;
        default:
            return;
    }
    
    // Format as YYYY-MM-DD for the date input fields
    filters.value.startDate = startDate.toISOString().split('T')[0];
    filters.value.endDate = endDate.toISOString().split('T')[0];
    applyFilters();
};

const loadLogs = async () => {
    loading.value = true;
    try {
        // Calculate limit and page based on pagination
        const limit = itemsPerPage.value === -1 ? 0 : itemsPerPage.value; // 0 = all results
        const page = itemsPerPage.value === -1 ? 1 : currentPage.value;

        // Debug: Log pagination state
        console.log('[AccessLogs] loadLogs - Page:', page, 'Limit:', limit, 'CurrentPage state:', currentPage.value);

        // Build filters for API with pagination (using page instead of offset)
        const apiFilters: AccessLogFilters = {
            limit: limit,
            page: page,
        };

        if (filters.value.startDate) {
            // Parse date string (YYYY-MM-DD) and create UTC date at start of day
            // Use UTC to avoid timezone issues - database stores in UTC
            const dateStr = filters.value.startDate;
            const [year, month, day] = dateStr.split('-').map(Number);
            // Create date in UTC at start of day (month is 0-indexed)
            const utcDate = new Date(Date.UTC(year, month - 1, day, 0, 0, 0, 0));
            apiFilters.startDate = utcDate.toISOString();
            console.log('[AccessLogs] Date filter - startDate:', dateStr, '-> ISO:', apiFilters.startDate);
        }

        if (filters.value.endDate) {
            // Parse date string (YYYY-MM-DD) and create UTC date at end of day
            // Use UTC to avoid timezone issues - database stores in UTC
            const dateStr = filters.value.endDate;
            const [year, month, day] = dateStr.split('-').map(Number);
            // Create date in UTC at end of day (month is 0-indexed)
            const utcDate = new Date(Date.UTC(year, month - 1, day, 23, 59, 59, 999));
            apiFilters.endDate = utcDate.toISOString();
            console.log('[AccessLogs] Date filter - endDate:', dateStr, '-> ISO:', apiFilters.endDate);
        }

        if (filters.value.status !== undefined) {
            apiFilters.status = filters.value.status;
        }

        if (filters.value.clientId) {
            apiFilters.clientId = filters.value.clientId;
        }

        // Load logs and statistics in parallel
        // Statistics are always fetched without filters (all time stats)
        const [logsResponse, statsData] = await Promise.all([
            developerApi.listAccessLogs(apiFilters),
            developerApi.getAccessLogStatistics(),
        ]);

        // Ensure all data is properly mapped
        const receivedLogs = logsResponse.logs || [];
        logs.value = receivedLogs;
        totalCount.value = logsResponse.totalCount || 0;
        statistics.value = statsData;
        
        // Debug: Log response details
        console.log('[AccessLogs] Response received - Backend currentPage:', logsResponse.currentPage, 'Our currentPage:', currentPage.value);
        console.log('[AccessLogs] Logs count:', receivedLogs.length, 'TotalCount:', totalCount.value);
        console.log('[AccessLogs] Raw logsResponse:', logsResponse);
        console.log('[AccessLogs] First few logs:', receivedLogs.slice(0, 3));
        console.log('[AccessLogs] logs.value after assignment:', logs.value);
        console.log('[AccessLogs] logs.value length:', logs.value.length);
        
        // Don't overwrite currentPage from response - we set it correctly before calling loadLogs()
        // Trust our local state since we control the page navigation
        // The backend should return the same page we requested
    } catch (error) {
        console.error('Failed to load access logs:', error);
        logs.value = [];
        totalCount.value = 0;
        // Show error notification
        // You can add a snackbar/toast notification here
    } finally {
        loading.value = false;
    }
};

const applyFilters = () => {
    currentPage.value = 1; // Reset to first page when applying filters
    loadLogs();
};

const exportLogs = async () => {
    exporting.value = true;
    try {
        // Build filters for export - include pagination to export only current page
        const limit = itemsPerPage.value === -1 ? 0 : itemsPerPage.value; // -1 means all, 0 means all in backend
        const page = itemsPerPage.value === -1 ? 1 : currentPage.value;
        
        const apiFilters: AccessLogFilters = {
            limit: limit,
            page: page,
        };

        if (filters.value.startDate) {
            // Parse date string (YYYY-MM-DD) and create UTC date at start of day
            const dateStr = filters.value.startDate;
            const [year, month, day] = dateStr.split('-').map(Number);
            const utcDate = new Date(Date.UTC(year, month - 1, day, 0, 0, 0, 0));
            apiFilters.startDate = utcDate.toISOString();
        }

        if (filters.value.endDate) {
            // Parse date string (YYYY-MM-DD) and create UTC date at end of day
            const dateStr = filters.value.endDate;
            const [year, month, day] = dateStr.split('-').map(Number);
            const utcDate = new Date(Date.UTC(year, month - 1, day, 23, 59, 59, 999));
            apiFilters.endDate = utcDate.toISOString();
        }

        if (filters.value.status !== undefined) {
            apiFilters.status = filters.value.status;
        }

        if (filters.value.clientId) {
            apiFilters.clientId = filters.value.clientId;
        }

        const blob = await developerApi.exportAccessLogs(apiFilters);
        
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `access-logs-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Failed to export access logs:', error);
        // Show error notification
    } finally {
        exporting.value = false;
    }
};

const getStatusColor = (status: string): string => {
    switch (status.toLowerCase()) {
        case 'approved':
            return 'success';
        case 'rejected':
            return 'error';
        case 'pending':
            return 'warning';
        default:
            return 'grey';
    }
};

const getStatusIcon = (status: string): string => {
    switch (status.toLowerCase()) {
        case 'approved':
            return 'mdi-check-circle';
        case 'rejected':
            return 'mdi-close-circle';
        case 'pending':
            return 'mdi-clock-outline';
        default:
            return 'mdi-help-circle';
    }
};

// Lifecycle
onMounted(() => {
    loadLogs();
});
</script>

<style scoped lang="scss">
.access-logs-page {
    min-height: 100vh;
    background-color: rgb(var(--v-theme-background));
}

.page-header {
    background: linear-gradient(135deg, rgb(var(--v-theme-primary)) 0%, rgb(var(--v-theme-primary-darken-1)) 100%);
    color: white;
    padding: 2rem 0;
    margin-bottom: 2rem;

    .header-content {
        max-width: 1400px;
        margin: 0 auto;
        padding: 0 2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
    }

    .page-title {
        font-size: 2rem;
        font-weight: 600;
        margin: 0;
        color: white;
    }

    .page-subtitle {
        font-size: 0.95rem;
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
        color: white;
    }

    .header-actions {
        display: flex;
        gap: 0.75rem;
        flex-wrap: wrap;
    }
}

.stats-row {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
}

.stats-row .stat-card {
    flex: 1;
    min-width: 180px;
}

.stat-card {
    transition: all 0.3s ease;
    border-radius: 8px;

    &:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }

    .stat-icon-wrapper {
        width: 48px;
        height: 48px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .stat-icon-primary {
        background-color: rgba(var(--v-theme-primary), 0.1);
    }

    .stat-icon-success {
        background-color: rgba(var(--v-theme-success), 0.1);
    }

    .stat-icon-warning {
        background-color: rgba(var(--v-theme-warning), 0.1);
    }

    .stat-icon-error {
        background-color: rgba(var(--v-theme-error), 0.1);
    }

    .stat-icon-info {
        background-color: rgba(var(--v-theme-info), 0.1);
    }

    .stat-label {
        font-size: 0.875rem;
        color: rgb(var(--v-theme-on-surface));
        opacity: 0.7;
        margin-bottom: 0.25rem;
    }

    .stat-value {
        font-size: 1.5rem;
        font-weight: 600;
        line-height: 1.2;
    }
}

.filters-card {
    border-radius: 8px;
}

.log-row {
    transition: background-color 0.2s ease;

    &:hover {
        background-color: rgba(var(--v-theme-primary), 0.04);
    }
}

.redirect-uri {
    font-size: 0.75rem;
    background-color: rgba(var(--v-theme-surface-variant), 0.5);
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    color: rgb(var(--v-theme-on-surface));
    word-break: break-all;
}

.table-card {
    overflow: visible !important;
}

.table-card :deep(.v-card-text) {
    overflow: visible !important;
    padding: 0 !important;
}

.table-wrapper-horizontal {
    overflow-x: auto !important;
    overflow-y: visible !important;
    width: 100% !important;
    -webkit-overflow-scrolling: touch;
}

.table-wrapper-horizontal::-webkit-scrollbar {
    height: 8px;
}

.table-wrapper-horizontal::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 4px;
}

.table-wrapper-horizontal::-webkit-scrollbar-thumb {
    background: #888;
    border-radius: 4px;
}

.table-wrapper-horizontal::-webkit-scrollbar-thumb:hover {
    background: #555;
}

// Admin-style colorful table
:deep(.admin-data-table) {
    min-width: 2400px !important; // Force minimum width to show all columns
    width: max-content !important;
    
    // Force table to show headers
    table {
        border-collapse: separate !important;
        border-spacing: 0 !important;
        width: 100% !important;
        min-width: 2400px !important;
    }
    
    thead {
        display: table-header-group !important;
        visibility: visible !important;
        background: linear-gradient(135deg, #e8ecff 0%, #f0e8ff 100%) !important; // Light gradient default
    }
    
    // Dark mode thead
    .v-theme--dark thead {
        background: linear-gradient(135deg, #4a5fc7 0%, #5a3a7a 100%) !important;
    }
    
    // Light mode thead
    .v-theme--light thead {
        background: linear-gradient(135deg, #e8ecff 0%, #f0e8ff 100%) !important;
    }

    .v-data-table__thead {
        background: linear-gradient(135deg, #e8ecff 0%, #f0e8ff 100%) !important; // Light gradient for light mode
        display: table-header-group !important;
        visibility: visible !important;
        width: 100% !important;
    }
    
    // Dark mode - darker gradient with white text
    .v-theme--dark .v-data-table__thead {
        background: linear-gradient(135deg, #4a5fc7 0%, #5a3a7a 100%) !important;
    }
    
    // Light mode - light gradient with dark text
    .v-theme--light .v-data-table__thead {
        background: linear-gradient(135deg, #e8ecff 0%, #f0e8ff 100%) !important;
    }

    .v-data-table__th {
        font-weight: 600 !important;
        font-size: 12px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
        color: #1a1a1a !important; // Dark text for better readability
        padding: 16px !important;
        border-bottom: none !important;
        white-space: nowrap !important;
        display: table-cell !important;
        visibility: visible !important;
        opacity: 1 !important;
        background: transparent !important;
        min-width: fit-content !important;
    }
    
    // Dark mode support - use lighter text in dark mode
    .v-theme--dark .v-data-table__th {
        color: rgba(255, 255, 255, 0.95) !important; // White text in dark mode
    }
    
    // Light mode - use dark text for better contrast
    .v-theme--light .v-data-table__th {
        color: #1a1a1a !important; // Dark text in light mode
    }
    
    // Ensure all header cells are visible
    th {
        display: table-cell !important;
        visibility: visible !important;
        opacity: 1 !important;
        background: transparent !important;
    }
    
    // Force header row to display
    .v-data-table__thead tr {
        display: table-row !important;
    }
    
    .v-data-table__thead th {
        display: table-cell !important;
        visibility: visible !important;
    }
    
    // Apply theme-aware colors to header cells
    .v-theme--dark .v-data-table__thead th {
        color: rgba(255, 255, 255, 0.95) !important;
    }
    
    .v-theme--light .v-data-table__thead th {
        color: #1a1a1a !important;
    }
    
    .v-data-table__tbody {
        display: table-row-group !important;
    }
    
    .v-data-table__tr {
        display: table-row !important;
        transition: all 0.2s ease;
        
        &:hover {
            background: #f9fafb !important;
            transform: scale(1.001);
        }
        
        &:nth-child(even) {
            background-color: #fafbfc;
        }
    }
    
    .v-data-table__td {
        display: table-cell !important;
        white-space: nowrap !important;
        padding: 16px !important;
        border-bottom: 1px solid rgba(0, 0, 0, 0.08) !important;
        background-color: #ffffff !important;
    }
    
    // Remove height restrictions - only table-wrapper-horizontal handles scrolling
    .v-table__wrapper {
        overflow: visible !important;
        max-height: none !important;
        height: auto !important;
    }
    
    .v-data-table__wrapper {
        overflow: visible !important;
        max-height: none !important;
        height: auto !important;
    }
}

.client-id-code {
    font-size: 11px;
    background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
    padding: 4px 8px;
    border-radius: 4px;
    color: #667eea;
    font-weight: 500;
    border: 1px solid rgba(102, 126, 234, 0.2);
}

.user-id-code {
    font-size: 11px;
    background: rgba(156, 39, 176, 0.1);
    padding: 4px 8px;
    border-radius: 4px;
    color: #9c27b0;
    font-weight: 500;
    border: 1px solid rgba(156, 39, 176, 0.2);
}

.code-value {
    font-size: 11px;
    background: rgba(255, 152, 0, 0.1);
    padding: 4px 8px;
    border-radius: 4px;
    color: #ff9800;
    font-weight: 500;
    border: 1px solid rgba(255, 152, 0, 0.2);
}

.redirect-uri-code {
    font-size: 11px;
    background: rgba(33, 150, 243, 0.1);
    padding: 4px 8px;
    border-radius: 4px;
    color: #2196f3;
    font-weight: 500;
    border: 1px solid rgba(33, 150, 243, 0.2);
    word-break: break-all;
    display: inline-block;
    max-width: 100%;
}

.status-chip {
    font-weight: 600;
    text-transform: capitalize;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.scope-chip {
    font-weight: 500;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
}

// Dark mode adjustments
.v-theme--dark {
    .page-header {
        background: linear-gradient(135deg, rgb(var(--v-theme-primary)) 0%, rgb(var(--v-theme-primary-darken-1)) 100%);
    }

    .stat-card {
        background-color: rgb(var(--v-theme-surface));
    }

    .filters-card {
        background-color: rgb(var(--v-theme-surface));
    }

    .redirect-uri {
        background-color: rgba(var(--v-theme-surface-variant), 0.3);
    }
}
</style>




