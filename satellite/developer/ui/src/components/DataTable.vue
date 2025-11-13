<template>
    <v-card class="data-table-card" elevation="0" variant="outlined">
        <v-card-text class="pa-0">
            <v-data-table
                :headers="headers"
                :items="items"
                :loading="loading"
                :items-per-page="itemsPerPage"
                :items-per-page-options="itemsPerPageOptions"
                :sort-by="sortBy"
                class="admin-data-table"
                item-value="id"
            >
                <template v-slot:top>
                    <div v-if="title || $slots.toolbar" class="d-flex justify-space-between align-center pa-4 border-b">
                        <h3 v-if="title" class="text-h6 font-weight-medium">{{ title }}</h3>
                        <slot name="toolbar" />
                    </div>
                </template>

                <slot />

                <template v-slot:no-data>
                    <div class="text-center py-12">
                        <v-icon size="64" color="grey-lighten-1" class="mb-4">mdi-database-off</v-icon>
                        <div class="text-h6 text-medium-emphasis mb-2">No Data Available</div>
                        <div class="text-body-2 text-medium-emphasis">{{ noDataText }}</div>
                    </div>
                </template>

                <template v-slot:loading>
                    <div class="text-center py-8">
                        <v-progress-circular indeterminate color="primary" />
                    </div>
                </template>
            </v-data-table>
        </v-card-text>
    </v-card>
</template>

<script setup lang="ts">
defineProps<{
    headers: any[];
    items: any[];
    loading?: boolean;
    title?: string;
    itemsPerPage?: number;
    itemsPerPageOptions?: number[];
    sortBy?: any[];
    noDataText?: string;
}>();
</script>

<style scoped lang="scss">
.data-table-card {
    border-radius: 8px;
    overflow: hidden;
}

.border-b {
    border-bottom: 1px solid rgba(0, 0, 0, 0.12);
}

:deep(.admin-data-table) {
    .v-data-table__thead {
        background-color: #f5f7fa;
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
        background-color: #f9fafb;
    }
}
</style>

