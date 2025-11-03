// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-card variant="flat" :border="true" rounded="xlg">
        <v-text-field
            v-model="search" label="Search" prepend-inner-icon="mdi-magnify" single-line variant="solo-filled" flat
            hide-details clearable density="compact" rounded="lg" class="mx-2 mt-2"
        />

        <v-data-table
            v-model="selected" v-model:sort-by="sortBy" :headers="headers" :items="loginHistory" :search="search"
            class="elevation-1" item-key="id" density="comfortable" show-expand hover @item-click="handleItemClick"
        >
            <template #expanded-row="{ columns, item }">
                <tr>
                    <td :colspan="columns.length">
                        <div class="pa-4">
                            <h4>Session Details</h4>
                            <p><strong>Session ID:</strong> {{ item.raw.id }}</p>
                            <p><strong>User Agent:</strong> {{ item.raw.userAgent }}</p>
                            <p><strong>Status:</strong> {{ item.raw.isActive ? 'Active' : 'Expired' }}</p>
                            <p><strong>Expires At:</strong> {{ formatDateTime(item.raw.expiresAt) }}</p>
                        </div>
                    </td>
                </tr>
            </template>

            <template #item.status="{ item }">
                <v-chip 
                    :color="item.raw.isActive ? 'success' : 'default'" 
                    variant="tonal" 
                    size="small" 
                    rounded="lg"
                >
                    {{ item.raw.isActive ? 'Active' : 'Expired' }}
                </v-chip>
            </template>

            <template #item.ipAddress="{ item }">
                <v-chip variant="outlined" size="small" rounded="lg" @click="setSearch(item.raw.ipAddress)">
                    {{ item.raw.ipAddress }}
                </v-chip>
            </template>

            <template #item.userAgent="{ item }">
                <span class="text-caption">{{ truncateUserAgent(item.raw.userAgent) }}</span>
            </template>

            <template #item.loginTime="{ item }">
                <span class="text-no-wrap">
                    {{ formatDateTime(item.raw.loginTime) }}
                </span>
            </template>
        </v-data-table>
    </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { VCard, VTextField, VChip } from 'vuetify/components';
import { VDataTable } from 'vuetify/labs/components';
import { useAppStore } from '@/store/app';
import { adminApi } from '@/api/adminApi';

const search = ref<string>('');
const selected = ref<string[]>([]);
const sortBy = ref([{ key: 'loginTime', order: 'desc' as const }]);
const loginHistory = ref<any[]>([]);
const loading = ref(false);

const appStore = useAppStore();

const headers = [
    { title: 'Login Time', key: 'loginTime' },
    { title: 'IP Address', key: 'ipAddress' },
    { title: 'User Agent', key: 'userAgent' },
    { title: 'Status', key: 'status' },
    { title: '', key: 'data-table-expand' },
];

// Load login history when component mounts
onMounted(async () => {
    await loadLoginHistory();
});

async function loadLoginHistory() {
    const userAccount = appStore.state.userAccount;
    if (!userAccount?.email) {
        return;
    }

    try {
        loading.value = true;
        const response = await adminApi.getUserLoginHistory(userAccount.email);
        loginHistory.value = response.sessions || [];
    } catch (error) {
        console.error('Failed to load login history:', error);
        loginHistory.value = [];
    } finally {
        loading.value = false;
    }
}

function setSearch(searchText: string) {
    search.value = searchText;
}

function formatDateTime(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function truncateUserAgent(userAgent: string): string {
    if (userAgent.length <= 50) {
        return userAgent;
    }
    return userAgent.substring(0, 47) + '...';
}

function handleItemClick(event: any, item: any) {
    // Handle item click if needed
    console.log('Clicked item:', item);
}
</script>
