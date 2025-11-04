// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-menu activator="parent">
        <v-list class="pa-2">
            <v-list-item v-if="featureFlags.account.view" density="comfortable" link rounded="lg" base-color="info" @click="navigateToAccountDetails">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    View Account
                </v-list-item-title>
            </v-list-item>

            <v-divider v-if="featureFlags.account.updateInfo || featureFlags.account.updateStatus || featureFlags.account.updatePlacement || featureFlags.account.updateLimits" class="my-2" />

            <v-list-item v-if="featureFlags.account.updateInfo" density="comfortable" link rounded="lg">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Edit Account
                    <AccountInformationDialog :userEmail="userEmail" @account-updated="handleAccountUpdated" />
                </v-list-item-title>
            </v-list-item>

            <!-- <v-list-item v-if="featureFlags.account.updateStatus" density="comfortable" link rounded="lg">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Set Status
                    <AccountStatusDialog :userEmail="userEmail" />
                </v-list-item-title>
            </v-list-item> -->

            <!-- <v-list-item v-if="featureFlags.account.updateValueAttribution" density="comfortable" link rounded="lg">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Set Value
                    <AccountUserAgentsDialog :userEmail="userEmail" />
                </v-list-item-title>
            </v-list-item> -->

            <!-- <v-list-item v-if="featureFlags.account.updatePlacement" density="comfortable" link rounded="lg">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Set Placement
                    <AccountGeofenceDialog :userEmail="userEmail" />
                </v-list-item-title>
            </v-list-item> -->

            <v-list-item v-if="featureFlags.account.updateLimits" density="comfortable" link rounded="lg">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Change Limits
                    <AccountLimitsDialog :userEmail="userEmail" />
                </v-list-item-title>
            </v-list-item>

            <v-list-item v-if="featureFlags.account.updateLimits" density="comfortable" link rounded="lg" base-color="success">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Upgrade Account
                    <AccountUpgradeDialog :userEmail="userEmail" @account-upgraded="handleAccountUpdated" />
                </v-list-item-title>
            </v-list-item>

            <v-divider v-if="featureFlags.account.resetMFA || featureFlags.account.suspend || featureFlags.account.delete" class="my-2" />

            <v-list-item v-if="featureFlags.account.resetMFA" density="comfortable" link rounded="lg">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Reset MFA
                    <AccountResetMFADialog />
                </v-list-item-title>
            </v-list-item>

            <v-list-item v-if="featureFlags.account.suspend" density="comfortable" link rounded="lg" base-color="warning">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Deactivate Account
                    <AccountSuspendDialog :userEmail="userEmail" @account-deactivated="handleAccountDeactivated" />
                </v-list-item-title>
            </v-list-item>

            <v-list-item v-if="featureFlags.account.delete" density="comfortable" link rounded="lg" base-color="error">
                <v-list-item-title class="text-body-2 font-weight-medium">
                    Delete
                    <AccountDeleteDialog :userEmail="userEmail" @account-deleted="handleAccountDeleted" />
                </v-list-item-title>
            </v-list-item>
        </v-list>
    </v-menu>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { VMenu, VList, VListItem, VListItemTitle, VDivider } from 'vuetify/components';
import { useRouter } from 'vue-router';

import { FeatureFlags } from '@/api/client.gen';
import { useAppStore } from '@/store/app';

import AccountInformationDialog from '@/components/AccountInformationDialog.vue';
import AccountStatusDialog from '@/components/AccountStatusDialog.vue';
import AccountResetMFADialog from '@/components/AccountResetMFADialog.vue';
import AccountSuspendDialog from '@/components/AccountSuspendDialog.vue';
import AccountDeleteDialog from '@/components/AccountDeleteDialog.vue';
import AccountGeofenceDialog from '@/components/AccountGeofenceDialog.vue';
// import AccountUserAgentsDialog from '@/components/AccountUserAgentsDialog.vue';
import AccountLimitsDialog from '@/components/AccountLimitsDialog.vue';
import AccountUpgradeDialog from '@/components/AccountUpgradeDialog.vue';

// Props
const props = defineProps<{
    userEmail?: string;
}>();

const router = useRouter();
const appStore = useAppStore();

// Safely access feature flags with fallback
const featureFlags = computed(() => {
    const settings = appStore.state.settings;
    if (!settings || !settings.admin || !settings.admin.features) {
        return {} as FeatureFlags;
    }
    return settings.admin.features as FeatureFlags;
});

// Navigation function
const navigateToAccountDetails = () => {
    if (props.userEmail) {
        localStorage.setItem('selectedUserEmail', props.userEmail);
        router.push(`/account-details?email=${encodeURIComponent(props.userEmail)}`);
    }
};

// Handle account actions - emit events to parent to refresh data
const emit = defineEmits<{
    'refresh-accounts': [];
}>();

const handleAccountDeactivated = () => {
    emit('refresh-accounts');
};

const handleAccountDeleted = () => {
    emit('refresh-accounts');
};

const handleAccountUpdated = () => {
    emit('refresh-accounts');
};
</script>
