// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-dialog v-model="dialog" activator="parent" width="auto" transition="fade-transition">
        <v-card rounded="xlg">
            <v-sheet>
                <v-card-item class="pl-7 py-4">
                    <template #prepend>
                        <v-card-title class="font-weight-bold">
                            Account Status
                        </v-card-title>
                    </template>

                    <template #append>
                        <v-btn icon="$close" variant="text" size="small" color="default" @click="dialog = false" />
                    </template>
                </v-card-item>
            </v-sheet>

            <v-divider />

            <v-form v-model="valid" class="pa-7">
                <v-row>
                    <v-col cols="12">
                        <p>Select the account status for this user.</p>
                    </v-col>
                </v-row>
                <v-row>
                    <v-col cols="12">
                        <v-select
                            v-model="accountStatus"
                            label="Account Status" placeholder="Select the account status"
                            :items="statusOptions.map(opt => ({ title: opt.label, value: opt.value }))" 
                            chips required variant="outlined"
                            hide-details="auto" :disabled="loading"
                        />
                    </v-col>
                    <v-col cols="12">
                        <v-text-field
                            v-model="email" label="Account Email" variant="solo-filled" flat readonly
                            hide-details="auto"
                        />
                    </v-col>
                </v-row>
            </v-form>

            <v-divider />

            <v-card-actions class="pa-7">
                <v-row>
                    <v-col>
                        <v-btn variant="outlined" color="default" block @click="dialog = false">Cancel</v-btn>
                    </v-col>
                    <v-col>
                        <v-btn color="primary" variant="flat" block :loading="loading" @click="onButtonClick">Save</v-btn>
                    </v-col>
                </v-row>
            </v-card-actions>
        </v-card>
    </v-dialog>

    <v-snackbar v-model="snackbar" :timeout="7000" color="success">
        Successfully saved the account status.
        <template #actions>
            <v-btn color="default" variant="text" @click="snackbar = false">
                Close
            </v-btn>
        </template>
    </v-snackbar>

    <v-snackbar v-model="errorSnackbar" :timeout="7000" color="error">
        {{ errorMessage }}
        <template #actions>
            <v-btn color="default" variant="text" @click="errorSnackbar = false">
                Close
            </v-btn>
        </template>
    </v-snackbar>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import {
    VDialog,
    VCard,
    VSheet,
    VCardItem,
    VCardTitle,
    VBtn,
    VDivider,
    VForm,
    VRow,
    VCol,
    VSelect,
    VTextField,
    VCardActions,
    VSnackbar,
} from 'vuetify/components';
import { adminApi } from '@/api/adminApi';

const props = defineProps<{
    userEmail?: string;
}>();

const snackbar = ref<boolean>(false);
const errorSnackbar = ref<boolean>(false);
const errorMessage = ref<string>('');
const dialog = ref<boolean>(false);
const loading = ref<boolean>(false);
const valid = ref<boolean>(false);

const userEmail = computed(() => {
    return props.userEmail || '';
});

const accountStatus = ref<string>('Active');
const email = ref<string>('');

const statusOptions = [
    { value: 'Active', label: 'Active', status: 1 },
    { value: 'Inactive', label: 'Inactive', status: 0 },
    { value: 'Deleted', label: 'Deleted', status: 2 },
    { value: 'PendingDeletion', label: 'Pending Deletion', status: 3 },
    { value: 'LegalHold', label: 'Legal Hold', status: 4 },
    { value: 'PendingBotVerification', label: 'Pending Bot Verification', status: 5 },
];

const statusMap: { [key: number]: string } = {
    0: 'Inactive',
    1: 'Active',
    2: 'Deleted',
    3: 'PendingDeletion',
    4: 'LegalHold',
    5: 'PendingBotVerification',
};

// Load user data when dialog opens
watch(() => dialog.value, async (isOpen) => {
    if (isOpen && userEmail.value) {
        await loadUserData();
    }
});

async function loadUserData() {
    if (!userEmail.value) return;
    
    try {
        loading.value = true;
        const userInfo = await adminApi.getUserInfo(userEmail.value);
        email.value = userInfo.user.email;
        accountStatus.value = statusMap[userInfo.user.status] || 'Active';
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to load user data';
        errorSnackbar.value = true;
    } finally {
        loading.value = false;
    }
}

async function onButtonClick() {
    if (!valid.value || !userEmail.value) return;
    
    try {
        loading.value = true;
        const statusOption = statusOptions.find(opt => opt.value === accountStatus.value);
        if (!statusOption) {
            errorMessage.value = 'Invalid status selected';
            errorSnackbar.value = true;
            return;
        }
        
        // Update user status using dedicated API
        await adminApi.updateUserStatus(userEmail.value, statusOption.status);
        
        snackbar.value = true;
        dialog.value = false;
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to update account status';
        errorSnackbar.value = true;
    } finally {
        loading.value = false;
    }
}
</script>
