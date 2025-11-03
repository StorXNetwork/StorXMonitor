// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-dialog v-model="dialog" activator="parent" width="auto" transition="fade-transition">
        <v-card rounded="xlg">
            <v-sheet>
                <v-card-item class="pl-7 py-4">
                    <template #prepend>
                        <v-card-title class="font-weight-bold">
                            Account Placement
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
                        <p>Select a placement region for this account.</p>
                        <p>Applies to all the projects, buckets, and data.</p>
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12">
                        <v-select
                            v-model="accountPlacement"
                            label="Account Placement" placeholder="Select the placement region."
                            :items="placementOptions.map(opt => opt.value)" variant="outlined" chips
                            hide-details="auto" :disabled="loading"
                        />
                    </v-col>
                </v-row>

                <v-row>
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
        The account placement was set successfully.
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
    VTextField,
    VCardActions,
    VSnackbar,
    VSelect,
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

const accountPlacement = ref<string>('global');
const email = ref<string>('');
const hasGeofence = ref<boolean>(false);

const placementOptions = [
    { value: 'global', label: 'Global' },
    { value: 'us-select-1', label: 'US Select 1' },
];

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
        // Check if placement is set (non-zero means geofence exists)
        hasGeofence.value = userInfo.user.placement !== 0;
        // Map placement number to string
        if (userInfo.user.placement === 0) {
            accountPlacement.value = 'global';
        } else {
            accountPlacement.value = `placement-${userInfo.user.placement}`;
        }
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
        // Parse placement from string (e.g., "placement-1" -> 1, "global" -> 0)
        const placementNum = accountPlacement.value === 'global' ? 0 : parseInt(accountPlacement.value.replace('placement-', ''));
        
        if (hasGeofence.value && placementNum === 0) {
            // Delete geofence if switching to global
            await adminApi.deleteGeofenceForAccount(userEmail.value);
        } else if (placementNum !== 0) {
            // Create/update geofence
            await adminApi.createGeofenceForAccount(userEmail.value, placementNum);
        }
        
        snackbar.value = true;
        dialog.value = false;
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to update account placement';
        errorSnackbar.value = true;
    } finally {
        loading.value = false;
    }
}
</script>
