// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-dialog v-model="dialog" activator="parent" width="600" transition="fade-transition" persistent>
        <v-card rounded="lg">
            <v-sheet>
                <v-card-item class="pl-7 py-4">
                    <template #prepend>
                        <v-card-title class="font-weight-bold">
                            Upgrade Account
                        </v-card-title>
                    </template>

                    <template #append>
                        <v-btn icon="$close" variant="text" size="small" color="default" @click="dialog = false" />
                    </template>
                </v-card-item>
            </v-sheet>

            <v-divider />

            <v-form v-model="valid" class="pa-7" @submit.prevent="onButtonClick">
                <v-row>
                    <v-col cols="12">
                        <p class="text-body-2 text-medium-emphasis">
                            Upgrade user account to paid tier and set project limits. This will update all existing projects.
                        </p>
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12">
                        <v-text-field
                            v-model="email"
                            label="Account Email"
                            variant="solo-filled"
                            flat
                            readonly
                            hide-details="auto"
                        />
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12" md="6">
                        <v-text-field
                            v-model.number="storageLimitGB"
                            label="Storage Limit"
                            type="number"
                            suffix="GB"
                            variant="outlined"
                            :rules="[rules.required, rules.minValue]"
                            hide-details="auto"
                            :disabled="loading"
                            @input="updateStorageBytes"
                        />
                        <p class="text-caption text-medium-emphasis mt-1">
                            Per project: {{ formatBytes(storageLimitBytes) }}
                        </p>
                    </v-col>
                    <v-col cols="12" md="6">
                        <v-text-field
                            v-model.number="bandwidthLimitGB"
                            label="Bandwidth Limit"
                            type="number"
                            suffix="GB"
                            variant="outlined"
                            :rules="[rules.required, rules.minValue]"
                            hide-details="auto"
                            :disabled="loading"
                            @input="updateBandwidthBytes"
                        />
                        <p class="text-caption text-medium-emphasis mt-1">
                            Per project: {{ formatBytes(bandwidthLimitBytes) }}
                        </p>
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12">
                        <v-checkbox
                            v-model="upgradeToPaid"
                            label="Upgrade to Paid Tier"
                            color="primary"
                            hide-details
                            :disabled="loading"
                        />
                        <p class="text-caption text-medium-emphasis ml-8 mt-1">
                            Set user's paid_tier status to true
                        </p>
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12">
                        <v-checkbox
                            v-model="resetExpiration"
                            label="Reset Expiration Tracking"
                            color="primary"
                            hide-details
                            :disabled="loading"
                        />
                        <p class="text-caption text-medium-emphasis ml-8 mt-1">
                            Reset prevdays_untilexpiration to 0 and update created_at timestamp
                        </p>
                    </v-col>
                </v-row>
            </v-form>

            <v-divider />

            <v-card-actions class="pa-7">
                <v-row>
                    <v-col>
                        <v-btn variant="outlined" color="default" block :disabled="loading" @click="dialog = false">
                            Cancel
                        </v-btn>
                    </v-col>
                    <v-col>
                        <v-btn
                            color="primary"
                            variant="flat"
                            block
                            :loading="loading"
                            :disabled="!valid"
                            @click="onButtonClick"
                        >
                            Upgrade Account
                        </v-btn>
                    </v-col>
                </v-row>
            </v-card-actions>
        </v-card>

        <v-snackbar v-model="snackbar" :timeout="7000" color="success">
            Account upgraded successfully!
            <template #actions>
                <v-btn color="default" variant="text" @click="snackbar = false">Close</v-btn>
            </template>
        </v-snackbar>

        <v-snackbar v-model="errorSnackbar" :timeout="7000" color="error">
            {{ errorMessage }}
            <template #actions>
                <v-btn color="default" variant="text" @click="errorSnackbar = false">Close</v-btn>
            </template>
        </v-snackbar>
    </v-dialog>
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
    VCheckbox,
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

const email = computed(() => props.userEmail || '');

const storageLimitGB = ref<number>(20);
const bandwidthLimitGB = ref<number>(20);
const storageLimitBytes = ref<number>(20 * 1024 * 1024 * 1024); // 20GB in bytes
const bandwidthLimitBytes = ref<number>(20 * 1024 * 1024 * 1024); // 20GB in bytes
const upgradeToPaid = ref<boolean>(true);
const resetExpiration = ref<boolean>(true);

const rules = {
    required: (value: number) => (value !== null && value !== undefined && value > 0) || 'This field is required',
    minValue: (value: number) => value > 0 || 'Value must be greater than 0',
};

function updateStorageBytes() {
    storageLimitBytes.value = storageLimitGB.value * 1024 * 1024 * 1024;
}

function updateBandwidthBytes() {
    bandwidthLimitBytes.value = bandwidthLimitGB.value * 1024 * 1024 * 1024;
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

const emit = defineEmits<{
    'account-upgraded': [];
}>();

async function onButtonClick() {
    if (!valid.value || !email.value || loading.value) return;

    try {
        loading.value = true;
        await adminApi.upgradeUserAccount(email.value, {
            storageLimit: storageLimitBytes.value,
            bandwidthLimit: bandwidthLimitBytes.value,
            upgradeToPaid: upgradeToPaid.value,
            resetExpiration: resetExpiration.value,
        });
        snackbar.value = true;
        dialog.value = false;

        // Emit event to refresh parent component
        emit('account-upgraded');
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to upgrade account';
        errorSnackbar.value = true;
    } finally {
        loading.value = false;
    }
}

// Reset form when dialog opens
watch(() => dialog.value, (isOpen) => {
    if (isOpen) {
        storageLimitGB.value = 20;
        bandwidthLimitGB.value = 20;
        updateStorageBytes();
        updateBandwidthBytes();
        upgradeToPaid.value = true;
        resetExpiration.value = true;
    }
});
</script>

