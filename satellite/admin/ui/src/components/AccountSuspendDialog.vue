// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-dialog v-model="dialog" activator="parent" width="auto" transition="fade-transition">
        <v-card rounded="xlg">
            <v-sheet>
                <v-card-item class="pl-7 py-4">
                    <template #prepend>
                        <v-card-title class="font-weight-bold">
                            Deactivate Account
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
                        <p>Please enter the reason for deactivating this account.</p>
                    </v-col>
                </v-row>
                <v-row>
                    <v-col cols="12">
                        <v-select
                            v-model="selected" label="Deactivation reason" placeholder="Select one or more reasons"
                            :items="['Account Delinquent', 'Illegal Content', 'Malicious Links', 'Other']" required multiple
                            variant="outlined" autofocus hide-details="auto" :disabled="loading"
                        />
                    </v-col>
                    <v-col v-if="selected.includes('Other')" cols="12">
                        <v-text-field v-model="otherReason" variant="outlined" hide-details="auto" label="Enter other reason" :disabled="loading" />
                    </v-col>
                </v-row>
                <v-row>
                    <v-col cols="12">
                        <v-text-field
                            :model-value="userEmail" label="Account Email" variant="solo-filled" flat readonly
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
                        <v-btn color="warning" variant="flat" block :loading="loading" :disabled="!valid || loading" @click="onButtonClick">Deactivate Account</v-btn>
                    </v-col>
                </v-row>
            </v-card-actions>
        </v-card>
    </v-dialog>

    <v-snackbar v-model="snackbar" :timeout="7000" color="success">
        The account was deactivated successfully.
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
import { ref, computed } from 'vue';
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
import { useNotificationsStore } from '@/store/notifications';

const props = defineProps<{
    userEmail?: string;
}>();

const emit = defineEmits<{
    'account-deactivated': [];
}>();

const notify = useNotificationsStore();

const selected = ref<string[]>([]);
const otherReason = ref<string>('');
const snackbar = ref<boolean>(false);
const errorSnackbar = ref<boolean>(false);
const errorMessage = ref<string>('');
const dialog = ref<boolean>(false);
const valid = ref<boolean>(false);
const loading = ref<boolean>(false);

const userEmail = computed(() => props.userEmail || '');

async function onButtonClick() {
    if (!valid.value || !userEmail.value || loading.value) return;
    
    try {
        loading.value = true;
        
        await adminApi.deactivateUserAccount(userEmail.value);
        
        snackbar.value = true;
        dialog.value = false;
        notify.notifySuccess('Account deactivated successfully');
        
        // Reset form
        selected.value = [];
        otherReason.value = '';
        
        // Emit event to refresh parent component
        emit('account-deactivated');
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to deactivate account';
        errorSnackbar.value = true;
        notify.notifyError(errorMessage.value);
    } finally {
        loading.value = false;
    }
}
</script>