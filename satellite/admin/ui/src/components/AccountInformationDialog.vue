// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-dialog v-model="dialog" activator="parent" width="auto" transition="fade-transition">
        <v-card rounded="xlg">
            <v-sheet>
                <v-card-item class="pl-7 py-4">
                    <template #prepend>
                        <v-card-title class="font-weight-bold">
                            Account Information
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
                        <p>Edit the name and email.</p>
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12">
                        <v-text-field
                            v-model="fullName" label="Account Name" variant="outlined"
                            hide-details="auto" :disabled="loading"
                        />
                    </v-col>

                    <v-col cols="12">
                        <v-text-field 
                            v-model="email" label="Account Email" variant="solo-filled" 
                            flat readonly hide-details="auto" 
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
        Successfully saved the account information.
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

const fullName = ref<string>('');
const email = ref<string>('');
const projectLimit = ref<number>(0);
const projectStorageLimit = ref<number>(0);
const projectBandwidthLimit = ref<number>(0);
const defaultPlacement = ref<number>(0);

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
        fullName.value = userInfo.user.fullName;
        email.value = userInfo.user.email;
        projectLimit.value = userInfo.user.projectLimit;
        projectStorageLimit.value = 0; // This might need to come from limits API
        projectBandwidthLimit.value = 0; // This might need to come from limits API
        defaultPlacement.value = userInfo.user.placement;
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to load user data';
        errorSnackbar.value = true;
    } finally {
        loading.value = false;
    }
}

const emit = defineEmits<{
    'account-updated': [];
}>();

async function onButtonClick() {
    if (!valid.value || !userEmail.value || loading.value) return;
    
    try {
        loading.value = true;
        await adminApi.updateUser(userEmail.value, {
            fullName: fullName.value,
            projectLimit: projectLimit.value,
            projectStorageLimit: projectStorageLimit.value,
            projectBandwidthLimit: projectBandwidthLimit.value,
            defaultPlacement: defaultPlacement.value,
        });
        snackbar.value = true;
        dialog.value = false;
        
        // Emit event to refresh parent component
        emit('account-updated');
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to update account information';
        errorSnackbar.value = true;
    } finally {
        loading.value = false;
    }
}
</script>