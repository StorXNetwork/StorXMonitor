// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-dialog v-model="dialog" activator="parent" width="auto" transition="fade-transition">
        <v-card rounded="xlg">
            <v-sheet>
                <v-card-item class="pl-7 py-4">
                    <template #prepend>
                        <v-card-title class="font-weight-bold">
                            Create New Account
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
                    <v-col>
                        <p class="pb-2">Create a new account in the US1 satellite.</p>
                    </v-col>
                </v-row>
                <v-row>
                    <v-col cols="12">
                        <v-text-field
                            v-model="fullName" variant="outlined" label="Full name" required
                            hide-details="auto" autofocus :disabled="loading"
                        />
                    </v-col>
                </v-row>

                <v-row>
                    <v-col cols="12">
                        <v-text-field
                            v-model="email" variant="outlined" :rules="emailRules" label="E-mail"
                            hint="A temporary password will be generated and sent by email." hide-details="auto" required
                            :disabled="loading"
                        />
                    </v-col>
                </v-row>
            </v-form>

            <v-divider />

            <v-card-actions class="pa-7">
                <v-row>
                    <v-col>
                        <v-btn size="large" variant="outlined" color="default" block @click="dialog = false">Cancel</v-btn>
                    </v-col>
                    <v-col>
                        <v-btn size="large" color="primary" variant="flat" block :loading="loading" :disabled="!valid || loading" @click="onButtonClick">Create Account</v-btn>
                    </v-col>
                </v-row>
            </v-card-actions>
        </v-card>
    </v-dialog>

    <v-snackbar v-model="snackbar" :timeout="7000" color="success">
        Account created successfully.
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
import { ref } from 'vue';
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
import { useNotificationsStore } from '@/store/notifications';

const snackbar = ref<boolean>(false);
const errorSnackbar = ref<boolean>(false);
const errorMessage = ref<string>('');
const dialog = ref<boolean>(false);
const valid = ref<boolean>(false);
const loading = ref<boolean>(false);
const email = ref<string>('');
const fullName = ref<string>('');

const notify = useNotificationsStore();

const emit = defineEmits<{
    'account-created': [];
}>();

const emailRules = [
    value => {
        if (value) return true;
        return 'E-mail is required.';
    },
    value => {
        if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return true;
        return 'E-mail must be valid.';
    },
];

async function onButtonClick() {
    if (!valid.value || loading.value) return;
    
    try {
        loading.value = true;
        
        // Generate a temporary password (backend will handle this, but we need to provide one)
        // For now, we'll generate a random password - backend can override this
        const tempPassword = Math.random().toString(36).slice(-12) + 'A1!';
        
        await adminApi.createUser({
            email: email.value,
            fullName: fullName.value,
            password: tempPassword,
        });
        
        snackbar.value = true;
        dialog.value = false;
        notify.notifySuccess('Account created successfully');
        
        // Reset form
        email.value = '';
        fullName.value = '';
        
        // Emit event to refresh parent component
        emit('account-created');
    } catch (error: any) {
        errorMessage.value = error.message || 'Failed to create account';
        errorSnackbar.value = true;
        notify.notifyError(errorMessage.value);
    } finally {
        loading.value = false;
    }
}
</script>