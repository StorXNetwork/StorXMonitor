// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-container fluid class="fill-height">
        <v-row align="center" justify="center">
            <v-col cols="12" sm="8" md="6" lg="4">
                <v-card variant="flat" class="pa-6" rounded="xlg" border>
                    <v-card-title class="text-h4 mb-2">Storx Admin</v-card-title>
                    <v-card-subtitle class="mb-4">Enter your admin token to continue</v-card-subtitle>
                    
                    <v-form v-model="isFormValid" @submit.prevent="login">
                        <v-text-field
                            v-model="token"
                            label="Admin Token"
                            type="password"
                            variant="outlined"
                            class="mb-4"
                            :disabled="isLoading"
                            :rules="tokenRules"
                            :error-messages="errorMessage"
                            autofocus
                            autocomplete="off"
                        />
                        
                        <v-btn
                            block
                            size="large"
                            type="submit"
                            :loading="isLoading"
                            :disabled="!isFormValid || isLoading"
                        >
                            Sign In
                        </v-btn>
                    </v-form>
                </v-card>
            </v-col>
        </v-row>
    </v-container>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useNotificationsStore } from '@/store/notifications';
import { AdminHttpClient } from '@/utils/adminHttpClient';

const router = useRouter();
const notify = useNotificationsStore();

const token = ref<string>('');
const isLoading = ref<boolean>(false);
const isFormValid = ref<boolean>(false);
const errorMessage = ref<string>('');

const tokenRules = [
    (v: string) => !!v || 'Token is required',
    (v: string) => v.length >= 3 || 'Token must be at least 3 characters',
];

async function login(): Promise<void> {
    if (!isFormValid.value || isLoading.value) return;
    
    isLoading.value = true;
    errorMessage.value = '';

    try {
        const httpClient = new AdminHttpClient();
        const response = await httpClient.post('/api/auth/login', JSON.stringify({ token: token.value }));
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Invalid credentials' }));
            throw new Error(errorData.error || 'Login failed');
        }

        const data = await response.json();
        
        // Store token in localStorage (JWT token from backend)
        localStorage.setItem('adminToken', data.token);
        
        // Navigate to dashboard
        router.push('/dashboard');
        notify.notifySuccess('Logged in successfully');
    } catch (error: any) {
        errorMessage.value = error.message || 'Login failed. Please check your token.';
        notify.notifyError(errorMessage.value);
    } finally {
        isLoading.value = false;
    }
}
</script>
