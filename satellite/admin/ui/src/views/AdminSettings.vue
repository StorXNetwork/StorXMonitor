// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

<template>
    <v-container>
        <v-row>
            <v-col cols="6">
                <PageTitleComponent title="Admin Settings" />
                <PageSubtitleComponent subtitle="View and change your account settings." />
            </v-col>
        </v-row>

        <!-- Loading state -->
        <v-row v-if="loading">
            <v-col cols="12" class="text-center py-8">
                <v-progress-circular indeterminate color="primary" size="64" />
                <p class="mt-4">Loading admin settings...</p>
            </v-col>
        </v-row>

        <!-- Error state -->
        <v-row v-else-if="error">
            <v-col cols="12">
                <v-alert type="error" variant="tonal">
                    <v-alert-title>Error loading settings</v-alert-title>
                    {{ error }}
                </v-alert>
            </v-col>
        </v-row>

        <!-- Settings cards -->
        <v-row v-else class="justify-center">
            <v-col cols="12" sm="6" md="4" lg="3" style="max-width: 320px;">
                <v-card title="Account" variant="flat" :border="true" rounded="lg" class="h-100">
                    <v-card-text class="pa-4">
                        <div class="mb-3">
                            <p class="text-caption text-medium-emphasis mb-1">Email</p>
                            <v-chip color="primary" variant="tonal" size="small" class="font-weight-medium">
                                {{ adminInfo?.email || 'N/A' }}
                            </v-chip>
                        </div>
                        <v-divider class="my-3" />
                        <v-btn 
                            variant="outlined" 
                            size="small" 
                            color="default"
                            block
                            @click="showEditAccountDialog = true"
                        >
                            <v-icon start icon="mdi-pencil" size="16"></v-icon>
                            Edit
                        </v-btn>
                    </v-card-text>
                </v-card>
            </v-col>

            <v-col cols="12" sm="6" md="4" lg="3" style="max-width: 320px;">
                <v-card title="Role" variant="flat" :border="true" rounded="lg" class="h-100">
                    <v-card-text class="pa-4">
                        <div class="mb-3">
                            <p class="text-caption text-medium-emphasis mb-1">Account Type</p>
                            <v-chip 
                                :color="getRoleColor(adminInfo?.role || 'admin')" 
                                variant="tonal" 
                                size="small"
                                class="font-weight-medium"
                            >
                                {{ formatRole(adminInfo?.role || 'admin') }}
                            </v-chip>
                        </div>
                        <v-divider class="my-3" />
                        <v-btn 
                            variant="outlined" 
                            size="small" 
                            color="default"
                            block
                            disabled
                        >
                            <v-icon start icon="mdi-lock" size="16"></v-icon>
                            Cannot Edit
                        </v-btn>
                        <p class="text-caption text-medium-emphasis mt-2 mb-0">
                            Requires super admin privileges
                        </p>
                    </v-card-text>
                </v-card>
            </v-col>

            <v-col cols="12" sm="6" md="4" lg="3" style="max-width: 320px;">
                <v-card title="Security" variant="flat" :border="true" rounded="lg" class="h-100">
                    <v-card-text class="pa-4">
                        <div class="mb-3">
                            <p class="text-caption text-medium-emphasis mb-1">Two-factor Authentication</p>
                            <v-chip color="default" variant="tonal" size="small" class="font-weight-medium">
                                Not Available
                            </v-chip>
                        </div>
                        <v-divider class="my-3" />
                        <v-btn 
                            size="small" 
                            color="primary"
                            disabled
                            variant="outlined"
                            block
                        >
                            <v-icon start icon="mdi-shield-lock" size="16"></v-icon>
                            Enable 2FA
                        </v-btn>
                        <p class="text-caption text-medium-emphasis mt-2 mb-0">
                            Not yet implemented
                        </p>
                    </v-card-text>
                </v-card>
            </v-col>
        </v-row>

        <!-- Edit Account Dialog -->
        <v-dialog v-model="showEditAccountDialog" max-width="500" persistent>
            <v-card rounded="lg">
                <v-card-title class="d-flex align-center justify-space-between">
                    <span>Edit Account</span>
                    <v-btn icon="mdi-close" variant="text" size="small" @click="showEditAccountDialog = false"></v-btn>
                </v-card-title>
                <v-divider></v-divider>
                <v-card-text class="pt-4">
                    <v-text-field
                        v-model="editAccountForm.email"
                        label="Email"
                        type="email"
                        prepend-inner-icon="mdi-email-outline"
                        variant="outlined"
                        density="comfortable"
                        :rules="[rules.email, rules.required]"
                        class="mb-3"
                    />
                    <v-text-field
                        v-model="editAccountForm.password"
                        label="New Password (leave empty to keep current)"
                        type="password"
                        prepend-inner-icon="mdi-lock-outline"
                        variant="outlined"
                        density="comfortable"
                        :rules="[rules.passwordMin]"
                        hint="Password must be at least 8 characters"
                        persistent-hint
                    />
                </v-card-text>
                <v-divider></v-divider>
                <v-card-actions class="pa-4">
                    <v-spacer></v-spacer>
                    <v-btn variant="text" @click="showEditAccountDialog = false">Cancel</v-btn>
                    <v-btn 
                        color="primary" 
                        variant="flat"
                        :loading="updating"
                        @click="updateAccount"
                    >
                        Save Changes
                    </v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>

    </v-container>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import {
    VContainer,
    VRow,
    VCol,
    VCard,
    VCardText,
    VChip,
    VDivider,
    VBtn,
    VIcon,
    VProgressCircular,
    VAlert,
    VAlertTitle,
    VDialog,
    VCardTitle,
    VCardActions,
    VTextField,
    VSelect,
    VSpacer,
} from 'vuetify/components';

import { useNotificationsStore } from '@/store/notifications';
import { adminApi } from '@/api/adminApi';
import PageTitleComponent from '@/components/PageTitleComponent.vue';
import PageSubtitleComponent from '@/components/PageSubtitleComponent.vue';

const notify = useNotificationsStore();

// Admin info state
const loading = ref(true);
const error = ref<string | null>(null);
const adminInfo = ref<{
    id: string;
    email: string;
    role: string;
    status: number;
    createdAt: string;
    updatedAt: string;
} | null>(null);

// Dialog states
const showEditAccountDialog = ref(false);
const updating = ref(false);

// Edit forms
const editAccountForm = ref({
    email: '',
    password: '',
});

// Validation rules
const rules = {
    required: (value: string) => !!value || 'This field is required',
    email: (value: string) => {
        const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return pattern.test(value) || 'Invalid email address';
    },
    passwordMin: (value: string) => {
        if (!value) return true; // Optional field
        return value.length >= 8 || 'Password must be at least 8 characters';
    },
};

// Load admin info
const loadAdminInfo = async () => {
    try {
        loading.value = true;
        error.value = null;
        adminInfo.value = await adminApi.getCurrentAdmin();
    } catch (err) {
        console.error('Failed to load admin info:', err);
        error.value = err instanceof Error ? err.message : 'Unknown error occurred';
    } finally {
        loading.value = false;
    }
};

// Update account
const updateAccount = async () => {
    if (!adminInfo.value) return;

    try {
        updating.value = true;
        
        const updateData: { email?: string; password?: string } = {};
        if (editAccountForm.value.email !== adminInfo.value.email) {
            updateData.email = editAccountForm.value.email;
        }
        if (editAccountForm.value.password) {
            updateData.password = editAccountForm.value.password;
        }

        if (Object.keys(updateData).length === 0) {
            notify.notifyInfo('No changes to save');
            showEditAccountDialog.value = false;
            return;
        }

        adminInfo.value = await adminApi.updateCurrentAdmin(updateData);
        notify.notifySuccess('Account updated successfully');
        showEditAccountDialog.value = false;
        editAccountForm.value.password = ''; // Clear password field
    } catch (err) {
        console.error('Failed to update account:', err);
        notify.notifyError(err instanceof Error ? err.message : 'Failed to update account');
    } finally {
        updating.value = false;
    }
};

// Format role for display
const formatRole = (role: string): string => {
    const roleMap: Record<string, string> = {
        'admin': 'Admin',
        'super_admin': 'Super Admin',
        'operator': 'Operator',
        'viewer': 'Viewer',
    };
    return roleMap[role] || role.charAt(0).toUpperCase() + role.slice(1);
};

// Get role color
const getRoleColor = (role: string): string => {
    if (role === 'super_admin') return 'error';
    if (role === 'admin') return 'primary';
    if (role === 'operator') return 'success';
    return 'default';
};

// Watch for dialog open to populate forms
watch(showEditAccountDialog, (isOpen) => {
    if (isOpen && adminInfo.value) {
        editAccountForm.value.email = adminInfo.value.email;
        editAccountForm.value.password = '';
    }
});

// Load data on mount
onMounted(() => {
    loadAdminInfo();
});
</script>
