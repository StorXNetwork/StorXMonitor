<template>
    <div>
        <v-container>
            <v-row>
                <v-col cols="12">
                    <h1 class="text-h4 mb-4">Account Settings</h1>
                </v-col>
            </v-row>

            <v-row>
                <v-col cols="12" md="8">
                    <v-card>
                        <v-card-title>Profile Information</v-card-title>
                        <v-card-text>
                            <v-form ref="profileForm" @submit.prevent="updateProfile">
                                <v-text-field
                                    v-model="profile.fullName"
                                    label="Full Name"
                                    variant="outlined"
                                    required
                                    class="mb-4"
                                />

                                <v-text-field
                                    :model-value="account?.email"
                                    label="Email"
                                    variant="outlined"
                                    readonly
                                    class="mb-4"
                                />

                                <v-btn type="submit" color="primary" :loading="updating">
                                    Save Changes
                                </v-btn>
                            </v-form>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>

            <v-row>
                <v-col cols="12" md="8">
                    <v-card>
                        <v-card-title>Change Password</v-card-title>
                        <v-card-text>
                            <v-alert
                                v-if="passwordMessage"
                                :type="passwordMessageType"
                                variant="tonal"
                                class="mb-4"
                                closable
                                @click:close="passwordMessage = ''"
                            >
                                {{ passwordMessage }}
                            </v-alert>

                            <v-form ref="passwordForm" @submit.prevent="changePassword">
                                <v-text-field
                                    v-model="passwordData.currentPassword"
                                    label="Current Password"
                                    type="password"
                                    variant="outlined"
                                    required
                                    class="mb-2"
                                />

                                <v-text-field
                                    v-model="passwordData.newPassword"
                                    label="New Password"
                                    type="password"
                                    variant="outlined"
                                    required
                                    class="mb-2"
                                />

                                <v-text-field
                                    v-model="passwordData.confirmPassword"
                                    label="Confirm New Password"
                                    type="password"
                                    variant="outlined"
                                    required
                                    class="mb-4"
                                />

                                <v-btn type="submit" color="primary" :loading="changingPassword">
                                    Change Password
                                </v-btn>
                            </v-form>
                        </v-card-text>
                    </v-card>
                </v-col>
            </v-row>
        </v-container>
    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useAuthStore } from '@/store/modules/auth';
import { developerApi } from '@/api/developerApi';
import { validatePassword, validatePasswordMatch } from '@/utils/validators';

const authStore = useAuthStore();

const account = computed(() => authStore.account);
const profile = ref({ fullName: '' });
const passwordData = ref({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
});
const updating = ref(false);
const changingPassword = ref(false);
const passwordMessage = ref('');
const passwordMessageType = ref<'success' | 'error'>('success');
const profileForm = ref();
const passwordForm = ref();

onMounted(() => {
    if (account.value) {
        profile.value.fullName = account.value.fullName;
    }
});

async function updateProfile() {
    const { valid } = await profileForm.value.validate();
    if (!valid) return;

    updating.value = true;
    try {
        await authStore.updateAccount(profile.value.fullName);
    } catch (error) {
        console.error('Failed to update profile:', error);
    } finally {
        updating.value = false;
    }
}

async function changePassword() {
    const { valid } = await passwordForm.value.validate();
    if (!valid) return;

    // Validate new password
    const passwordValidation = validatePassword(passwordData.value.newPassword);
    if (!passwordValidation.valid) {
        passwordMessage.value = passwordValidation.message || 'Invalid password';
        passwordMessageType.value = 'error';
        return;
    }

    // Validate passwords match
    if (!validatePasswordMatch(passwordData.value.newPassword, passwordData.value.confirmPassword)) {
        passwordMessage.value = 'Passwords do not match';
        passwordMessageType.value = 'error';
        return;
    }

    changingPassword.value = true;
    passwordMessage.value = '';

    try {
        await developerApi.changePassword(
            passwordData.value.currentPassword,
            passwordData.value.newPassword
        );
        passwordMessage.value = 'Password changed successfully';
        passwordMessageType.value = 'success';
        passwordData.value = {
            currentPassword: '',
            newPassword: '',
            confirmPassword: '',
        };
        passwordForm.value.reset();
    } catch (error) {
        passwordMessage.value = error instanceof Error ? error.message : 'Failed to change password';
        passwordMessageType.value = 'error';
    } finally {
        changingPassword.value = false;
    }
}
</script>

