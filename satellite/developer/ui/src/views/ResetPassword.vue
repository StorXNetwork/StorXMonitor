<template>
    <div class="reset-password-page">
        <!-- Left Panel: Reset Password Form -->
        <div class="reset-left-panel">
            <div class="reset-content">
                <!-- Logo Section -->
                <div class="logo-section">
                    <img src="@/assets/SidebarLogo.svg" alt="StorX Logo" class="logo-img" />
                </div>

                <!-- Title -->
                <h2 class="reset-title">Reset Your Password</h2>

                <!-- Subtitle -->
                <p class="reset-subtitle">
                    {{ isAuthenticated ? `Hello ${account?.email}, please set a new password.` : 'Please enter your new password.' }}
                </p>

                <!-- Error Message -->
                <div v-if="errorMessage" class="error-alert">
                    {{ errorMessage }}
                    <button class="close-btn" @click="errorMessage = ''">×</button>
                </div>

                <!-- Success Message -->
                <div v-if="successMessage" class="success-alert">
                    {{ successMessage }}
                </div>

                <!-- Reset Password Form -->
                <v-form ref="resetForm" @submit.prevent="handleResetPassword" class="reset-form">
                    <v-text-field
                        v-model="newPassword"
                        label="New Password"
                        type="password"
                        variant="outlined"
                        :rules="newPasswordRules"
                        required
                        class="mb-3"
                        density="comfortable"
                    />

                    <v-text-field
                        v-model="confirmPassword"
                        label="Confirm Password"
                        type="password"
                        variant="outlined"
                        :rules="confirmPasswordRules"
                        required
                        class="mb-4"
                        density="comfortable"
                    />

                    <v-btn
                        type="submit"
                        color="primary"
                        size="large"
                        block
                        :loading="loading"
                        class="reset-btn"
                    >
                        Reset Password
                    </v-btn>
                </v-form>

                <!-- Legal Links -->
                <p class="legal-text">
                    By resetting your password, I agree to StorX 
                    <a href="#" class="legal-link">Privacy Policy</a> and 
                    <a href="#" class="legal-link">Terms of Service</a>
                </p>
            </div>
        </div>

        <!-- Right Panel: Welcome Section -->
        <div class="reset-right-panel">
            <img src="@/assets/image.svg" alt="Background" class="background-image" />
            <div class="welcome-content">
                <h2 class="welcome-title">Welcome to StorX Developer Console</h2>
                <ul class="features-list">
                    <li class="feature-item">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16.7071 5.29289C17.0976 5.68342 17.0976 6.31658 16.7071 6.70711L8.70711 14.7071C8.31658 15.0976 7.68342 15.0976 7.29289 14.7071L3.29289 10.7071C2.90237 10.3166 2.90237 9.68342 3.29289 9.29289C3.68342 8.90237 4.31658 8.90237 4.70711 9.29289L8 12.5858L15.2929 5.29289C15.6834 4.90237 16.3166 4.90237 16.7071 5.29289Z" fill="white"/>
                        </svg>
                        <span>Access developer tools and APIs</span>
                    </li>
                    <li class="feature-item">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16.7071 5.29289C17.0976 5.68342 17.0976 6.31658 16.7071 6.70711L8.70711 14.7071C8.31658 15.0976 7.68342 15.0976 7.29289 14.7071L3.29289 10.7071C2.90237 10.3166 2.90237 9.68342 3.29289 9.29289C3.68342 8.90237 4.31658 8.90237 4.70711 9.29289L8 12.5858L15.2929 5.29289C15.6834 4.90237 16.3166 4.90237 16.7071 5.29289Z" fill="white"/>
                        </svg>
                        <span>Manage API keys and credentials</span>
                    </li>
                    <li class="feature-item">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16.7071 5.29289C17.0976 5.68342 17.0976 6.31658 16.7071 6.70711L8.70711 14.7071C8.31658 15.0976 7.68342 15.0976 7.29289 14.7071L3.29289 10.7071C2.90237 10.3166 2.90237 9.68342 3.29289 9.29289C3.68342 8.90237 4.31658 8.90237 4.70711 9.29289L8 12.5858L15.2929 5.29289C15.6834 4.90237 16.3166 4.90237 16.7071 5.29289Z" fill="white"/>
                        </svg>
                        <span>Monitor usage and analytics</span>
                    </li>
                    <li class="feature-item">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16.7071 5.29289C17.0976 5.68342 17.0976 6.31658 16.7071 6.70711L8.70711 14.7071C8.31658 15.0976 7.68342 15.0976 7.29289 14.7071L3.29289 10.7071C2.90237 10.3166 2.90237 9.68342 3.29289 9.29289C3.68342 8.90237 4.31658 8.90237 4.70711 9.29289L8 12.5858L15.2929 5.29289C15.6834 4.90237 16.3166 4.90237 16.7071 5.29289Z" fill="white"/>
                        </svg>
                        <span>Build with decentralized storage</span>
                    </li>
                    <li class="feature-item">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16.7071 5.29289C17.0976 5.68342 17.0976 6.31658 16.7071 6.70711L8.70711 14.7071C8.31658 15.0976 7.68342 15.0976 7.29289 14.7071L3.29289 10.7071C2.90237 10.3166 2.90237 9.68342 3.29289 9.29289C3.68342 8.90237 4.31658 8.90237 4.70711 9.29289L8 12.5858L15.2929 5.29289C15.6834 4.90237 16.3166 4.90237 16.7071 5.29289Z" fill="white"/>
                        </svg>
                        <span>Secure developer authentication</span>
                    </li>
                    <li class="feature-item">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16.7071 5.29289C17.0976 5.68342 17.0976 6.31658 16.7071 6.70711L8.70711 14.7071C8.31658 15.0976 7.68342 15.0976 7.29289 14.7071L3.29289 10.7071C2.90237 10.3166 2.90237 9.68342 3.29289 9.29289C3.68342 8.90237 4.31658 8.90237 4.70711 9.29289L8 12.5858L15.2929 5.29289C15.6834 4.90237 16.3166 4.90237 16.7071 5.29289Z" fill="white"/>
                        </svg>
                        <span>24/7 support and documentation</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useAuthStore } from '@/store/modules/auth';
import { developerApi } from '@/api/developerApi';
import { validatePassword, validatePasswordMatch } from '@/utils/validators';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

const newPassword = ref('');
const confirmPassword = ref('');
const loading = ref(false);
const errorMessage = ref('');
const successMessage = ref('');
const resetForm = ref();

const isAuthenticated = computed(() => authStore.isAuthenticated);
const account = computed(() => authStore.account);

const newPasswordRules = [
    (v: string) => !!v || 'Password is required',
    (v: string) => {
        const validation = validatePassword(v);
        return validation.valid || validation.message || '';
    },
];

const confirmPasswordRules = [
    (v: string) => !!v || 'Please confirm your password',
    (v: string) => validatePasswordMatch(newPassword.value, v) || 'Passwords do not match',
];

onMounted(async () => {
    // Check authentication status
    if (!authStore.isAuthenticated) {
        try {
            await authStore.checkAuth();
        } catch {
            // Not authenticated
        }
    }

    // If not authenticated, check for token in URL
    if (!authStore.isAuthenticated) {
        const token = route.query.token as string;
        if (!token) {
            // No token and not authenticated, redirect to login
            router.push({ name: 'Login' });
            return;
        }
    } else {
        // Authenticated, check if status requires password reset
        if (!authStore.isResetPassStatus) {
            // Status is not ResetPass, redirect to dashboard
            router.push({ name: 'Dashboard' });
            return;
        }
    }
});

async function handleResetPassword() {
    const { valid } = await resetForm.value.validate();
    if (!valid) return;

    loading.value = true;
    errorMessage.value = '';
    successMessage.value = '';

    try {
        const token = route.query.token as string;

        if (token && !authStore.isAuthenticated) {
            // Reset using token (from email link)
            await developerApi.resetPasswordWithToken(token, newPassword.value);
        } else if (authStore.isAuthenticated) {
            // Reset after login (status is ResetPass)
            await authStore.resetPasswordAfterLogin(newPassword.value);
        } else {
            throw new Error('Invalid reset password request');
        }

        successMessage.value = 'Password reset successfully! Please log in with your new password.';

        // Logout and redirect to login after 2 seconds
        setTimeout(async () => {
            await authStore.logout();
            router.push({ 
                name: 'Login',
                query: { 
                    message: 'Password reset successful. Please log in with your new password.' 
                }
            });
        }, 2000);
    } catch (error) {
        errorMessage.value = error instanceof Error ? error.message : 'Password reset failed. Please try again.';
    } finally {
        loading.value = false;
    }
}
</script>

<style scoped>
.reset-password-page {
    display: flex;
    min-height: 100vh;
    width: 100%;
    margin: 0;
    padding: 0;
    overflow: hidden;
}

/* Left Panel: Reset Password Form */
.reset-left-panel {
    flex: 0 0 60%;
    background-color: #ffffff;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px;
    overflow-y: auto;
}

.reset-content {
    width: 100%;
    max-width: 420px;
}

.logo-section {
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 48px;
}

.logo-img {
    height: 48px;
    width: auto;
}

.reset-title {
    font-size: 32px;
    font-weight: 700;
    color: #000000;
    margin: 0 0 16px 0;
    line-height: 1.2;
}

.reset-subtitle {
    font-size: 16px;
    color: #666666;
    margin: 0 0 32px 0;
    line-height: 1.5;
}

.success-alert {
    background-color: #e8f5e9;
    color: #2e7d32;
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 24px;
    font-size: 14px;
    line-height: 1.5;
}

.error-alert {
    background-color: #ffebee;
    color: #c62828;
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 24px;
    font-size: 14px;
    line-height: 1.5;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.close-btn {
    background: none;
    border: none;
    color: #c62828;
    font-size: 24px;
    cursor: pointer;
    padding: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
}

.close-btn:hover {
    opacity: 0.7;
}

.reset-form {
    margin-bottom: 24px;
}

.reset-btn {
    text-transform: none;
    font-weight: 500;
    letter-spacing: 0.5px;
    height: 48px;
}

.legal-text {
    font-size: 14px;
    color: #666666;
    text-align: center;
    margin: 0;
    line-height: 1.5;
}

.legal-link {
    color: #1976d2;
    text-decoration: none;
}

.legal-link:hover {
    text-decoration: underline;
}

/* Right Panel: Welcome Section */
.reset-right-panel {
    flex: 0 0 40%;
    background-color: #1976d2;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 60px 40px;
    overflow: hidden;
}

.background-image {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    opacity: 0.15;
    z-index: 0;
}

.welcome-content {
    position: relative;
    z-index: 1;
    width: 100%;
    max-width: 500px;
}

.welcome-title {
    font-size: 36px;
    font-weight: 700;
    color: #ffffff;
    margin: 0 0 40px 0;
    line-height: 1.3;
}

.features-list {
    list-style: none;
    padding: 0;
    margin: 0;
}

.feature-item {
    display: flex;
    align-items: flex-start;
    margin-bottom: 20px;
    color: #ffffff;
    font-size: 16px;
    line-height: 1.6;
}

.feature-item svg {
    flex-shrink: 0;
    margin-right: 12px;
    margin-top: 2px;
}

.feature-item span {
    flex: 1;
}

/* Responsive Design */
@media (max-width: 960px) {
    .reset-password-page {
        flex-direction: column;
    }

    .reset-left-panel {
        flex: 1;
        min-height: 50vh;
    }

    .reset-right-panel {
        flex: 1;
        min-height: 50vh;
    }

    .welcome-title {
        font-size: 28px;
    }
}

@media (max-width: 600px) {
    .reset-left-panel,
    .reset-right-panel {
        padding: 24px;
    }

    .reset-title {
        font-size: 28px;
    }

    .welcome-title {
        font-size: 24px;
        margin-bottom: 24px;
    }

    .feature-item {
        font-size: 14px;
        margin-bottom: 16px;
    }
}
</style>

