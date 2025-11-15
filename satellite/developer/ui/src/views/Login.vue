<template>
    <div class="login-page">
        <!-- Left Panel: Login Form -->
        <div class="login-left-panel">
            <div class="login-content">
                <!-- Logo Section -->
                <div class="logo-section">
                    <img src="@/assets/SidebarLogo.svg" alt="StorX Logo" class="logo-img" />
                </div>

                <!-- Title -->
                <h2 class="sign-in-title">Sign in</h2>

                <!-- Token Info Alert -->
                <div v-if="tokenInfo" class="info-alert">
                    <strong>Hello {{ tokenInfo.fullName }}!</strong><br>
                    Please log in with your temporary credentials from the email.
                </div>

                <!-- Success Message -->
                <div v-if="successMessage" class="success-alert">
                    {{ successMessage }}
                </div>

                <!-- Error Message -->
                <div v-if="errorMessage" class="error-alert">
                    {{ errorMessage }}
                    <button class="close-btn" @click="errorMessage = ''">×</button>
                </div>

                <!-- Login Form -->
                <v-form ref="loginForm" @submit.prevent="handleLogin" class="login-form">
                    <v-text-field
                        v-model="email"
                        label="Email"
                        type="email"
                        variant="outlined"
                        :readonly="!!tokenInfo"
                        :rules="emailRules"
                        required
                        class="mb-3"
                        density="comfortable"
                    />

                    <v-text-field
                        v-model="password"
                        label="Password"
                        type="password"
                        variant="outlined"
                        :rules="passwordRules"
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
                        class="sign-in-btn"
                    >
                        Sign In
                    </v-btn>
                </v-form>

                <!-- Legal Links -->
                <p class="legal-text">
                    By logging in, I agree to StorX 
                    <a href="#" class="legal-link">Privacy Policy</a> and 
                    <a href="#" class="legal-link">Terms of Service</a>
                </p>
            </div>
        </div>

        <!-- Right Panel: Welcome Section -->
        <div class="login-right-panel">
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
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useAuthStore } from '@/store/modules/auth';
import { developerApi, type TokenVerificationResponse } from '@/api/developerApi';
import { validateEmail } from '@/utils/validators';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();

const email = ref('');
const password = ref('');
const loading = ref(false);
const errorMessage = ref('');
const successMessage = ref('');
const tokenInfo = ref<TokenVerificationResponse | null>(null);
const loginForm = ref();

const emailRules = [
    (v: string) => !!v || 'Email is required',
    (v: string) => validateEmail(v) || 'Email must be valid',
];

const passwordRules = [
    (v: string) => !!v || 'Password is required',
];

onMounted(async () => {
    // Check for success message from password reset
    const message = route.query.message as string;
    if (message) {
        successMessage.value = message;
        // Clear query param
        router.replace({ name: 'Login' });
    }

    // Check if already authenticated
    if (authStore.isAuthenticated) {
        // If status is ResetPass, redirect to reset password
        if (authStore.isResetPassStatus) {
            router.push({ name: 'ResetPassword' });
        } else {
            // Otherwise redirect to dashboard
            router.push({ name: 'Dashboard' });
        }
        return;
    }

    // Check if token is in URL (from email link)
    const token = route.query.token as string;
    if (token) {
        try {
            tokenInfo.value = await developerApi.verifyResetToken(token);
            email.value = tokenInfo.value.email;
        } catch (error) {
            errorMessage.value = error instanceof Error ? error.message : 'Invalid or expired activation link';
        }
    }
});

async function handleLogin() {
    const { valid } = await loginForm.value.validate();
    if (!valid) return;

    loading.value = true;
    errorMessage.value = '';

    try {
        await authStore.login(email.value, password.value);

        // Check if account status requires password reset (status = 6 = ResetPass)
        if (authStore.isResetPassStatus) {
            // Redirect to reset password page - user must set new password
            router.push({ name: 'ResetPassword' });
        } else {
            // Status is Active, redirect to dashboard
            const redirect = route.query.redirect as string;
            router.push(redirect || { name: 'Dashboard' });
        }
    } catch (error) {
        errorMessage.value = error instanceof Error ? error.message : 'Login failed. Please check your credentials.';
    } finally {
        loading.value = false;
    }
}
</script>

<style scoped>
.login-page {
    display: flex;
    min-height: 100vh;
    width: 100%;
    margin: 0;
    padding: 0;
    overflow: hidden;
}

/* Left Panel: Login Form */
.login-left-panel {
    flex: 0 0 60%;
    background-color: #ffffff;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px;
    overflow-y: auto;
}

.login-content {
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

.sign-in-title {
    font-size: 32px;
    font-weight: 700;
    color: #000000;
    margin: 0 0 32px 0;
    line-height: 1.2;
}

.info-alert {
    background-color: #e3f2fd;
    color: #1976d2;
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 24px;
    font-size: 14px;
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

.login-form {
    margin-bottom: 24px;
}

.sign-in-btn {
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
.login-right-panel {
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
    .login-page {
        flex-direction: column;
    }

    .login-left-panel {
        flex: 1;
        min-height: 50vh;
    }

    .login-right-panel {
        flex: 1;
        min-height: 50vh;
    }

    .welcome-title {
        font-size: 28px;
    }
}

@media (max-width: 600px) {
    .login-left-panel,
    .login-right-panel {
        padding: 24px;
    }

    .sign-in-title {
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

