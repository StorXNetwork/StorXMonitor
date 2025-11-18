<template>
    <div>
        <v-container>
            <v-row>
                <v-col cols="12">
                    <h1 class="text-h4 mb-2">Welcome, {{ account?.fullName }}!</h1>
                    <p class="text-body-1 text-medium-emphasis">Email: {{ account?.email }}</p>
                    <p v-if="account?.companyName" class="text-body-1 text-medium-emphasis">
                        Company: {{ account.companyName }}
                    </p>
                </v-col>
            </v-row>

            <v-row>
                <v-col cols="12" md="4">
                    <v-card class="dashboard-card" elevation="2">
                        <v-card-title>
                            <v-icon class="mr-2" color="primary">mdi-oauth</v-icon>
                            OAuth Clients
                        </v-card-title>
                        <v-card-text>
                            <p class="text-body-2 text-medium-emphasis">Manage your OAuth2 clients</p>
                        </v-card-text>
                        <v-card-actions>
                            <v-btn color="primary" @click="$router.push({ name: 'OAuthClients' })">
                                Manage Clients
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                </v-col>

                <v-col cols="12" md="4">
                    <v-card class="dashboard-card" elevation="2">
                        <v-card-title>
                            <v-icon class="mr-2" color="primary">mdi-key</v-icon>
                            API Keys
                        </v-card-title>
                        <v-card-text>
                            <p class="text-body-2 text-medium-emphasis">View and manage your API keys</p>
                        </v-card-text>
                        <v-card-actions>
                            <v-btn color="primary" disabled>Coming Soon</v-btn>
                        </v-card-actions>
                    </v-card>
                </v-col>

                <v-col cols="12" md="4">
                    <v-card class="dashboard-card" elevation="2">
                        <v-card-title>
                            <v-icon class="mr-2" color="primary">mdi-cog</v-icon>
                            Settings
                        </v-card-title>
                        <v-card-text>
                            <p class="text-body-2 text-medium-emphasis">Update your account settings</p>
                        </v-card-text>
                        <v-card-actions>
                            <v-btn color="primary" @click="$router.push({ name: 'Settings' })">
                                Settings
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                </v-col>
            </v-row>
        </v-container>
    </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useAuthStore } from '@/store/modules/auth';

const authStore = useAuthStore();

const account = computed(() => authStore.account);
</script>

<style scoped>
.dashboard-card {
    height: 100%;
    transition: transform 0.2s;
}

.dashboard-card:hover {
    transform: translateY(-4px);
}
</style>

