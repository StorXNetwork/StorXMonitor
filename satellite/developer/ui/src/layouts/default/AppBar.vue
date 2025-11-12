<template>
    <v-app-bar color="primary" prominent>
        <v-app-bar-nav-icon @click="drawer = !drawer" />
        <v-toolbar-title>StorX Developer Console</v-toolbar-title>
        <v-spacer />
        <v-menu>
            <template v-slot:activator="{ props }">
                <v-btn icon="mdi-account-circle" v-bind="props" />
            </template>
            <v-list>
                <v-list-item>
                    <v-list-item-title>{{ account?.fullName }}</v-list-item-title>
                    <v-list-item-subtitle>{{ account?.email }}</v-list-item-subtitle>
                </v-list-item>
                <v-divider />
                <v-list-item @click="handleLogout">
                    <v-list-item-title>Logout</v-list-item-title>
                </v-list-item>
            </v-list>
        </v-menu>
    </v-app-bar>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { useAuthStore } from '@/store/modules/auth';

const router = useRouter();
const authStore = useAuthStore();

const account = computed(() => authStore.account);
const drawer = computed({
    get: () => true,
    set: () => {},
});

async function handleLogout() {
    await authStore.logout();
    router.push({ name: 'Login' });
}
</script>

