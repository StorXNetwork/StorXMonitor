<template>
    <v-app>
        <v-navigation-drawer
            v-model="drawer"
            permanent
            :color="isDark ? 'surface' : 'white'"
            :class="{ 'drawer-dark': isDark }"
        >
            <v-list nav density="compact" class="nav-list">
                <v-list-item
                    prepend-icon="mdi-view-dashboard"
                    title="Dashboard"
                    :to="{ name: 'DashboardHome' }"
                    :active-class="isDark ? 'active-dark' : 'active-light'"
                />
                <v-list-item
                    prepend-icon="mdi-oauth"
                    title="OAuth Clients"
                    :to="{ name: 'OAuthClients' }"
                    :active-class="isDark ? 'active-dark' : 'active-light'"
                />
                <v-list-item
                    prepend-icon="mdi-cog"
                    title="Settings"
                    :to="{ name: 'Settings' }"
                    :active-class="isDark ? 'active-dark' : 'active-light'"
                />
            </v-list>
        </v-navigation-drawer>
        <AppBar :drawer-model="drawer" @update:drawer="drawer = $event" />
        <v-main :class="{ 'main-dark': isDark }">
            <v-container fluid class="pa-0">
                <router-view />
            </v-container>
        </v-main>
        <Footer />
    </v-app>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import AppBar from './AppBar.vue';
import Footer from './Footer.vue';
import { useTheme } from '@/composables/useTheme';

const { isDark } = useTheme();
const drawer = ref(true);

// Sync theme with Vuetify
watch(isDark, (dark) => {
    document.documentElement.classList.toggle('v-theme--dark', dark);
}, { immediate: true });
</script>

<style scoped lang="scss">
.v-navigation-drawer {
    border-right: 1px solid rgba(0, 0, 0, 0.08);
    transition: all 0.3s ease;
}

.drawer-dark {
    border-right-color: rgba(255, 255, 255, 0.12);
    background-color: #1e1e1e !important;
}

.nav-list {
    padding: 8px;
    
    :deep(.v-list-item) {
        border-radius: 8px;
        margin-bottom: 4px;
        transition: all 0.2s ease;
        
        &:hover {
            background-color: rgba(0, 0, 0, 0.05);
        }
    }
}

.drawer-dark .nav-list :deep(.v-list-item:hover) {
    background-color: rgba(255, 255, 255, 0.1);
}

.active-light {
    background-color: rgba(102, 126, 234, 0.1) !important;
    color: #667eea !important;
    
    :deep(.v-icon) {
        color: #667eea !important;
    }
}

.active-dark {
    background-color: rgba(102, 126, 234, 0.2) !important;
    color: #8c9eff !important;
    
    :deep(.v-icon) {
        color: #8c9eff !important;
    }
}

.v-main {
    background-color: #f5f7fa;
    transition: background-color 0.3s ease;
}

.main-dark {
    background-color: #121212 !important;
}
</style>


