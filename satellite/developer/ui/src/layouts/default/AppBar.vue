<template>
    <v-app-bar
        :color="isDark ? 'surface' : 'white'"
        elevation="0"
        height="64"
        class="app-bar"
        :class="{ 'app-bar-dark': isDark }"
    >
        <!-- Hamburger Menu -->
        <v-app-bar-nav-icon
            @click="toggleDrawer"
            :icon="drawer ? 'mdi-menu-open' : 'mdi-menu'"
            class="menu-icon"
        />

        <!-- StorX Logo -->
        <div class="logo-container">
            <img
                :src="logoPath"
                alt="StorX"
                class="logo-img"
            />
            <div class="logo-text">
                <span class="logo-text-stor">Stor</span>
                <span class="logo-text-x">X</span>
            </div>
        </div>

        <v-spacer />

        <!-- Right Side Actions -->
        <div class="header-actions">
            <!-- Dark Mode Toggle -->
            <v-btn
                icon
                variant="text"
                @click="toggleTheme"
                class="theme-toggle-btn"
                :title="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
            >
                <v-icon>{{ isDark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
            </v-btn>

            <!-- User Menu -->
            <v-menu location="bottom end" offset="8">
                <template v-slot:activator="{ props }">
                    <v-btn
                        variant="text"
                        v-bind="props"
                        class="user-menu-btn"
                        prepend-icon="mdi-account-circle"
                    >
                        <span class="user-menu-text">{{ account?.fullName || 'Developer' }}</span>
                        <v-icon size="16" class="ml-1">mdi-chevron-down</v-icon>
                    </v-btn>
                </template>
                <v-list class="user-menu-list" density="compact">
                    <v-list-item class="user-info-item">
                        <v-list-item-title class="user-name">{{ account?.fullName }}</v-list-item-title>
                        <v-list-item-subtitle class="user-email">{{ account?.email }}</v-list-item-subtitle>
                    </v-list-item>
                    <v-divider class="my-1" />
                    <v-list-item
                        prepend-icon="mdi-cog-outline"
                        title="Settings"
                        :to="{ name: 'Settings' }"
                    />
                    <v-list-item
                        prepend-icon="mdi-logout"
                        title="Logout"
                        @click="handleLogout"
                        class="logout-item"
                    />
                </v-list>
            </v-menu>
        </div>
    </v-app-bar>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { useAuthStore } from '@/store/modules/auth';
import { useTheme } from '@/composables/useTheme';
import SidebarLogo from '@/assets/SidebarLogo.svg';
import SidebarLogoWhite from '@/assets/SidebarLogoWhite.svg';

const props = defineProps<{
    drawerModel?: boolean;
}>();

const emit = defineEmits<{
    'update:drawer': [value: boolean];
}>();

const router = useRouter();
const authStore = useAuthStore();
const { isDark, toggleTheme } = useTheme();

const account = computed(() => authStore.account);
const drawer = computed({
    get: () => props.drawerModel ?? true,
    set: (value) => emit('update:drawer', value),
});

const logoPath = computed(() => {
    return isDark.value ? SidebarLogoWhite : SidebarLogo;
});

function toggleDrawer() {
    drawer.value = !drawer.value;
}

async function handleLogout() {
    await authStore.logout();
    router.push({ name: 'Login' });
}
</script>

<style scoped lang="scss">
.app-bar {
    border-bottom: 1px solid rgba(0, 0, 0, 0.08);
    transition: all 0.3s ease;
}

.app-bar-dark {
    border-bottom-color: rgba(255, 255, 255, 0.12);
    background-color: #1e1e1e !important;
}

.menu-icon {
    margin-right: 8px;
}

.logo-container {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-left: 8px;
    cursor: pointer;
    user-select: none;
}

.logo-img {
    height: 32px;
    width: auto;
    flex-shrink: 0;
}

.logo-text {
    display: flex;
    align-items: center;
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.5px;
}

.logo-text-stor {
    color: #040a18;
    transition: color 0.3s ease;
}

.app-bar-dark .logo-text-stor {
    color: #ffffff;
}

.logo-text-x {
    color: #e04124;
    margin-left: 2px;
}

.header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
}

.theme-toggle-btn {
    border-radius: 8px;
    transition: all 0.2s ease;
    
    &:hover {
        background-color: rgba(0, 0, 0, 0.05);
    }
}

.app-bar-dark .theme-toggle-btn:hover {
    background-color: rgba(255, 255, 255, 0.1);
}

.user-menu-btn {
    text-transform: none;
    font-weight: 500;
    border-radius: 8px;
    padding: 6px 12px;
    height: auto;
    min-width: auto;
}

.user-menu-text {
    font-size: 14px;
    color: #040a18;
    transition: color 0.3s ease;
}

.app-bar-dark .user-menu-text {
    color: #ffffff;
}

.user-menu-list {
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    min-width: 200px;
    padding: 4px 0;
}

.user-info-item {
    padding: 12px 16px;
    cursor: default;
}

.user-name {
    font-weight: 600;
    font-size: 14px;
    color: #040a18;
}

.app-bar-dark .user-name {
    color: #ffffff;
}

.user-email {
    font-size: 12px;
    color: #6b7280;
    margin-top: 2px;
}

.logout-item {
    color: #dc2626;
    
    :deep(.v-list-item-title) {
        color: #dc2626;
    }
    
    :deep(.v-icon) {
        color: #dc2626;
    }
    
    &:hover {
        background-color: rgba(220, 38, 38, 0.1);
    }
}

@media (max-width: 600px) {
    .logo-text {
        display: none;
    }
    
    .user-menu-text {
        display: none;
    }
    
    .user-menu-btn {
        min-width: 40px;
        padding: 8px;
    }
}
</style>
