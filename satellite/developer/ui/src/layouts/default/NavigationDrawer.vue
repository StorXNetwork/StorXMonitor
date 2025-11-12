<template>
    <v-navigation-drawer permanent>
        <v-list nav>
            <v-list-item prepend-icon="mdi-view-dashboard" title="Dashboard" :to="{ name: 'DashboardHome' }" />
            <v-list-item prepend-icon="mdi-oauth" title="OAuth Clients" :to="{ name: 'OAuthClients' }" />
            <v-list-item prepend-icon="mdi-cog" title="Settings" :to="{ name: 'Settings' }" />
        </v-list>
    </v-navigation-drawer>
</template>

<script setup lang="ts">
// Navigation drawer component
</script>

