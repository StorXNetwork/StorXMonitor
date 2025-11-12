<template>
    <v-app>
        <AppBar />
        <NavigationDrawer />
        <v-main>
            <v-container fluid>
                <router-view />
            </v-container>
        </v-main>
        <Footer />
    </v-app>
</template>

<script setup lang="ts">
import AppBar from './AppBar.vue';
import NavigationDrawer from './NavigationDrawer.vue';
import Footer from './Footer.vue';
</script>

