<template>
    <v-menu location="bottom end" offset="8">
        <template v-slot:activator="{ props }">
            <v-btn
                icon="mdi-dots-vertical"
                variant="text"
                size="small"
                v-bind="props"
                class="action-menu-btn"
            />
        </template>
        <v-list density="compact" class="action-menu-list">
            <slot />
        </v-list>
    </v-menu>
</template>

<script setup lang="ts">
// Action menu component
</script>

<style scoped lang="scss">
.action-menu-btn {
    opacity: 0.6;
    transition: opacity 0.2s;
}

.action-menu-btn:hover {
    opacity: 1;
}

.action-menu-list {
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    min-width: 180px;
    padding: 4px 0;
}
</style>

