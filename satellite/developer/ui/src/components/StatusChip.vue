<template>
    <v-chip
        :color="color"
        size="small"
        variant="flat"
        :prepend-icon="icon"
        class="status-chip"
    >
        {{ label }}
    </v-chip>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
    status: number | string;
    activeLabel?: string;
    inactiveLabel?: string;
}>();

const isActive = computed(() => props.status === 1 || props.status === 'active' || props.status === 'Active');

const color = computed(() => (isActive.value ? 'success' : 'warning'));
const icon = computed(() => (isActive.value ? 'mdi-check-circle' : 'mdi-pause-circle'));
const label = computed(() => {
    if (props.status === 1 || props.status === 'active' || props.status === 'Active') {
        return props.activeLabel || 'Active';
    }
    return props.inactiveLabel || 'Inactive';
});
</script>

<style scoped lang="scss">
.status-chip {
    font-weight: 500;
    font-size: 12px;
}
</style>

