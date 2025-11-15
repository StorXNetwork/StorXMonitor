<template>
    <div class="page-header">
        <div class="header-content">
            <div>
                <h1 class="page-title">{{ title }}</h1>
                <p v-if="subtitle" class="page-subtitle">{{ subtitle }}</p>
            </div>
            <div v-if="$slots.actions" class="header-actions">
                <slot name="actions" />
            </div>
        </div>
    </div>
</template>

<script setup lang="ts">
defineProps<{
    title: string;
    subtitle?: string;
}>();
</script>

<style scoped lang="scss">
.page-header {
    background: #ffffff;
    padding: 24px 0;
    margin-bottom: 24px;
    border-bottom: 1px solid rgba(0, 0, 0, 0.08);
}

.header-content {
    max-width: 100%;
    padding: 0 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}

.page-title {
    font-size: 24px;
    font-weight: 600;
    color: #111827;
    margin: 0 0 4px 0;
    line-height: 1.2;
}

.page-subtitle {
    font-size: 14px;
    color: #6b7280;
    margin: 0;
}

.header-actions {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}

@media (max-width: 960px) {
    .header-content {
        flex-direction: column;
        align-items: flex-start;
    }

    .header-actions {
        width: 100%;
        justify-content: flex-start;
    }
}
</style>

