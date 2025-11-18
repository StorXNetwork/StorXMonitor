import { computed, getCurrentInstance } from 'vue';

export function useTheme() {
    // Get Vuetify instance from app context
    const instance = getCurrentInstance();
    let vuetify: any = null;
    
    if (instance) {
        vuetify = instance.appContext.config.globalProperties.$vuetify;
    }

    // Initialize theme from localStorage or system preference
    const savedTheme = localStorage.getItem('theme') as 'light' | 'dark' | null;
    
    function applyTheme(theme: 'light' | 'dark') {
        if (vuetify) {
            vuetify.theme.global.name.value = theme;
        }
        document.documentElement.classList.toggle('v-theme--dark', theme === 'dark');
        localStorage.setItem('theme', theme);
    }

    if (savedTheme) {
        applyTheme(savedTheme);
    } else {
        // Check system preference
        if (window.matchMedia) {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            applyTheme(prefersDark ? 'dark' : 'light');
        }
    }

    // Watch for system theme changes (only if no saved preference)
    if (window.matchMedia && !savedTheme) {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        mediaQuery.addEventListener('change', (e) => {
            if (!localStorage.getItem('theme')) {
                applyTheme(e.matches ? 'dark' : 'light');
            }
        });
    }

    const isDark = computed({
        get: () => {
            if (vuetify) {
                return vuetify.theme.current.value.dark;
            }
            return document.documentElement.classList.contains('v-theme--dark');
        },
        set: (value) => {
            applyTheme(value ? 'dark' : 'light');
        },
    });

    function toggleTheme() {
        const newTheme = isDark.value ? 'light' : 'dark';
        applyTheme(newTheme);
    }

    function setTheme(theme: 'light' | 'dark') {
        applyTheme(theme);
    }

    return {
        isDark,
        toggleTheme,
        setTheme,
    };
}

