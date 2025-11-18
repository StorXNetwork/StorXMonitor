import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '@/store/modules/auth';

const router = createRouter({
    history: createWebHistory(),
    routes: [
        {
            path: '/',
            redirect: '/login',
        },
        {
            path: '/login',
            name: 'Login',
            component: () => import('@/views/Login.vue'),
            meta: { requiresAuth: false },
        },
        {
            path: '/reset-password',
            name: 'ResetPassword',
            component: () => import('@/views/ResetPassword.vue'),
            meta: { requiresAuth: false },
        },
        {
            path: '/dashboard',
            name: 'Dashboard',
            component: () => import('@/layouts/default/Default.vue'),
            meta: { requiresAuth: true },
            children: [
                {
                    path: '',
                    name: 'DashboardHome',
                    component: () => import('@/views/Dashboard.vue'),
                },
                {
                    path: 'oauth-clients',
                    name: 'OAuthClients',
                    component: () => import('@/views/OAuthClients.vue'),
                },
                {
                    path: 'access-logs',
                    name: 'AccessLogs',
                    component: () => import('@/views/AccessLogs.vue'),
                },
                {
                    path: 'settings',
                    name: 'Settings',
                    component: () => import('@/views/Settings.vue'),
                },
            ],
        },
    ],
});

// Navigation guard
router.beforeEach(async (to, _from, next) => {
    const authStore = useAuthStore();

    // Skip auth check if there's a token in the URL (user is verifying email link)
    // The token will be verified in the Login component
    const hasTokenInUrl = to.query.token != null;

    // Check authentication status (skip if token is in URL)
    if (!authStore.isAuthenticated && !hasTokenInUrl) {
        try {
            await authStore.checkAuth();
        } catch {
            // Ignore errors, will redirect to login if needed
        }
    }

    if (to.meta.requiresAuth) {
        if (!authStore.isAuthenticated) {
            // Not authenticated, redirect to login
            next({ name: 'Login', query: { redirect: to.fullPath } });
        } else {
            // Authenticated, check if status requires password reset
            if (authStore.isResetPassStatus && to.name !== 'ResetPassword') {
                // Status is ResetPass, must reset password first
                next({ name: 'ResetPassword' });
            } else {
                next();
            }
        }
    } else {
        // Public routes (Login, ResetPassword)
        if (to.name === 'Login' && authStore.isAuthenticated) {
            // Already authenticated, check status
            if (authStore.isResetPassStatus) {
                // Must reset password
                next({ name: 'ResetPassword' });
            } else {
                // Redirect to dashboard
                next({ name: 'Dashboard' });
            }
        } else if (to.name === 'ResetPassword' && authStore.isAuthenticated && !authStore.isResetPassStatus) {
            // Trying to access reset password but status is not ResetPass
            next({ name: 'Dashboard' });
        } else {
            next();
        }
    }
});

export default router;