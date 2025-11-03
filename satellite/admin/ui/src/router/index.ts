// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

import { watch } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';

const routes = [
    {
        path: '/login',
        name: 'Login',
        component: () => import(/* webpackChunkName: "Login" */ '@/views/Login.vue'),
    },
    {
        path: '/',
        redirect: '/dashboard',
    },
    {
        path: '/',
        component: () => import('@/layouts/default/Default.vue'),
        children: [
            {
                path: '/dashboard',
                name: 'Dashboard',
                component: () => import(/* webpackChunkName: "Dashboard" */ '@/views/Dashboard.vue'),
            },
            {
                path: '/accounts',
                name: 'Accounts',
                component: () => import(/* webpackChunkName: "Users" */ '@/views/Accounts.vue'),
            },
            {
                path: '/account-search',
                name: 'Search Account',
                component: () => import(/* webpackChunkName: "Users" */ '@/views/AccountSearch.vue'),
            },
            {
                path: '/account-details',
                name: 'Account Details',
                component: () => import(/* webpackChunkName: "AccountDetails" */ '@/views/AccountDetails.vue'),
            },
            {
                path: '/projects',
                name: 'Projects',
                component: () => import(/* webpackChunkName: "Projects" */ '@/views/Projects.vue'),
            },
            {
                path: '/nodes',
                name: 'Nodes',
                component: () => import(/* webpackChunkName: "Nodes" */ '@/views/Nodes.vue'),
            },
            {
                path: '/node-details/:id',
                name: 'Node Details',
                component: () => import(/* webpackChunkName: "NodeDetails" */ '@/views/NodeDetails.vue'),
            },
            {
                path: '/project-details',
                name: 'Project Details',
                component: () => import(/* webpackChunkName: "ProjectDetails" */ '@/views/ProjectDetails.vue'),
            },
            {
                path: '/bucket-details',
                name: 'Bucket Details',
                component: () => import(/* webpackChunkName: "BucketDetails" */ '@/views/BucketDetails.vue'),
            },
            {
                path: '/admin-settings',
                name: 'Admin Settings',
                component: () => import(/* webpackChunkName: "AdminSettings" */ '@/views/AdminSettings.vue'),
            },
        ],
    },
];

const router = createRouter({
    history: createWebHistory(process.env.NODE_ENV === 'production' ? '/back-office/' : process.env.BASE_URL),
    routes,
});

// Router guard - protect routes except login
router.beforeEach((to, from, next) => {
    const token = localStorage.getItem('adminToken');
    
    // Allow access to login page without token
    if (to.path === '/login') {
        // If already logged in, redirect to dashboard
        if (token) {
            next('/dashboard');
        } else {
            next();
        }
        return;
    }
    
    // Protect all other routes
    if (!token) {
        next('/login');
    } else {
        next();
    }
});

watch(
    () => router.currentRoute.value.name as string,
    routeName => document.title = 'Storx Admin' + (routeName ? ' - ' + routeName : ''),
);

export default router;
