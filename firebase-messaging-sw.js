// Firebase Cloud Messaging Service Worker
// This file must be accessible at the root: /firebase-messaging-sw.js
// 
// IMPORTANT: Replace the Firebase config values below with your actual values
// from your environment variables:
// - VITE_FIREBASE_API_KEY
// - VITE_FIREBASE_AUTH_DOMAIN
// - VITE_FIREBASE_PROJECT_ID
// - VITE_FIREBASE_MESSAGING_SENDER_ID
// - VITE_FIREBASE_APP_ID

// Firebase Cloud Messaging Service Worker
let messaging;

try {
    importScripts('https://www.gstatic.com/firebasejs/12.6.0/firebase-app-compat.js');
    importScripts('https://www.gstatic.com/firebasejs/12.6.0/firebase-messaging-compat.js');

    const firebaseConfig = {
        apiKey: "AIzaSyC9R-m3tyhMMwxQbJJ9-bYzFjn6UN1zeu4",
        authDomain: "storx-network.firebaseapp.com",
        projectId: "storx-network",
        storageBucket: "storx-network.firebasestorage.app",
        messagingSenderId: "220941885214",
        appId: "1:220941885214:web:82889b14327943b49bb30f"
    };
    
    firebase.initializeApp(firebaseConfig);
    messaging = firebase.messaging();
} catch (error) {
    console.error('[firebase-messaging-sw.js] Error initializing Firebase:', error);
    throw error;
}

// Handle background messages when the app is in the background
messaging.onBackgroundMessage((payload) => {
    const notificationTitle = payload.notification?.title || 'New Notification';
    const notificationOptions = {
        body: payload.notification?.body || '',
        icon: payload.notification?.icon || '/static/dist/favicon.ico',
        badge: '/static/dist/favicon.ico',
        image: payload.notification?.image,
        data: payload.data || {},
        tag: payload.data?.tag || 'default',
        requireInteraction: false,
        silent: false
    };

    return self.registration.showNotification(notificationTitle, notificationOptions);
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if (client.url === '/' && 'focus' in client) {
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow('/');
            }
        })
    );
});

