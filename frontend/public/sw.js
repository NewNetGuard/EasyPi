/* eslint-disable no-restricted-globals */

/**
 * EasyPi Service Worker
 * 
 * Handles:
 * - Push notification events
 * - Notification click events
 * - Offline caching (Cache First for static, Network First for API)
 * - Background sync (future)
 */

// Replaced with the source commit by the production build. A different worker
// body lets an already-open EasyPi panel detect every installed release.
const BUILD_ID = '__EASYPI_BUILD_ID__';
const STATIC_CACHE = `easypi-static-${BUILD_ID}`;
const DYNAMIC_CACHE = `easypi-dynamic-${BUILD_ID}`;

// Static assets to cache on install
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192x192.svg',
  '/icons/icon-512x512.svg'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
      .catch((error) => {
        console.error('[SW] Failed to cache static assets:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== STATIC_CACHE && name !== DYNAMIC_CACHE)
            .map((name) => {
              return caches.delete(name);
            })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Skip API requests - always go to network
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/ws/')) {
    return;
  }

  // Don't cache Vite asset chunks. Stale JS/CSS here can break the app after deploys.
  if (url.pathname.startsWith('/assets/')) {
    return;
  }
  
  // Skip chrome-extension and other non-http requests
  if (!url.protocol.startsWith('http')) {
    return;
  }
  
  // For navigation requests, try network first, then cache
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Cache successful responses
          if (response.status === 200) {
            const responseClone = response.clone();
            caches.open(DYNAMIC_CACHE)
              .then((cache) => cache.put(request, responseClone));
          }
          return response;
        })
        .catch(() => {
          return caches.match(request)
            .then((response) => response || caches.match('/index.html'));
        })
    );
    return;
  }
  
  // For static assets, try cache first, then network
  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        
        return fetch(request)
          .then((response) => {
            // Don't cache non-successful responses
            if (!response || response.status !== 200) {
              return response;
            }
            
            // Cache the fetched response
            const responseClone = response.clone();
            caches.open(DYNAMIC_CACHE)
              .then((cache) => cache.put(request, responseClone));
            
            return response;
          });
      })
  );
});

// Push notification received
self.addEventListener('push', (event) => {
  let data = {
    title: 'EasyPi Notification',
    body: 'You have a new notification',
    icon: '/icons/icon-192x192.png',
    badge: '/icons/badge-72x72.png',
    tag: 'default',
    data: {}
  };
  
  if (event.data) {
    try {
      data = { ...data, ...event.data.json() };
    } catch (e) {
      console.error('[SW] Error parsing push data:', e);
      data.body = event.data.text();
    }
  }
  
  const options = {
    body: data.body,
    icon: data.icon || '/icons/icon-192x192.png',
    badge: data.badge || '/icons/badge-72x72.png',
    tag: data.tag || 'easypi-notification',
    data: data.data || {},
    vibrate: [100, 50, 100],
    requireInteraction: data.requireInteraction || false,
    silent: data.silent || false,
    timestamp: data.timestamp || Date.now(),
    actions: data.actions || []
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  const data = event.notification.data || {};
  const action = event.action;
  
  // Determine URL to open based on notification type
  let urlToOpen = '/dashboard';
  
  if (data.type) {
    switch (data.type) {
      case 'backup':
        urlToOpen = '/backup';
        break;
      case 'service_status':
        urlToOpen = '/services';
        break;
      case 'security':
        urlToOpen = '/security';
        break;
      case 'update':
        urlToOpen = '/settings';
        break;
      case 'system_alert':
        urlToOpen = '/monitoring';
        break;
      default:
        urlToOpen = '/dashboard';
    }
  }
  
  // Handle action buttons
  if (action) {
    switch (action) {
      case 'update':
        urlToOpen = '/settings?tab=updates';
        break;
      case 'view':
        if (typeof data.url === 'string' && data.url.startsWith('/') && !data.url.startsWith('//')) {
          urlToOpen = data.url;
        }
        break;
      case 'dismiss':
      case 'later':
        return; // Just close the notification
    }
  }
  
  // Focus existing window or open new one
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        // Try to focus an existing window
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            client.navigate(urlToOpen);
            return client.focus();
          }
        }
        
        // Open new window if none exists
        if (self.clients.openWindow) {
          return self.clients.openWindow(urlToOpen);
        }
      })
  );
});

// Notification close handler
self.addEventListener('notificationclose', () => {});

// Handle push subscription change
self.addEventListener('pushsubscriptionchange', (event) => {
  const applicationServerKey = event.oldSubscription?.options?.applicationServerKey;
  event.waitUntil(
    applicationServerKey ? self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey
    })
    .then(async (subscription) => {
      const csrfResponse = await fetch('/api/v1/auth/csrf', {
        method: 'GET',
        credentials: 'include'
      });
      if (!csrfResponse.ok) {
        throw new Error('Failed to obtain CSRF token');
      }
      const csrfPayload = await csrfResponse.json();
      return fetch('/api/v1/notifications/push/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfPayload.csrf_token,
        },
        credentials: 'include',
        body: JSON.stringify({
          endpoint: subscription.endpoint,
          keys: {
            p256dh: btoa(String.fromCharCode.apply(null, 
              new Uint8Array(subscription.getKey('p256dh')))),
            auth: btoa(String.fromCharCode.apply(null,
              new Uint8Array(subscription.getKey('auth'))))
          }
        })
      });
    })
    .catch((error) => {
      console.error('[SW] Failed to resubscribe:', error);
    }) : Promise.reject(new Error('Push subscription key is unavailable'))
  );
});

// Background sync (for future use)
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-notifications') {
    event.waitUntil(syncNotifications());
  }
});

async function syncNotifications() {
  // Future: sync notification preferences with server
}

// Message handler for communication with main app
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'GET_VERSION') {
    event.ports[0].postMessage({ version: STATIC_CACHE });
  }
});
