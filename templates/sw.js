{{ JSGlue.include() }}
var staticCacheName = 'TIE-static-v1';
var contentImgsCache = 'TIE-content-imgs';
var allCaches = [
    staticCacheName,
    contentImgsCache
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(staticCacheName).then(function(cache) {
            return cache.addAll([
                '/',
                '/about',
                '/services',
                '/contact'
            ]);
        })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.filter(function(cacheName) {
                    return cacheName.startsWith('TIE-') && cacheName != staticCacheName;
                }).map(function(cacheName) {
                    return caches.delete(cacheName);
                })
            );
        })
    );
});

self.addEventListener('fetch', function(event) {

    var requestUrl = new URL(event.request.url);
    var eventResponse = fetch(event.request)
    console.log(eventResponse === 404)
    if (requestUrl.pathname.startsWith('/static/images/')) {
        event.respondWith(servePhoto(event.request));
        return;
    }

    event.respondWith(caches.match(event.request).then(function(response) {
        return  response || fetch(event.request);
    }));
});

function servePhoto(request) {
    var storageUrl = request.url.replace(/-\d+px\.jpg$/, '');

    return caches.open(contentImgsCache).then(function(cache) {
        return cache.match(storageUrl).then(function(response) {
            if (response) return response;

            return fetch(request).then(function(networkResponse) {
                cache.put(storageUrl, networkResponse.clone());
                return networkResponse;
            });
        });
    });
}

self.addEventListener('message', function(event) {
    if (event.data.action === 'skipWaiting') {
        self.skipWaiting();
    }
});