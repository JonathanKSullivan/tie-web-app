registerServiceWorker = function() {
    if (!navigator.serviceWorker) return;

    navigator.serviceWorker.register('/sw.js', {
        scope: '/'
    }).then(function(reg) {
        if (!navigator.serviceWorker.controller) {
            return;
        }

        if (reg.waiting) {
            updateReady(reg.waiting);
            return;
        }

        if (reg.installing) {
            trackInstalling(reg.installing);
            return;
        }

        reg.addEventListener('updatefound', function() {
            trackInstalling(reg.installing);
        });
    });
}



function trackInstalling(worker) {
    worker.addEventListener('statechange', function() {
        if (worker.state == 'installed') {
            updateReady(worker);
        }
    });
}

function updateReady(worker) {
    worker.postMessage({
            action: 'skipWaiting'
        });
}

var refreshing;
navigator.serviceWorker.addEventListener('controllerchange', function() {
    if (refreshing) return;
    window.location.reload();
    refreshing = true;
});