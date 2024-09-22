const puppeteer = require('puppeteer');

async function startChrome() {
    const launchOptions = {
        args: [
            '--disk-cache-size=1',
            '--window-size=1920,1080',
            '--user-data-dir=./chrome_data',
            '--enable-automation',
            '--proxy-server=localhost:8080'  // Adjust proxy if needed
        ],
        ignoreDefaultArgs: ["--disable-extensions"],
        defaultViewport: { width: 1920, height: 1080 },
        headless: false
    };

    const browser = await puppeteer.launch(launchOptions);
    return browser;
}

(async function () {
    const MAX_BATCH_SIZE = 30;  // Maximum number of resources to process in each cycle
    const INTERVAL = 1000;      // Fixed cycle interval (ms)
    let pendingRequests = [];

    // Start the browser
    const browser = await startChrome();

    // Open a new page
    const page = await browser.newPage();

    // // Enable request interception for controlling request flow
    // await page.setRequestInterception(true);

    // // Intercept and batch network requests
    // page.on('request', (request) => {
    //     if (['image', 'script', 'stylesheet', 'font', 'xhr', 'fetch'].includes(request.resourceType())) {
    //         // Collect requests that are for resources (batchable)
    //         pendingRequests.push(request);
    //     } else {
    //         // Let non-batchable requests (like main document HTML) continue immediately
    //         request.continue();
    //     }
    // });

    // // Helper function to wait for a given time (milliseconds)
    // function delay(time) {
    //     return new Promise(resolve => setTimeout(resolve, time));
    // }

    // // Main loop to process requests in 1-second intervals
    // async function processRequestsInBatches() {
    //     while (true) {
    //         // Process up to MAX_BATCH_SIZE requests every 1 second
    //         if (pendingRequests.length > 0) {
    //             console.log("Processing batch...", pendingRequests.length);
    //             const batch = pendingRequests.splice(0, MAX_BATCH_SIZE);  // Take at most 20 requests
    //             await Promise.all(batch.map(request => request.continue()));
    //         }

    //         // Wait for the INTERVAL (1 second) before starting the next cycle
    //         console.log("Idle cycle: waiting for the next batch...");
    //         await delay(INTERVAL);
    //     }
    // }

    // // Start the busy-idle cycle
    // processRequestsInBatches();

    // Let the user manually enter any URL in the browser
    console.log("Browser launched. Manually enter a URL in the address bar.");

    // This keeps the browser session alive until manually closed
})();
