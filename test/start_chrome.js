const puppeteer = require('puppeteer');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

async function startChrome(useProxy, proxyPort, forceHttp1) {
    const launchOptions = {
        args: [
            '--disk-cache-size=1',
            '--window-size=1920,1080',
            '--user-data-dir=./chrome_data',
            '--enable-automation',
        ],
        defaultViewport: { width: 1920, height: 1080 },
        headless: false
    };

    // Conditionally add proxy server
    if (useProxy && proxyPort) {
        launchOptions.args.push(`--proxy-server=localhost:${proxyPort}`);
    }

    // Conditionally force HTTP/1.1
    if (forceHttp1) {
        launchOptions.args.push('--disable-http2');
    }

    const browser = await puppeteer.launch(launchOptions);
    return browser;
}

function delay(time) {
    return new Promise(function (resolve) {
        setTimeout(resolve, time)
    });
}

async function captureNetworkTraffic(url, useProxy, proxyPort, forceHttp1) {
    const browser = await startChrome(useProxy, proxyPort, forceHttp1);
    const page = await browser.newPage();

    // Disable cache in the page settings
    await page.setCacheEnabled(false);

    // Set default timeout for navigation and other actions to 300 seconds
    await page.setDefaultNavigationTimeout(300000);  // 300 seconds (5 minutes)
    await page.setDefaultTimeout(300000);            // Applies to other actions like `waitFor`

    // Store network events in this array
    const networkEvents = [];

    // Enable request interception to monitor network traffic
    await page.setRequestInterception(true);

    // Log each real network request and response, excluding blobs, data, and other non-network types
    page.on('request', request => {
        const url = request.url();

        // Only intercept real network requests (skip blob, data, etc.)
        if (!url.startsWith('blob:') && !url.startsWith('data:') && !url.startsWith('image:') && url.startsWith('http')) {
            networkEvents.push({
                url: request.url(),
                method: request.method(),
                resourceType: request.resourceType(),
                statusCode: null,
                errorText: null
            });
        }

        request.continue();
    });

    page.on('response', async response => {
        const req = response.request();
        const eventIndex = networkEvents.findIndex(event => event.url === req.url());

        if (eventIndex >= 0) {
            networkEvents[eventIndex].statusCode = response.status();
        }
    });

    page.on('requestfailed', request => {
        const eventIndex = networkEvents.findIndex(event => event.url === request.url());

        if (eventIndex >= 0) {
            networkEvents[eventIndex].errorText = request.failure().errorText;
        }
    });

    try {
        // Load the page with increased timeout
        const startTime = Date.now();
        await page.goto(url, { waitUntil: 'networkidle0', timeout: 180000 });
        const networkIdleTime = Date.now() - startTime;

        const delayTime = Math.min(60000, Math.max(networkIdleTime, 5000));
        await delay(delayTime);

    } catch (error) {
        console.error(`Error occurred while loading ${url}: ${error.message}`);
        networkEvents.push({
            url: url,
            method: 'GET',
            resourceType: 'document',
            statusCode: null,
            errorText: error.message
        });
    }

    // Log all network events to the output
    networkEvents.forEach(event => {
        console.log(JSON.stringify(event));
    });

    await browser.close();
}

// Parse the command-line flags
const argv = yargs(hideBin(process.argv))
    .option('u', {
        alias: 'url',
        type: 'string',
        demandOption: true,
        describe: 'The URL to load'
    })
    .option('p', {
        alias: 'proxy',
        type: 'number',
        describe: 'The proxy port to use (e.g., 8080)'
    })
    .option('h', {
        alias: 'http',
        type: 'string',
        choices: ['http1.1', 'http2'],
        demandOption: true,
        describe: 'The HTTP version to use (http1.1 or http2)'
    })
    .help()
    .argv;

// Determine the flags and their effects
const url = argv.u;
const useProxy = !!argv.p;
const proxyPort = argv.p || null;
const forceHttp1 = argv.h === 'http1.1';

// Start the process
(async function () {
    await captureNetworkTraffic(url, useProxy, proxyPort, forceHttp1);
})();
