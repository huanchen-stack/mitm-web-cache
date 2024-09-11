const puppeteer = require('puppeteer');

async function startChrome() {
    const launchOptions = {
        args: [
            '--disk-cache-size=1',
            '--window-size=1920,1080',
            '--user-data-dir=./chrome_data',
            '--enable-automation',
            '--proxy-server=127.0.0.1:8080'
        ],
        ignoreDefaultArgs: ["--disable-extensions"],
        defaultViewport: { width: 1920, height: 1080 },
        headless: false
    };

    const browser = await puppeteer.launch(launchOptions);
    return browser;
}

(async function () {

    const browser = await startChrome();
    // const page = await browser.newPage();

})();
