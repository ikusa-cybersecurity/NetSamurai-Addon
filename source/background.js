/*
 * SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
 *
 * This file contains code originally licensed under the Apache License 2.0
 * and modifications/additions licensed under the GNU General Public License v3.0.
 *
 * - Original portions: Copyright (C) 2020 Universitat Politècnica de Catalunya – Licensed under Apache 2.0
 * - Modifications: Copyright (C) 2025 ePrivo Observatory  – Licensed under GPL-3.0-or-later
 * - Modifications: Copyright (C) 2025 Ikusa Cybersecurity  – Licensed under GPL-3.0-or-later
 *
 * You may choose to follow either license when using this file.
 *
 * Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0
 * GPL-3.0 License: https://www.gnu.org/licenses/gpl-3.0.html
 */


// ============== GENERAL PURPOSE VARIABLES ==============
let filter = true; // Boolean that indicates if extension's filter is activated or not
let tabsInfo = new Map(); //Info about current open tabs will be handled in this variable

const cookieDBEnabled = true;
let trackingCookies = [] // Extracted from the Open Cookie Database
let hardBlockThreshold = 3

// ============== REMOTE PATHS ==============
const remoteBasePath = "https://raw.githubusercontent.com/ikusa-cybersecurity/NetSamurai-Addon/main/"
const openCookieDBPath = "https://raw.githubusercontent.com/jkwakman/Open-Cookie-Database/master/open-cookie-database.csv";

// ============== LIST/RULES MANAGEMENT ==============
let globalWhitelist = [];
let tabTmpWhitelist = [] // EXPERIMENTAL - save tmpWhitelist when reloading

let addonResourceCleaningActive = true; // Addon button
let offsetHashlist = {};

const unbreakRulesActive = true;
let reUnbreakRules; // RegExp

let addonPaywallBlockingActive = true; // Addon button 
const paywallRulesActive = true;
let rePaywallRules; // RegExp

// #################### ADDON INITIALIZATION ####################
async function initializeAddon() {
    try {
        await loadWhitelist();
        await updateOffsetHashlist();
        if (unbreakRulesActive) {
            await updateUnbreakRules();
        }
        if (paywallRulesActive) {
            await updatePaywallRules();
        }
        if (cookieDBEnabled) {
            await loadTrackingCookiesDB();
        }
        console.debug("Addon initialization completed successfully");
    } catch (e) {
        console.error("Error during addon initialization:", e);
    }
}

initializeAddon();
browser.browserAction.setBadgeBackgroundColor({color:'#cf1b1b'}); // Badge color (# cleaned urls)


// ############################################## UPDATE LISTS/RULES ##############################################
async function getRemoteList(list_url, storage_var) {
    try {
        // Get local hash from storage
        let localHashVar = storage_var + "Hash";
        let localHash = (await browser.storage.local.get(localHashVar))[localHashVar];
        // Try to get remote hash
        let remoteHash;
        try {
            remoteHash = await (await fetch(list_url + ".sha256")).text();
        } catch (e) {
            console.error(`Error fetching hash for ${storage_var}:`, e);
            // If we can't get the remote hash, use existing data if available
            if (localHash !== undefined) {
                return (await browser.storage.local.get(storage_var))[storage_var];
            }
            // If no existing data, throw error to trigger fallback
            throw e;
        }
        // Update if no local data stored or if newer data is available
        if (localHash === undefined || localHash !== remoteHash) {
            console.debug(`${storage_var} local  : ${localHash}`);
            console.debug(`${storage_var} remote : ${remoteHash}`);
            try {
                let response = await fetch(list_url);
                let json_response = await response.json();
                // Store data
                isRegexRules = storage_var.toLowerCase().includes('rules')
                storage_data = isRegexRules ? json_response.rules : json_response;
                let storageObj = {};
                storageObj[storage_var] = storage_data;
                await browser.storage.local.set(storageObj);
                // Store hash
                let hashObj = {};
                hashObj[localHashVar] = remoteHash;
                await browser.storage.local.set(hashObj);

                console.debug(`${storage_var} updated!`);
                return storage_data;
            } catch (e) {
                console.error(`Error fetching data for ${storage_var}:`, e);
                // If fetch fails but we have existing data, use it
                if (localHash !== undefined) {
                    console.warn(`Loading stored content for ${storage_var}:`, e);
                    return (await browser.storage.local.get(storage_var))[storage_var];
                }
                // If no existing data, throw error to trigger fallback
                throw e;
            }
        }
        else {
            // Return existing data from storage
            console.debug(`${storage_var} already up to date!`);
            return (await browser.storage.local.get(storage_var))[storage_var];
        }
    } catch (e) {
        console.error(`Error loading ${storage_var}:`, e);
        // Return null to indicate failure, allowing caller to handle fallback
        return null;
    }
}

async function updateOffsetHashlist() {
    offsetHashlist = await getRemoteList(remoteBasePath + "lists/offsets/offsets.json", "offsetHashlist");
    if (offsetHashlist === null) {
        console.error("Failed to load offsetHashlist! loaded empty list.");
        offsetHashlist = {};
    }
}

async function updatePaywallRules() {
    let rawPaywallRules = await getRemoteList(remoteBasePath + "lists/rules/paywalls.json", "paywallRules");
    if (rawPaywallRules === null) {
        console.error("Failed to load paywallRules! paywallRules disabled.");
    } else {
        rePaywallRules = new RegExp(rawPaywallRules.join("|"));
    }
}
function isPaywall(url) { return rePaywallRules.test(url); }

async function updateUnbreakRules() {
    let rawUnbreakRules = await getRemoteList(remoteBasePath + "lists/rules/unbreak.json", "unbreakRules");
    if (rawUnbreakRules === null) {
        console.error("Failed to load unbreakRules! unbreakRules disabled.");
    } else {
        reUnbreakRules = new RegExp(rawUnbreakRules.join("|"));
    }
}
function isUnbreak(url) { return reUnbreakRules.test(url); }

async function loadTrackingCookiesDB() {
    let response = await fetch(openCookieDBPath);
    let lines = (await response.text()).split("\n");
    for (let idx in lines) {
        let content = lines[idx].split(',');
        if (content[2] === "Marketing") { // Content[2] -> Category header
            trackingCookies.push(content[3]); // Content[3] -> Cookie / Data Key name header
        }
    }
    console.log("Loaded tracking cookie list from Open Cookie Database.");
}


// ############################################## USER WHITELIST FUNCTIONS ##############################################
async function loadWhitelist(){
    globalWhitelist = (await browser.storage.local.get("globalWhitelist")).globalWhitelist;
    if (globalWhitelist === undefined) {
        globalWhitelist = [];
        // console.debug("[whitelist] Initializing whitelist...");
        browser.storage.local.set({globalWhitelist});
    }
}


//######################### CONTENT-BLOCKER FUNCTIONS #########################
//generates the SHA-256 hash string from an ArrayBuffer
async function hash_func(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data); // hash the message
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    return (hashArray.map(b => b.toString(16).padStart(2, '0')).join('')); // convert bytes to hex string
}


//######################### tabInfo related functions #########################
//function to create a new entry for tabsInfo
function newInfo (tabId){
    browser.tabs.get(tabId,
         function(tab) {
            if (browser.runtime.lastError) {
                // Roundabout to error "no tab with id xxx"
                console.debug("Sorry for this: ",browser.runtime.lastError.message);
                return;
            }
            try {
                if (tab.url === undefined) return;
                let auxHost = new URL(tab.url).host;

                let auxTmpWhitelist = []
                if (tabTmpWhitelist[tabId] !== undefined) {
                    auxTmpWhitelist = tabTmpWhitelist[tabId];
                    console.debug("(newInfo:tab-" + tabId + ") Loaded previous tmp whitelist: " + auxTmpWhitelist);
                }

                let info = {
                    id: tabId,
                    url: tab.url,
                    host: auxHost,
                    baseHost: getBaseHost(auxHost),
                    substitutedUrls: [], // array of {url: x, host: y, times: z}
                    totalSubstituted: 0, // Total number of substituted resources
                    bytesLoadedDefault: 0, // Total size of loaded resources without cleaner
                    bytesLoadedClean: 0, // Size of loaded clean resources
                    totalCookies: 0, // Number of cookies for this tab url
                    trackingCookies: 0, // Number of tracking (marketing) cookies identified using openCookieDB
                    thirdParties: 0, // Number of third party domains found in the url
                    thirdPartyDomains: [], // List of third party domains
                    hardBlockList: [], // Resources that have to be blocked without substituting
                    tmpWhitelist: auxTmpWhitelist, // Whitelist for resources permitted temporally & only on this tab
                };
                tabsInfo.set(tabId,info);
                // To initialize counters with the already existing cookies
                countCookiesURL(tabId, tab.url);
            } catch (e) {
                // If you load something that's not a website, error, like local files
                console.debug("Visited site is not an URL");
            }
        }
    );
}

function getBaseHost(auxHost) {
    // baseHost doesn't work with more complex domains, e.g. those .co.uk
    let baseHost = auxHost.split(".");
    baseHost = baseHost.slice(baseHost.length-2, baseHost.length);
    baseHost = (baseHost[0]+"."+baseHost[1]);
    return baseHost;
}

function updateTabInfo (idTab, auxUrl, bytesDefault, bytesClean){
    const auxUrlArray = tabsInfo.get(idTab).substitutedUrls;
    let urlFound = false;
    for (let index = 0; !urlFound && index < auxUrlArray.length; index++) {
        if (auxUrlArray[index].url === auxUrl.href) {
            tabsInfo.get(idTab).substitutedUrls[index].times += 1;
            urlFound = true;
            // Update hardBlock list too
            if (tabsInfo.get(idTab).substitutedUrls[index].times === hardBlockThreshold)
                tabsInfo.get(idTab).hardBlockList.push(auxUrl.href);
        }
    }
    if (!urlFound) {
        tabsInfo.get(idTab).substitutedUrls.push({
            url: auxUrl.href,
            host: auxUrl.host,
            times: 1
        });
    }

    tabsInfo.get(idTab).bytesLoadedDefault += bytesDefault;
    tabsInfo.get(idTab).bytesLoadedClean += bytesClean;
    tabsInfo.get(idTab).totalSubstituted += 1;

    // To update cookie counters whenever possible
    countCookiesURL(idTab, tabsInfo.get(idTab).url);

    browser.browserAction.setBadgeText(
        {tabId: idTab, text: ((tabsInfo.get(idTab).totalSubstituted).toString())}
    );
}

function updateTabInfoWhitelist(idTab, auxUrl) {
    const auxUrlArray = tabsInfo.get(idTab).substitutedUrls;
    let urlFound = false;
    for (let index = 0; !urlFound && index < auxUrlArray.length; index++) {
        if (auxUrlArray[index].url === auxUrl.href) {
            urlFound = true;
        }
    }
    if (!urlFound) {
        tabsInfo.get(idTab).substitutedUrls.push({
            url: auxUrl.href,
            host: auxUrl.host,
            times: 0
        });
    }
}

function countTrackingCookies(cookies) {
    let counter = 0;
    // Maybe should look for a way to do this more efficiently
    for (let i in cookies) {
        for (let j in trackingCookies) {
            if (cookies[i].name === trackingCookies[j]) {
                counter++;
            }
        }
    }
    return counter;
}

function countCookiesURL(idTab, targetUrl) {
    browser.cookies.getAll({url: targetUrl})
        .then(cookies => {
            tabsInfo.get(idTab).totalCookies = cookies.length;
            tabsInfo.get(idTab).trackingCookies = countTrackingCookies(cookies);
            // console.log(targetUrl + ": " + cookies.length + " cookies (" + tabsInfo.get(idTab).trackingCookies + " tracking)");
        })
        .catch(err => {
            console.log("Something went wrong: " + err);
            tabsInfo.get(idTab).totalCookies = -1;
            tabsInfo.get(idTab).trackingCookies = -1;
        });
}


// ############################################## REQUEST PROCESSING ##############################################
function cleanResourceOffsets(data, trackingParts) {
    let cleanResource = [];
    try {
        let index = 0;
        for (let [offset, length] of trackingParts) {
            cleanResource.push(...data.slice(index, offset));
            index = offset + length;
        }
        cleanResource.push(...data.slice(index));
    } catch (e) {
        console.error(e);
        console.error("Substitution failed. Blocking resource...");
        cleanResource = new ArrayBuffer(0);
    }
    return new Uint8Array(cleanResource);
}


browser.webRequest.onBeforeRequest.addListener(
    function(details){
        //this is a callback function executed when details of the webrequest are available

        //check if extension is enabled
        if (!filter){
            console.debug("No filter!");
            return;
        }

        const request_url = details.url;
        const idTab = details.tabId;

        //needed when tab created in background
        if (idTab >= 0 && !tabsInfo.has(idTab)) {
            newInfo(idTab);
        }

        if (tabsInfo.get(idTab) === undefined) {
            return;
        }

        let auxURL = new URL(request_url);
        // let tabHost = tabsInfo.get(idTab).host;
        let tabBaseHost = tabsInfo.get(idTab).baseHost;

        // Check if the resource is in the unbreak list
        if (unbreakRulesActive && isUnbreak(auxURL.href)) {
            console.debug("Allowed by unbreak list: " + request_url);
            return;
        }
        // Check global permanent whitelist
        for (let key in globalWhitelist) {
            if (auxURL.href.includes(globalWhitelist[key])) {
                updateTabInfoWhitelist(idTab, auxURL);
                console.debug("Allowed by global whitelist: " + request_url);
                return;
            }
        }
        // Check tab temporal whitelist
        let auxTmpWhitelist = tabsInfo.get(idTab).tmpWhitelist;
        for (let key in auxTmpWhitelist) {
            // console.log("Checking " + auxURL.href + " against tmp whitelist:");
            // console.log(auxTmpWhitelist);
            if (auxURL.href.includes(auxTmpWhitelist[key])) {
                updateTabInfoWhitelist(idTab, auxURL);
                console.debug("Allowed by tab whitelist: " + request_url);
                return;
            }
        }
        // Check if the resource is identified as paywall or comes from paywall providers 
        if (addonPaywallBlockingActive && paywallRulesActive && isPaywall(auxURL.href)) {
            console.log(auxURL.href + " blocked due to paywall restrictions!");
            return {cancel: true};
        }
        // Check if the resource has to be blocked due to spamming
        let auxHardBlockList = tabsInfo.get(idTab).hardBlockList;
        for (let idx in auxHardBlockList) {
            if (auxURL.href.includes(auxHardBlockList[idx])) {
                console.log(auxURL.href + " directly blocked to avoid spamming!");
                return {cancel: true};
            }
        }

        // Check if addon has resource cleaning disabled. We need to check it after paywall, in case
        // user wants to keep paywall blocking functionality withouth resource cleaning active.
        if (!addonResourceCleaningActive) {return;}

        // CONTENT BLOCKER
        let filterReq = browser.webRequest.filterResponseData(details.requestId);
        let tmp_data = [];

        filterReq.ondata = event => {
            tmp_data.push(event.data);
        };

        filterReq.onstop = async event => {

            let auxBlob = new Blob(tmp_data);
            let data = await new Response(auxBlob).arrayBuffer();

            let hash = await hash_func(data);
            let isTracking = offsetHashlist.hasOwnProperty(hash);

            if (isTracking) { // Has to be blocked
                replacementEntry = offsetHashlist[hash]
                console.debug("Tracking resource found: " + details.url + " -> " + hash);
                let originalDataView = new Uint8Array(data);
                let new_data;

                if (replacementEntry["num"] === -1) {
                    new_data = new ArrayBuffer(0);
                }
                else {
                    // cleanResourceOffsets function does already check for exceptions.
                    new_data = cleanResourceOffsets(originalDataView, replacementEntry["parts"]);
                }

                console.debug(details.url + " cleaned by netsamurai");
                // TODO: Check why so many new_data.legth come as undefined despite the algorithm working
                //console.debug("(Replaced: " + hash + " | size " + originalDataView.length + " -> " + new_data.length + " )");

                // Add info to tabInfo
                let auxURL = await new URL(request_url);
                await updateTabInfo(details.tabId, auxURL, data.byteLength, new_data.byteLength);
                await writeFilter(filterReq, new_data);
            }
            else {
                await writeFilter(filterReq, data);
            }
        }
        async function writeFilter(filter, data) {
            filter.write(data);
            filter.close();

        }
    },
    {urls: ["<all_urls>"]},
    ["blocking"]
);


// ############################################## TABS LISTENERS ##############################################
let current_tab;

function setCurrentTab(tabs) {
    current_tab = tabs[0].id;
}

function currentTabError(error) {
    console.error(`Error: ${error}`);
}

browser.tabs.query({ currentWindow: true, active: true }).then(setCurrentTab, currentTabError);

//on removed, remove tabInfo when a tab is closed
browser.tabs.onCreated.addListener(
    function(tab){
        console.error("onCreated for tab.id " + tab.id);
        if(!tabsInfo.has(tab.id)){
            newInfo(tab.id);
            console.error("Initialized structure for " + tab.id);
        }
    }
);

//on activated tab, creates new tabInfo if tab visited is not registered
browser.tabs.onActivated.addListener(
    function(activeInfo){
        console.error("onActivated for tabId " + activeInfo.tabId);
        current_tab = activeInfo.tabId;
        if (!tabsInfo.has(activeInfo.tabId)){
            newInfo(activeInfo.tabId);
            console.error("Initialized structure for " + activeInfo.tabId);
        }
    }
);

//on updated tab, creates new tabInfo when page is reloaded or url is changed
browser.tabs.onUpdated.addListener(
    function(tabId, changeInfo){
        console.error("onUpdated for tabId " + tabId);
        if ((changeInfo.url !== undefined) && tabsInfo.has(tabId)){
            newInfo(tabId);
            console.error("Re-Initialized (redirect|refresh) structure for " + tabId);
            browser.browserAction.setBadgeText(
                {tabId: tabId, text: ('')}
            );
        }
    }
);

//on removed, remove tabInfo when a tab is closed
browser.tabs.onRemoved.addListener(
    function(tabId){
        if(!tabsInfo.has(tabId)){
            return;
        }
        tabsInfo.delete(tabId);
    }
);


// ############################################## CONNECTIONS WITH POPUP ##############################################
browser.runtime.onMessage.addListener(function(request, sender, sendResponse) {
	switch (request.method) {
        case 'get_enabled':
            sendResponse(filter);
            break;

        case 'filterCheck':
            filter = request.data;
            break;

        case 'get_blocked_urls':
            if (tabsInfo.has(current_tab)){
                // Show tracking resources default size vs. clean size
                // console.log(current_tab.toString() + " def bytes: " + tabsInfo.get(current_tab).bytesLoadedDefault)
                // console.log(current_tab.toString() + " clean bytes: " + tabsInfo.get(current_tab).bytesLoadedClean)
                //console.debug("Request received, sending data...", tabsInfo.get(current_tab).blocked);
                sendResponse(tabsInfo.get(current_tab).substitutedUrls);
            }
            break;

        case 'get_current_domain':
            //if (current_tab === undefined) {
            //    let auxtab = await browser.tabs.query({currentWindow: true, active: true});
            //    current_tab = auxtab[0].id;
            //}
            //console.error("get_current_domain -> current_tab: " + current_tab);
            if (tabsInfo.has(current_tab)){
                sendResponse(tabsInfo.get(current_tab).host);
            }
            break;

        case 'get_percent_preserved':
            if (tabsInfo.has(current_tab)){
                let default_bytes = tabsInfo.get(current_tab).bytesLoadedDefault;
                let clean_bytes = tabsInfo.get(current_tab).bytesLoadedClean;
                // console.log(Math.round(clean_bytes/default_bytes));
                sendResponse(Math.round(clean_bytes/default_bytes));
            }
            break;

        case 'reload_tab':
            browser.tabs.executeScript(current_tab, {code: "window.location.reload();"});
            break;

        case 'options_page':
            browser.runtime.openOptionsPage();
            break;

        case 'add_to_whitelist':
            let atw_idx = globalWhitelist.indexOf(request.data);
            if (atw_idx === -1) {
                globalWhitelist.push(request.data);
                browser.storage.local.set({globalWhitelist});
            }
            console.debug("add_to_whitelist -> " + request.data);
            console.debug(globalWhitelist);
            break;

        case 'remove_from_whitelist':
            let rfw_idx = globalWhitelist.indexOf(request.data);
            if (rfw_idx !== -1) {
                globalWhitelist.splice(rfw_idx, 1);
                browser.storage.local.set({globalWhitelist});
            }
            console.debug("remove_from_whitelist -> " + request.data);
            console.debug(globalWhitelist);
            break;

        case 'add_to_tmp_whitelist':
            if (tabsInfo.has(current_tab)) {
                let attw_idx = tabsInfo.get(current_tab).tmpWhitelist.indexOf(request.data);
                if (attw_idx === -1) {
                    tabsInfo.get(current_tab).tmpWhitelist.push(request.data);
                    tabTmpWhitelist[current_tab] = tabsInfo.get(current_tab).tmpWhitelist;
                }
            }
            console.debug("add_to_tmp_whitelist -> " + request.data);
            console.debug(tabsInfo.get(current_tab).tmpWhitelist);
            break;

        case 'remove_from_tmp_whitelist':
            if (tabsInfo.has(current_tab)) {
                let rftw_idx = tabsInfo.get(current_tab).tmpWhitelist.indexOf(request.data);
                if (rftw_idx !== -1) {
                    tabsInfo.get(current_tab).tmpWhitelist.splice(rftw_idx, 1);
                    tabTmpWhitelist[current_tab] = tabsInfo.get(current_tab).tmpWhitelist;
                }
            }
            console.debug("remove_from_tmp_whitelist -> " + request.data);
            console.debug(tabsInfo.get(current_tab).tmpWhitelist);
            break;

        case 'get_cookies':
            if (tabsInfo.has(current_tab)) {
                sendResponse([tabsInfo.get(current_tab).totalCookies, tabsInfo.get(current_tab).trackingCookies]);
            }
            break;

        case 'get_paywall_blocking':
            sendResponse(addonPaywallBlockingActive);
            break;
        
        case 'paywallCheck':
            addonPaywallBlockingActive = request.data;
            break;
        
        case 'get_resource_cleaning':
            sendResponse(addonResourceCleaningActive);
            break;
        
        case 'resourceCheck':
            addonResourceCleaningActive = request.data;
            break;
    }
    //this is to prevent error message "Unchecked runtime.lastError: The message port closed before a response was received." from appearing needlessly
    sendResponse();
});
