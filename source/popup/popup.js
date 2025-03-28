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


let unique_amount = 0;
let total_amount = 0;

function organizeBlockedHostUrls(data) {
    // resultData => {hostname: [[url, times_replaced], ...]}
    let resultData = new Map();
    for (let i = 0; i < data.length; i++) {
        if (resultData.has(data[i].host)) {
            resultData.get(data[i].host).push([data[i].url, data[i].times]);
        }
        else {
            resultData.set(data[i].host, [[data[i].url, data[i].times]]);
        }
        total_amount += data[i].times;
    }
    return resultData;
}


function truncateUrl(str) {
    const size = 64;
    if (str.length <= size) {
        return str;
    }
    return str.slice(0, size) + '...';
}

function truncateDomain(str) {
    const size = 26; //32
    if (str.length <= size) {
        return str;
    }
    return '...' + str.slice(-size);
}


function createHostUrlStructure(hostname, data) {
    const hostDetails = document.createElement("details");
    const hostSummary = document.createElement("summary");

    // Summary content
    const hostnameTable = document.createElement("table");
    const hostnameRow = document.createElement("tr");
    const hostnameCellLeft = document.createElement("td");
    const hostnameCellRight = document.createElement("td");
    const hostnameHeading = document.createElement("h4");
    hostnameHeading.textContent = truncateDomain(hostname);
    let hostnameResourceAmount = 0;

    const createButton = (className, buttonTitle, messageMethods) => {
        const button = document.createElement('button');
        button.classList.add("image-button", "small-button", "change-opacity", className);
        button.title = buttonTitle;
        button.addEventListener('click', () => {
            for (messageMethod of messageMethods) {
                browser.runtime.sendMessage({ method: messageMethod, data: hostname });
            }
            window.close();
        });
        return button;
    };

    // Create URL table
    const hostUrlTable = document.createElement("table");
    for (let i = 0; i < data.length; i++) {
        const row = document.createElement("tr");
        const urlCell = document.createElement("td");
        const timesCell = document.createElement("td");

        // Add '**' in front of the urls from the resources that are being hardBlocked for spamming
        let displayUrl = (data[i][1] >= 3) ? ("** " + data[i][0]) : data[i][0];

        urlCell.textContent = truncateUrl(displayUrl);
        urlCell.style.width = "270px";
        timesCell.textContent = data[i][1];
        timesCell.style.width = "30px";

        row.appendChild(urlCell);
        row.appendChild(timesCell);
        hostUrlTable.appendChild(row);

        hostnameResourceAmount += data[i][1];
    }

    // Right cell - now contains buttons + resource amount
    const buttonsSpan = document.createElement("span");
    buttonsSpan.appendChild(createButton("del-whitelist-button", "Delete from whitelist", ["remove_from_whitelist", "remove_from_tmp_whitelist", "reload_tab"]));
    buttonsSpan.appendChild(createButton("add-whitelist-button", "Add to whitelist", ["add_to_whitelist", "reload_tab"]));
    buttonsSpan.appendChild(createButton("tmp-whitelist-button", "Add to temporal whitelist", ["add_to_tmp_whitelist", "reload_tab"]));
    buttonsSpan.className = "whitelist-buttons";

    let resAmount = (hostnameResourceAmount === 0) ? "allowed" : hostnameResourceAmount.toString();
    const resAmountSpan = document.createElement("span");
    resAmountSpan.textContent = resAmount;
    resAmountSpan.className = "resource-amount";

    hostnameCellRight.appendChild(buttonsSpan);
    hostnameCellRight.appendChild(resAmountSpan);
    hostnameCellRight.className = "hostname-cell-right";

    // Left cell
    hostnameCellLeft.appendChild(hostnameHeading);
    hostnameCellLeft.className = "hostname-cell-left change-color";

    hostnameRow.appendChild(hostnameCellLeft);
    hostnameRow.appendChild(hostnameCellRight);
    hostnameTable.appendChild(hostnameRow);

    hostSummary.appendChild(hostnameTable);
    hostSummary.className = "host-summary";
    hostDetails.appendChild(hostSummary);
    hostDetails.appendChild(hostUrlTable);

    hostUrlTable.className = "host-url-table";
    hostDetails.className = "host-details";

    return hostDetails;
}


function renderPopup(){
    browser.runtime.sendMessage({method: 'get_current_domain'}, function(response) {
        let domain = document.getElementById("domain");
        let summary = document.getElementById("substituted_summary");
        let blockedUrls = document.getElementById("blocked_urls");
        if (response) {
            domain.innerHTML = response;
            summary.style.display = "block";
            blockedUrls.style.display = "block";
        }
        else {
            domain.innerHTML = "undefined";
            summary.style.display = "block";
            blockedUrls.style.display = "none";
        }
    });
}


function renderHomePage() {
    browser.runtime.sendMessage({method: 'get_blocked_urls'}, function(response) {
        if (response && response.length >= 0) {
            let blockedUrls = document.getElementById("blocked_urls");
            let parsedData = organizeBlockedHostUrls(response);
            parsedData.forEach (function(value, key) {
                // console.log(key + JSON.stringify(value));
                const hostStruct = createHostUrlStructure(key, value);
                blockedUrls.appendChild(hostStruct);
            })
            unique_amount += response.length;
            document.getElementById('num_unique').innerHTML = unique_amount.toString();
            document.getElementById('num_total').innerHTML = total_amount.toString();
            browser.runtime.sendMessage({method: 'get_cookies'}, function(response) {
                document.getElementById('total_cookies').textContent = response[0];
                document.getElementById('tracking_cookies').textContent = response[1];
            });
            /*
            browser.runtime.sendMessage({method: 'get_percent_preserved'}, function(response) {
                let percent = document.getElementById('percentage');
                if (typeof(response) === "number") {
                    percent.textContent = response.toString() + "%";
                }
                else {
                    percent.textContent = "N/A";
                }
            });
             */
        }
        else {
            document.getElementById("substituted_summary").style.display = "none";
            let blockedUrls = document.getElementById("blocked_urls");
            const message = document.createElement("span");
            message.textContent = "No tracking resources found on this site! (just yet)";
            message.className = "text_msg";
            blockedUrls.style.textAlign = "center";
            blockedUrls.appendChild(message);
        }
    });
}


function checkEnabled() {
    paywallButton = document.getElementById('paywallButton');
    resourceButton = document.getElementById('resourceButton');

    browser.runtime.sendMessage({method: 'get_paywall_blocking'}, function (response) {
        paywallButton.checked = response;
    });
    
    browser.runtime.sendMessage({method: 'get_resource_cleaning'}, function (response) {
        resourceButton.checked = response;
    });

    // Add event listeners
    paywallButton.addEventListener('change', function () {
        let isEnabled = paywallButton.checked;
        browser.runtime.sendMessage({method: 'paywallCheck', data: isEnabled});
    });

    resourceButton.addEventListener('change', function () {
        let isEnabled = resourceButton.checked;
        browser.runtime.sendMessage({method: 'resourceCheck', data: isEnabled});
    });
}

// Run our script as soon as the document's DOM is ready.
document.addEventListener('DOMContentLoaded', function () {
    checkEnabled();

    document.getElementById("home_button").addEventListener("click", function () {
        browser.tabs.create({url: "https://ikusa.tech/"});
    });
    document.getElementById("settings_button").addEventListener("click", function() {
        browser.runtime.sendMessage({method:'options_page'}, function(response){});
        window.close();
    });
    document.getElementById("report_button").addEventListener("click", function() {
        browser.tabs.query({active: true, currentWindow: true}, function(tabs) {
            let currentUrl = encodeURIComponent(tabs[0].url);
            let subject = encodeURIComponent("[NetSamurai-Addon] Report Broken Website");
            let body = encodeURIComponent(`Broken Website URL: ${currentUrl}\n\nPlease describe the issue:\n`);
            let mailtoUrl = `mailto:info@ikusa.tech?subject=${subject}&body=${body}`;
            console.debug(`Triggered broken website report - ${mailtoUrl}`);
            browser.tabs.create({url: mailtoUrl});
        });
    });
    document.getElementById("refresh_button").addEventListener("click", function() {
        browser.runtime.sendMessage({method:'reload_tab'}, function(response){});
        window.close();
    });

    const manifest = browser.runtime.getManifest();
    document.getElementById('version').textContent = 'v' + manifest.version;
});

renderPopup();
renderHomePage();
