document.addEventListener('DOMContentLoaded', loadWhitelist);

async function loadWhitelist() {
    const result = await browser.storage.local.get('globalWhitelist');
    const whitelist = result.globalWhitelist || [];
    displayWhitelist(whitelist);
}

function displayWhitelist(whitelist) {
    const whitelistElement = document.getElementById('whitelistItems');
    whitelistElement.innerHTML = '';
    
    whitelist.forEach(domain => {
        const li = document.createElement('li');
        li.innerHTML = `
            ${domain}
            <button class="delete-btn" data-domain="${domain}">Delete</button>
        `;
        whitelistElement.appendChild(li);
    });

    // Event listeners for delete buttons
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', deleteDomain);
    });
}

async function addDomain() {
    const input = document.getElementById('newDomain');
    const domain = input.value.trim();
    if (!domain) return;

    const result = await browser.storage.local.get('globalWhitelist');
    const whitelist = result.globalWhitelist || [];

    if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        // When adding a new domain not included in the list, the background script handles the extension
        // internal storage modification. 
        browser.runtime.sendMessage({
            method: 'add_to_whitelist',
            data: domain
        });
        displayWhitelist(whitelist);
    }
    input.value = ''; // Clear input
}

async function deleteDomain(event) {
    const domain = event.target.dataset.domain;
    
    const result = await browser.storage.local.get('globalWhitelist');
    const whitelist = result.globalWhitelist || [];

    const index = whitelist.indexOf(domain);
    if (index > -1) {
        whitelist.splice(index, 1);
        // Removing from whitelist and from extenstion storage also gets handled by background script.
        browser.runtime.sendMessage({
            method: 'remove_from_whitelist',
            data: domain
        });
        displayWhitelist(whitelist);
    }
}

// Event listeners for user input
document.getElementById('addDomain').addEventListener('click', addDomain);
document.getElementById('newDomain').addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        addDomain();
    }
});