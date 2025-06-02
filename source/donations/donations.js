document.addEventListener('DOMContentLoaded', async () => {
    // Add click event listeners to all copy buttons
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', copyAddress);
    });

    // Get and display the total cleaned resources
    try {
        const response = await browser.runtime.sendMessage({method: 'get_total_cleaned'});
        if (response !== undefined) {
            document.getElementById('totalCleanedResources').textContent = response.toLocaleString();
        }
    } catch (err) {
        console.error('Failed to get total cleaned resources:', err);
    }
});

async function copyAddress(event) {
    const button = event.target;
    const addressId = button.dataset.address;
    const addressElement = document.getElementById(addressId);
    const address = addressElement.textContent;

    try {
        await navigator.clipboard.writeText(address);
        
        // Visual feedback
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.style.backgroundColor = '#4CAF50';
        
        // Reset button after 2 seconds
        setTimeout(() => {
            button.textContent = originalText;
            button.style.backgroundColor = '';
        }, 2000);
    } catch (err) {
        console.error('Failed to copy address:', err);
        
        // Visual feedback for error
        button.textContent = 'Error!';
        button.style.backgroundColor = '#f44336';
        
        // Reset button after 2 seconds
        setTimeout(() => {
            button.textContent = 'Copy';
            button.style.backgroundColor = '';
        }, 2000);
    }
} 