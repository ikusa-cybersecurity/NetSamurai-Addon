(function() {
    // Configuration - Change this value to adjust when the banner appears
    const DONATION_BANNER_MILESTONE = 10; // Show banner every 1000 resources cleaned
    
    // Avoid injecting multiple times
    if (window.__netsamurai_donation_banner_injected) return;
    window.__netsamurai_donation_banner_injected = true;
  
    // Create the banner container
    const banner = document.createElement('div');
    banner.id = 'donationsBannerIntegrated';
    banner.style.display = 'none';
    banner.style.textAlign = 'center';
    banner.style.padding = '25px 20px';
    banner.style.backgroundColor = '#2A2A2A';
    banner.style.margin = '40px auto';
    banner.style.maxWidth = '800px';
    banner.style.boxSizing = 'border-box';
    banner.style.borderRadius = '8px';
    banner.style.opacity = '0';
    banner.style.transition = 'opacity 0.5s ease-out';
  
    // Banner inner HTML
    banner.innerHTML = `
      <span class="donations-banner-close" title="Close">&times;</span>
      <div class="donations-banner-content">
        <p class="donations-banner-text">
          Your data is constantly exploited by hidden trackers and data brokers.
          <span class="green-bold">NetSamurai offers cutting-edge protection</span> to safeguard your privacy.
          By <span class="green-bold">donating</span>, you empower us to further develop NetSamurai,
          <span class="green-bold">strengthening the very defenses that shield your digital life.</span>
        </p>
        <a href="#" target="_blank" class="donations-banner-button">
          Support Privacy, Support NetSamurai
        </a>
      </div>
    `;
  
    // Add styles
    const style = document.createElement('style');
    style.textContent = `
      #donationsBannerIntegrated {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        color: #FFFFFF;
        line-height: 1.6;
        display: none;
        text-align: center;
        padding: 40px 20px;      /* 40px top/bottom, 20px left/right */
        background-color: #2A2A2A;
        margin: 40px auto;       /* 40px top/bottom, centered horizontally */
        max-width: 800px;
        box-sizing: border-box;
        border-radius: 8px;
        opacity: 0;
        transition: opacity 0.5s ease-out;
        position: relative;
        font-size: 14px !important; /* Smaller base font size */
      }
      .donations-banner-content {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        gap: 15px;
      }
      .donations-banner-text {
        margin: 0;
        font-size: 1.1em !important; /* Slightly larger than base (15.4px) */
        text-align: center;
      }
      .donations-banner-text .green-bold {
        color: #68885A;
        font-weight: bold;
      }
      #donationsBannerIntegrated .donations-banner-button {
        display: inline-block;
        background-color: #68885A !important;
        color: #FFFFFF !important;
        padding: 12px 28px;
        border-radius: 8px;
        text-decoration: none !important;
        font-weight: bold;
        font-size: 1em !important;   /* Same as base (14px) */
        transition: background-color 0.3s ease, transform 0.2s ease;
        white-space: nowrap;
      }
      #donationsBannerIntegrated .donations-banner-button:hover {
        background-color: #55714A !important;
        transform: translateY(-2px);
        color: #FFFFFF !important;
      }
      #donationsBannerIntegrated .donations-banner-close {
        position: absolute;
        top: 12px;
        right: 18px;
        font-size: 1.7em;
        color: #bbb;
        cursor: pointer;
        font-weight: bold;
        z-index: 10;
        transition: color 0.2s;
      }
      #donationsBannerIntegrated .donations-banner-close:hover {
        color: #fff;
      }
      @media (max-width: 600px) {
        #donationsBannerIntegrated {
          padding: 20px 15px;
          margin: 20px auto;
          font-size: 12px !important; /* Even smaller on mobile */
        }
        #donationsBannerIntegrated .donations-banner-text {
          font-size: 1em !important;  /* 12px */
        }
        #donationsBannerIntegrated .donations-banner-button {
          font-size: 1em !important;  /* 12px */
        }
      }
    `;
  
    // Insert style into head
    document.head.appendChild(style);
  
    // Check if banner should be shown based on cleaned resources count
    async function shouldShowBanner() {
        try {
            const response = await browser.runtime.sendMessage({ method: "get_total_cleaned" });
            const totalCleaned = response || 0;
            
            // Get the last milestone when banner was shown
            const storage = await browser.storage.local.get("lastDonationBannerMilestone");
            const lastMilestone = storage.lastDonationBannerMilestone || 0;
            
            // Calculate the next milestone using the configurable threshold
            const nextMilestone = Math.floor(totalCleaned / DONATION_BANNER_MILESTONE) * DONATION_BANNER_MILESTONE;
            
            // Show banner if we've reached a new milestone and it's at least the threshold value
            if (nextMilestone >= DONATION_BANNER_MILESTONE && nextMilestone > lastMilestone) {
                await browser.storage.local.set({ lastDonationBannerMilestone: nextMilestone });
                return true;
            }
            
            return false;
        } catch (error) {
            console.error("Error checking banner display condition:", error);
            return false;
        }
    }
  
    async function insertBanner() {
        const body = document.body;
        if (!body) return;
        
        const showBanner = await shouldShowBanner();
        if (!showBanner) {
            return;
        }
        
        body.insertBefore(banner, body.firstChild);
    
        setTimeout(() => {
            banner.style.display = 'block';
            setTimeout(() => {
                banner.style.opacity = '1';
            }, 10);
        }, 2000);  // fade-in 2 seconds
    }
  
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', insertBanner);
    } else {
      insertBanner();
    }
  
    const button = banner.querySelector('.donations-banner-button');
    if (button) {
      button.addEventListener('click', function(e) {
        e.preventDefault();
        browser.runtime.sendMessage({ method: "donations_page" });
      });
    }

    const closeBtn = banner.querySelector('.donations-banner-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        banner.style.display = 'none';
      });
    }

  })();