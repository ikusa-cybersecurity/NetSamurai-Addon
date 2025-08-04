(function() {
    // Configuration - Change this value to adjust when the banner appears
    const DONATION_BANNER_MILESTONE = 10; // Show banner every 1000 resources cleaned
    const FIRST_BANNER_DELAY_DAYS = 0; // Days to wait before showing banner for the first time
    
    // Work hours restriction - avoid showing banner during work hours
    const WORK_HOURS_START = 8; // 8:00 am
    const WORK_HOURS_END = 16; // 4:00 pm (16:00h)
    
    // Avoid injecting multiple times
    if (window.__netsamurai_donation_banner_injected) return;
    window.__netsamurai_donation_banner_injected = true;
  
    // Create the banner container
    const banner = document.createElement('div');
    banner.id = 'donationsBannerIntegrated';
    banner.style.cssText = `
        display: none !important;
        text-align: center !important;
        padding: 25px 20px !important;
        background-color: #2A2A2A !important;
        margin: 40px auto !important;
        max-width: 800px !important;
        box-sizing: border-box !important;
        border-radius: 8px !important;
        opacity: 0 !important;
        transition: opacity 0.5s ease-out !important;
        position: relative !important;
        z-index: 999999 !important;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
        color: #FFFFFF !important;
        line-height: 1.6 !important;
        font-size: 14px !important;
    `;
  
    // Banner inner HTML with aggressive inline styles
    banner.innerHTML = `
      <span class="donations-banner-close" title="Close" style="position: absolute !important; top: 12px !important; right: 18px !important; font-size: 1.7em !important; color: #bbb !important; cursor: pointer !important; font-weight: bold !important; z-index: 10 !important; transition: color 0.2s !important;">&times;</span>
      <div class="donations-banner-content" style="display: flex !important; flex-direction: column !important; justify-content: center !important; align-items: center !important; gap: 15px !important;">
        <p class="donations-banner-text" style="margin: 0 !important; font-size: 1.1em !important; text-align: center !important; color: #FFFFFF !important;">
          Protecting your digital life is an ongoing battle, as hidden trackers and data brokers are always evolving. 
          <span class="green-bold" style="color: #68885A !important; font-weight: bold !important;">NetSamurai offers cutting-edge protection</span> to safeguard your privacy. 
          By donating, you join our mission to <span class="green-bold" style="color: #68885A !important; font-weight: bold !important;">stay a step ahead</span>, ensuring NetSamurai 
          remains a powerful shield <span class="green-bold" style="color: #68885A !important; font-weight: bold !important;">for everyone.</span>
        </p>
        <a href="#" target="_blank" class="donations-banner-button" style="display: inline-block !important; background-color: #68885A !important; color: #FFFFFF !important; padding: 12px 28px !important; border-radius: 8px !important; text-decoration: none !important; font-weight: bold !important; font-size: 1em !important; transition: background-color 0.3s ease, transform 0.2s ease !important; white-space: nowrap !important;">
          Support Our Mission
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
        padding: 40px 20px;
        background-color: #2A2A2A;
        margin: 40px auto;
        max-width: 800px;
        box-sizing: border-box;
        border-radius: 8px;
        opacity: 0;
        transition: opacity 0.5s ease-out;
        position: relative;
        font-size: 14px !important;
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
        font-size: 1.1em !important;
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
        font-size: 1em !important;
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
          font-size: 12px !important;
        }
        #donationsBannerIntegrated .donations-banner-text {
          font-size: 1em !important;
        }
        #donationsBannerIntegrated .donations-banner-button {
          font-size: 1em !important;
        }
      }
    `;
  
    // Insert style into head
    document.head.appendChild(style);
  
    // Check if banner should be shown based on cleaned resources count and time since installation
    async function shouldShowBanner() {
        try {
            // Check if current time and don't show banner during work hours
            const now = new Date();
            const currentHour = now.getHours();
            if (currentHour >= WORK_HOURS_START && currentHour < WORK_HOURS_END) {
                return false;
            }
            
            // Get total cleaned resources count from background script
            const response = await browser.runtime.sendMessage({ method: "get_total_cleaned" });
            const totalCleaned = response || 0;
            
            // Get the last milestone when banner was shown
            const storage = await browser.storage.local.get(["lastDonationBannerMilestone", "extensionInstallDate"]);
            const lastMilestone = storage.lastDonationBannerMilestone || 0;
            let installDate = storage.extensionInstallDate;
            
            if (!installDate) {
                installDate = Date.now();
                await browser.storage.local.set({ extensionInstallDate: installDate });
                return false; // No banner on first run
            }
            
            // Calculate days since installation and check if 14 days have passed since installation
            const daysSinceInstall = (Date.now() - installDate) / (1000 * 60 * 60 * 24);
            if (daysSinceInstall < FIRST_BANNER_DELAY_DAYS) {
                return false;
            }
            
            // Calculate the next milestone using the configurable threshold
            const nextMilestone = Math.floor(totalCleaned / DONATION_BANNER_MILESTONE) * DONATION_BANNER_MILESTONE;
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
