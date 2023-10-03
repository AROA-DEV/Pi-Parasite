1. **Install Fail2ban:**
   Start by updating the package list and installing Fail2ban:
   ```shell
   sudo apt update
   sudo apt install fail2ban
   ```

2. **Copy the Default Configuration:**
   Create a local copy of the Fail2ban configuration file to avoid making changes to the original:
   ```shell
   sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
   ```

3. **Edit the Configuration File:**
   Open the `jail.local` file in your preferred text editor:
   ```shell
   sudo nano /etc/fail2ban/jail.local
   ```

   In this file, you can customize the Fail2ban settings based on your needs. Below are some common configurations:

   - **Banning Settings:**
     By default, Fail2ban bans an IP address for 10 minutes after 3 failed login attempts. You can adjust these values as follows:
     ```shell
     [DEFAULT]
     bantime = 3600  # Set the ban time to 1 hour (in seconds)
     maxretry = 3   # Set the maximum number of retries before banning
     ```

   - **Whitelist Trusted IP Addresses:**
     If you have trusted IP addresses that should never be banned, you can add them to the `[DEFAULT]` section:
     ```shell
     [DEFAULT]
     ignoreip = 192.168.1.1  # Replace with your trusted IP addresses
     ```

   - **Service-Specific Settings:**
     You can customize settings for specific services (e.g., SSH) by adding sections like `[sshd]` with their respective settings.

   Save the file and exit the text editor.

4. **Restart Fail2ban:**
   Restart the Fail2ban service to apply your configuration changes:
   ```shell
   sudo systemctl restart fail2ban
   ```

5. **Check Fail2ban Status:**
   To check the status of Fail2ban and view the currently banned IP addresses, you can use the following command:
   ```shell
   sudo fail2ban-client status
   ```

   This will display a list of jails and the number of banned IP addresses.