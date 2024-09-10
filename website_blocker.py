# website_blocker.py
import os

class WebsiteBlocker:
    def __init__(self):
        self.hosts_file = "/etc/hosts"  # Path for hosts file
        self.redirect_ip = "127.0.0.1"

    def block_websites(self, websites):
        with open(self.hosts_file, 'a') as file:
            for website in websites:
                file.write(f"{self.redirect_ip} {website}\n")
        print(f"Blocked websites: {', '.join(websites)}")

    def unblock_websites(self, websites):
        with open(self.hosts_file, 'r') as file:
            lines = file.readlines()
        with open(self.hosts_file, 'w') as file:
            for line in lines:
                if not any(website in line for website in websites):
                    file.write(line)
        print(f"Unblocked websites: {', '.join(websites)}")
