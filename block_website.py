import subprocess
import socket
from PyQt5.QtWidgets import QWidget, QLineEdit, QListWidget, QPushButton, QVBoxLayout, QMessageBox

class BlockWebsite(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Input field for domain to block
        self.domain_input = QLineEdit(self)
        self.domain_input.setPlaceholderText("Enter domain to block...")

        # List to show blocked websites
        self.blocked_websites_list = QListWidget(self)

        # Block button
        self.block_button = QPushButton("Block", self)
        self.block_button.clicked.connect(self.block_website)

        # Unblock button
        self.unblock_button = QPushButton("Unblock", self)
        self.unblock_button.clicked.connect(self.unblock_website)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.domain_input)
        layout.addWidget(self.block_button)
        layout.addWidget(self.blocked_websites_list)
        layout.addWidget(self.unblock_button)

        self.setLayout(layout)

    def block_website(self):
        # Get domain from input field
        domain = self.domain_input.text()
        if domain:
            try:
                ip = socket.gethostbyname(domain)
                rule_name = f"Block_{domain}"
                
                # Command to block the domain using Windows Firewall
                command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}'
                subprocess.run(command, shell=True, check=True)
                
                # Add to blocked websites list
                self.blocked_websites_list.addItem(domain)
                self.domain_input.clear()
                QMessageBox.information(self, "Success", f"Blocked {domain}")
            except socket.gaierror:
                QMessageBox.warning(self, "Error", "Invalid domain. Please check and try again.")
            except subprocess.CalledProcessError as e:
                QMessageBox.warning(self, "Error", f"Failed to block {domain}. {str(e)}")

    def unblock_website(self):
        # Remove selected domain from the blocked websites list
        selected_item = self.blocked_websites_list.currentItem()
        if selected_item:
            domain = selected_item.text()
            try:
                rule_name = f"Block_{domain}"
                
                # Command to remove the block from Windows Firewall
                command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(command, shell=True, check=True)
                
                self.blocked_websites_list.takeItem(self.blocked_websites_list.row(selected_item))
                QMessageBox.information(self, "Success", f"Unblocked {domain}")
            except subprocess.CalledProcessError as e:
                QMessageBox.warning(self, "Error", f"Failed to unblock {domain}. {str(e)}")
