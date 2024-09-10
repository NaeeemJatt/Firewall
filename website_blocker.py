from PyQt5.QtWidgets import QLabel, QPushButton, QLineEdit, QVBoxLayout, QMessageBox
import subprocess

class WebsiteBlocker:
    def __init__(self):
        pass

    def create_layout(self, layout):
        layout.clear()  # Clear the layout
        self.label = QLabel("Enter the website domain to block:", layout.parentWidget())
        layout.addWidget(self.label)

        self.website_input = QLineEdit(layout.parentWidget())
        layout.addWidget(self.website_input)

        self.block_button = QPushButton("Block Website", layout.parentWidget())
        self.block_button.clicked.connect(self.block_website)
        layout.addWidget(self.block_button)

    def block_website(self):
        domain = self.website_input.text().strip()

        if domain:
            try:
                with open("/etc/hosts", "a") as hosts_file:
                    hosts_file.write(f"127.0.0.1 {domain}\n")
                QMessageBox.information(None, "Success", f"{domain} has been blocked.")
            except PermissionError:
                QMessageBox.critical(None, "Error", "Administrator privileges are required to block websites.")
            except Exception as e:
                QMessageBox.critical(None, "Error", f"An error occurred: {str(e)}")
        else:
            QMessageBox.warning(None, "Warning", "Please enter a valid domain.")
