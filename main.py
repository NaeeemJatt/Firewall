# main.py
from PyQt5 import QtWidgets
import sys
from gui import FirewallUI
from network_analyzer import NetworkAnalyzer
from website_blocker import WebsiteBlocker

class FirewallApp:
    def __init__(self):
        self.network_analyzer = NetworkAnalyzer()
        self.website_blocker = WebsiteBlocker()

    def start_gui(self):
        app = QtWidgets.QApplication(sys.argv)
        window = FirewallUI()
        window.show()
        sys.exit(app.exec_())

    def analyze_network(self):
        self.network_analyzer.analyze_traffic()

    def block_websites(self, websites):
        self.website_blocker.block_websites(websites)

    def unblock_websites(self, websites):
        self.website_blocker.unblock_websites(websites)

if __name__ == "__main__":
    firewall_app = FirewallApp()
    firewall_app.start_gui()
