from PyQt5.QtWidgets import QMainWindow, QMenuBar, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QPushButton
from PyQt5.QtCore import QTimer
from Network_Analyzer import NetworkAnalyzer
from Website_blocker import WebsiteBlocker

class FirewallApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Packet Analyzer and Website Blocker will be used across layouts
        self.network_analyzer = NetworkAnalyzer()
        self.website_blocker = WebsiteBlocker()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Firewall')
        self.setGeometry(100, 100, 900, 500)

        # Create Menu Bar
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)

        # Create central widget and layout for the window
        container = QWidget(self)
        self.setCentralWidget(container)

        # Define a layout for the central widget
        self.layout = QVBoxLayout(container)

        # Add a horizontal layout for Network Analyzer and Website Blocker buttons
        self.button_layout = QHBoxLayout()

        self.analyze_network_button = QPushButton("Analyze Network", self)
        self.analyze_network_button.setFixedHeight(50)
        self.analyze_network_button.setFixedWidth(450)
        self.analyze_network_button.clicked.connect(self.show_network_analyzer)
        self.button_layout.addWidget(self.analyze_network_button)

        self.block_website_button = QPushButton("Block Website", self)
        self.block_website_button.setFixedHeight(50)
        self.block_website_button.setFixedWidth(450)
        self.block_website_button.clicked.connect(self.show_block_website)
        self.button_layout.addWidget(self.block_website_button)

        self.layout.addLayout(self.button_layout)

        # Start with Network Analyzer layout
        self.network_analyzer_layout()

    def network_analyzer_layout(self):
        self.network_analyzer.create_layout(self.layout)

    def block_website_layout(self):
        self.website_blocker.create_layout(self.layout)

    def show_network_analyzer(self):
        self.network_analyzer_layout()

    def show_block_website(self):
        self.block_website_layout()
