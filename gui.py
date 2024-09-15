from PyQt5.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QStackedWidget
from network_analyzer import NetworkAnalyzer
from block_website import BlockWebsite  # Import BlockWebsite class

class FirewallGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Firewall Tool')
        self.setGeometry(100, 100, 800, 600)

        # Create the main layout
        self.main_layout = QVBoxLayout()

        # Create a horizontal layout for the top-left navigation buttons
        self.nav_layout = QHBoxLayout()

        # Create buttons for navigation
        self.btn_na = QPushButton('Network Analyzer', self)
        self.btn_na.setFixedSize(150, 50)
        self.btn_na.clicked.connect(self.show_network_analyzer)

        self.btn_bw = QPushButton('Block Website', self)
        self.btn_bw.setFixedSize(150, 50)
        self.btn_bw.clicked.connect(self.show_block_website)

        # Add navigation buttons to the nav layout
        self.nav_layout.addWidget(self.btn_na)
        self.nav_layout.addWidget(self.btn_bw)

        # Add nav layout to the main layout
        self.main_layout.addLayout(self.nav_layout)

        # Create a stacked widget to switch between Network Analyzer and Block Website screens
        self.stack = QStackedWidget(self)

        # Create instances of both screens
        self.network_analyzer_screen = NetworkAnalyzer()
        self.block_website_screen = BlockWebsite()  # Integrating BlockWebsite functionality

        # Add both screens to the stacked widget
        self.stack.addWidget(self.network_analyzer_screen)
        self.stack.addWidget(self.block_website_screen)

        # Add the stack to the main layout
        self.main_layout.addWidget(self.stack)

        # Set the layout
        self.setLayout(self.main_layout)

    def show_network_analyzer(self):
        # Show the Network Analyzer screen
        self.stack.setCurrentWidget(self.network_analyzer_screen)

    def show_block_website(self):
        # Show the Block Website screen
        self.stack.setCurrentWidget(self.block_website_screen)
