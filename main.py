import sys
from PyQt5.QtWidgets import QApplication
from gui import FirewallApp

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FirewallApp()  # Initialize the GUI
    window.show()  # Show the GUI
    sys.exit(app.exec_())  # Start the application loop
