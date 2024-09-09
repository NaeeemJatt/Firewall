import sys
import subprocess  # To run firewall commands
import json
import csv
from PyQt5.QtWidgets import QApplication, QMainWindow, QMenuBar, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog, QComboBox, QFileDialog
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from scapy.all import sniff, IP, TCP, UDP


class SnifferThread(QThread):
    packet_signal = pyqtSignal(object)  # Signal to send packets to the main thread

    def __init__(self):
        super().__init__()
        self.sniffing = True

    def run(self):
        sniff(prn=self.emit_packet, store=0, stop_filter=lambda x: not self.sniffing)

    def emit_packet(self, packet):
        if self.sniffing:
            self.packet_signal.emit(packet)

    def stop(self):
        self.sniffing = False


class FirewallApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize packet count and sniffing flag before UI
        self.packet_count = 0
        self.sniffer_thread = None  # To handle the thread for packet sniffing

        # Store captured packets for filtering
        self.captured_packets = []

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Python Firewall')
        self.setGeometry(100, 100, 800, 500)

        # Create Menu Bar
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)

        # Create central widget and layout for the window
        container = QWidget(self)
        self.setCentralWidget(container)

        # Define a layout for the central widget
        self.layout = QVBoxLayout(container)

        # Add a horizontal layout for AN and BW buttons
        self.button_layout = QHBoxLayout()

        # Add buttons for Analyze Network and Block Website with larger sizes
        self.analyze_network_button = QPushButton("Analyze Network", self)
        self.analyze_network_button.setFixedHeight(50)
        self.analyze_network_button.setFixedWidth(350)  # Make it large
        self.analyze_network_button.clicked.connect(self.show_network_analyzer)
        self.button_layout.addWidget(self.analyze_network_button)

        self.block_website_button = QPushButton("Block Website", self)
        self.block_website_button.setFixedHeight(50)
        self.block_website_button.setFixedWidth(350)  # Make it large
        self.block_website_button.clicked.connect(self.show_block_website)
        self.button_layout.addWidget(self.block_website_button)

        # Add the horizontal button layout to the main layout
        self.layout.addLayout(self.button_layout)

        # Set the layout for the network analyzer initially
        self.network_analyzer_layout()

        # Timer for regular updates to avoid blocking the event loop
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_ui)

    def network_analyzer_layout(self):
        # Clear previous layout
        for i in reversed(range(self.layout.count())):
            widget = self.layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        # Main Layout
        self.label = QLabel("Choose an action:", self)
        self.layout.addWidget(self.label)

        self.analyze_button = QPushButton("Start Analyzing Network", self)
        self.analyze_button.clicked.connect(self.start_sniffing_thread)
        self.layout.addWidget(self.analyze_button)

        self.stop_button = QPushButton("Stop Capturing", self)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        self.layout.addWidget(self.stop_button)

        self.save_button = QPushButton("Save Captured Data", self)
        self.save_button.clicked.connect(self.save_data)
        self.layout.addWidget(self.save_button)

        self.block_ip_button = QPushButton("Block IP", self)
        self.block_ip_button.clicked.connect(self.block_ip)
        self.layout.addWidget(self.block_ip_button)

        self.search_label = QLabel("Search Packets:", self)
        self.layout.addWidget(self.search_label)

        self.search_input = QLineEdit(self)
        self.search_input.textChanged.connect(self.search_packets)
        self.layout.addWidget(self.search_input)

        self.search_criteria = QComboBox(self)
        self.search_criteria.addItems(["Search by IP", "Search by Protocol"])
        self.layout.addWidget(self.search_criteria)

        self.packet_table = QTableWidget(self)
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"])
        self.layout.addWidget(self.packet_table)

        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        self.packet_table.setStyleSheet("QTableWidget::item { text-align: center; }")

        self.packet_count_label = QLabel(f"Packets Captured: {self.packet_count}", self)
        self.layout.addWidget(self.packet_count_label)

    def block_website_layout(self):
        # Clear previous layout
        for i in reversed(range(self.layout.count())):
            widget = self.layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        # Label
        self.label = QLabel("Enter the website domain to block:", self)
        self.layout.addWidget(self.label)

        # Input for the domain
        self.website_input = QLineEdit(self)
        self.layout.addWidget(self.website_input)

        # Block Button
        self.block_button = QPushButton("Block Website", self)
        self.block_button.clicked.connect(self.block_website)
        self.layout.addWidget(self.block_button)

    def start_sniffing_thread(self):
        self.label.setText("Capturing network traffic...")
        self.analyze_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        # Create and start the sniffer thread
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_signal.connect(self.process_packet)
        self.sniffer_thread.start()

        # Start the timer
        self.timer.start(100)

    def process_packet(self, packet):
        # Filter for IP packets and display Source IP, Destination IP, Source Port, Destination Port, and Protocol
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Check for TCP or UDP layer to extract ports
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "UDP"
            else:
                src_port = "N/A"
                dst_port = "N/A"
                protocol = "Other"

            # Save the packet data for searching/filtering
            self.captured_packets.append((src_ip, dst_ip, src_port, dst_port, protocol))

            # Add packet info to the table
            self.add_packet_to_table(src_ip, dst_ip, src_port, dst_port, protocol)

            # Increment packet count
            self.packet_count += 1
            self.packet_count_label.setText(f"Packets Captured: {self.packet_count}")

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.packet_signal.disconnect(self.process_packet)  # Disconnect the signal to avoid UI issues
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()  # Ensure the thread stops before proceeding

        self.analyze_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.label.setText("Stopped capturing network traffic.")


    def add_packet_to_table(self, src_ip, dst_ip, src_port, dst_port, protocol):
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)  # Insert at the bottom

        # Insert the correct data into the corresponding columns
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(src_ip))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(dst_ip))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(str(src_port)))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(str(dst_port)))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(protocol))

        # Center align the newly added items
        for i in range(5):
            item = self.packet_table.item(row_position, i)
            item.setTextAlignment(Qt.AlignCenter)

        # Scroll to the newly added row to show the latest packet
        self.packet_table.scrollToBottom()

    def block_ip(self):
        ip, ok = QInputDialog.getText(self, 'Block IP', 'Enter IP address to block:')
        if ok and ip:
            try:
                # Assuming Windows. For Linux, use `iptables`
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=Block {ip}', f'dir=in', f'action=block', f'remoteip={ip}'], check=True)
                self.label.setText(f"Blocked IP: {ip}")
            except Exception as e:
                self.label.setText(f"Error blocking IP: {str(e)}")

    def block_website(self):
        domain = self.website_input.text()
        if domain:
            try:
                # Blocking the website for the entire network using DNS filtering
                # For Linux: use `iptables` rules, for Windows a different approach might be needed
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=Block {domain}', f'dir=out', f'action=block', f'remoteip={domain}'], check=True)
                self.label.setText(f"Blocked website: {domain}")
            except Exception as e:
                self.label.setText(f"Error blocking website: {str(e)}")

    def save_data(self):
        # Let user choose CSV or JSON
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Data", "", "CSV Files (*.csv);;JSON Files (*.json)")
        if file_name:
            if file_name.endswith(".csv"):
                with open(file_name, "w", newline="") as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"])
                    writer.writerows(self.captured_packets)
            elif file_name.endswith(".json"):
                with open(file_name, "w") as json_file:
                    json.dump(self.captured_packets, json_file)

            self.label.setText(f"Data saved to {file_name}")

    def search_packets(self):
        query = self.search_input.text().lower()
        search_by = self.search_criteria.currentText()

        # Clear the table before showing search results
        self.packet_table.setRowCount(0)

        if search_by == "Search by IP":
            for packet in self.captured_packets:
                if query in packet[0].lower() or query in packet[1].lower():
                    self.add_packet_to_table(*packet)
        elif search_by == "Search by Protocol":
            for packet in self.captured_packets:
                if query in packet[4].lower():
                    self.add_packet_to_table(*packet)

    def update_ui(self):
        self.packet_count_label.setText(f"Packets Captured: {self.packet_count}")

    def show_network_analyzer(self):
        self.stop_sniffing_if_needed()  # Stop sniffing before switching layout
        self.network_analyzer_layout()

    def show_block_website(self):
        self.stop_sniffing_if_needed()  # Stop sniffing before switching layout
        self.block_website_layout()

    def stop_sniffing_if_needed(self):
        """ Stop the sniffer thread if it's running """
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.stop_sniffing()



if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FirewallApp()
    window.show()
    sys.exit(app.exec_())
