import threading
from scapy.all import sniff, IP
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
import psutil
from PyQt5.QtWidgets import QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt


# Class for capturing packets in a separate thread
class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.stop_event = threading.Event()

    def run(self):
        sniff(iface=self.iface, prn=self.process_packet, stop_filter=self.should_stop_sniff)

    def process_packet(self, packet):
        if IP in packet:
            self.packet_captured.emit(packet)

    def should_stop_sniff(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        self.stop_event.set()

# Main UI for network analyzer
class NetworkAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.packet_list = []  # Stores all captured packets
        self.packet_capture_thread = None  # Will hold the capture thread
        self.search_table = None  # Holds the reference to the search results table
        self.interface_map = {}  # Mapping of interface friendly names to actual network interfaces
        self.init_ui()

    # Initialize the UI elements
    def init_ui(self):
        self.layout = QVBoxLayout()

        # Set up the button layout
        self.button_layout = QHBoxLayout()
        self.start_button = QPushButton('Start', self)
        self.stop_button = QPushButton('Stop', self)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: lightgreen;
                border: 1px solid black;
            }
            QPushButton:hover {
                background-color: red;
                color: white;
            }
        """)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: lightcoral;
                border: 1px solid red;
            }
            QPushButton:hover {
                background-color: darkred;
                color: white;
            }
        """)
        self.setup_buttons()



        # Interface selection dropdown
        self.interface_dropdown = QComboBox(self)
        self.interfaces, self.interface_map = self.get_interfaces()
        self.interface_dropdown.addItems(self.interfaces)
        self.interface_label = QLabel('Select Interface: ')

        # Control layout (interface selection, search options)
        self.control_layout = QHBoxLayout()
        self.setup_controls()

        # Create the table for packet display
        self.packet_table = self.setup_packet_table()
        self.packet_count_label = QLabel('Packet Count: 0')

        # Search result table
        self.search_table = self.setup_search_table()

        # Add widgets to layout
        self.layout.addLayout(self.button_layout)
        self.layout.addLayout(self.control_layout)
        self.layout.addWidget(self.packet_table)
        self.layout.addWidget(self.search_table)
        self.layout.addWidget(self.packet_count_label)
        self.setLayout(self.layout)

        # Timer for periodic UI updates
        self.ui_update_timer = QTimer()
        self.ui_update_timer.timeout.connect(self.update_ui)
        self.ui_update_timer.start(10)  # Updates every 10 ms

    # Setup packet capture start and stop buttons
    def setup_buttons(self):
        self.start_button.setFixedSize(100, 30)
        self.stop_button.setFixedSize(100, 30)
        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)

    # Setup control panel (interface dropdown, search box)
    def setup_controls(self):
        self.filter_dropdown = QComboBox(self)
        self.filter_dropdown.addItems(['IP', 'Protocol'])
        self.input_field = QLineEdit(self)
        #self.input_field.setFixedWidth(250)
        self.search_button = QPushButton('Search', self)
        self.search_button.setFixedSize(100,30)
        self.search_button.setStyleSheet("""
            QPushButton {
                background-color: lightgreen;
                border: 1px solid blue;
            }
            QPushButton:hover {
                background-color: zinc;
                color: white;
            }
        """)
        self.control_layout.addWidget(self.interface_label)
        self.control_layout.addWidget(self.interface_dropdown)
        self.control_layout.addWidget(self.filter_dropdown)
        self.control_layout.addWidget(self.input_field)
        self.control_layout.addWidget(self.search_button)

        # Connect search button to search function
        self.search_button.clicked.connect(self.search_traffic)

    # Create table for displaying packets
    def setup_packet_table(self):
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])
        table.horizontalHeader().setStretchLastSection(True)
        return table

    # Create a search table for displaying filtered packets
    def setup_search_table(self):
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])
        table.horizontalHeader().setStretchLastSection(True)
        table.setVisible(False)  # Hide initially
        return table

    # Start capturing packets
    def start_capture(self):
        selected_iface = self.interface_map[self.interface_dropdown.currentText()]
        print(f"Starting capture on interface: {selected_iface}")

        self.packet_capture_thread = PacketCaptureThread(selected_iface)
        self.packet_capture_thread.packet_captured.connect(self.process_packet)
        self.packet_capture_thread.start()

    # Stop packet capture
    def stop_capture(self):
        if self.packet_capture_thread:
            self.packet_capture_thread.stop()
            self.packet_capture_thread.quit()
            self.packet_capture_thread.wait()
            self.packet_capture_thread = None

    # Process captured packet and add to list
    def process_packet(self, packet):
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            source_port = packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            destination_port = packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            protocol = packet[IP].proto
            self.packet_list.append([source_ip, destination_ip, source_port, destination_port, protocol])
            self.packet_table.scrollToBottom()

    # Search packets based on user input
    def search_traffic(self):
        search_type = self.filter_dropdown.currentText()
        search_value = self.input_field.text().strip()

        if not search_value:
            self.packet_table.setVisible(True)
            self.search_table.setVisible(False)
            self.update_ui()  # Show all packets
        else:
            filtered_packets = []
            if search_type == 'IP':
                filtered_packets = [p for p in self.packet_list if search_value in p[0] or search_value in p[1]]
            elif search_type == 'Protocol':
                filtered_packets = [p for p in self.packet_list if search_value == str(p[4])]

            self.update_search_table(filtered_packets)

    # Update search table with filtered packets
    def update_search_table(self, filtered_packets):
        self.search_table.setRowCount(len(filtered_packets))
        for row, packet in enumerate(filtered_packets):
            for col, item in enumerate(packet):
                item_widget = QTableWidgetItem(str(item))
                item_widget.setTextAlignment(Qt.AlignCenter)
                self.search_table.setItem(row, col, item_widget)

        self.packet_table.setVisible(False)
        self.search_table.setVisible(True)

    # Periodically update the main packet table
    def update_ui(self):
        # Update the table with packet details
        self.packet_table.setRowCount(len(self.packet_list))
        for row, packet in enumerate(self.packet_list):
            for col, item in enumerate(packet):
                item_widget = QTableWidgetItem(str(item))
                item_widget.setTextAlignment(Qt.AlignCenter)  # Center-align text
                self.packet_table.setItem(row, col, item_widget)

        # Ensure all columns have the same width and occupy full space equally
        header = self.packet_table.horizontalHeader()
        for i in range(self.packet_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)  # Make all columns the same width
        
        # Update packet count label
        self.packet_count_label.setText(f'Packet Count: {len(self.packet_list)}')

        # Update search table layout if visible
        if self.search_table.isVisible():
            self.search_table.setRowCount(len(self.packet_list))
            for row, packet in enumerate(self.packet_list):
                for col, item in enumerate(packet):
                    item_widget = QTableWidgetItem(str(item))
                    item_widget.setTextAlignment(Qt.AlignCenter)  # Center-align text
                    self.search_table.setItem(row, col, item_widget)
            
            header = self.search_table.horizontalHeader()
            for i in range(self.search_table.columnCount()):
                header.setSectionResizeMode(i, QHeaderView.Stretch)  # Make all columns the same width

    # Get network interfaces with friendly names
    def get_interfaces(self):
        """Fetch user-friendly interface names."""
        interfaces = []
        interface_map = {}
        for iface_name, iface_addresses in psutil.net_if_addrs().items():
            # Check for "Wi-Fi" or "Ethernet" keywords in the name
            if "Wi-Fi" in iface_name or "wlan" in iface_name.lower():
                human_readable_name = "Wi-Fi"
            elif "Ethernet" in iface_name or "eth" in iface_name.lower():
                human_readable_name = "Ethernet"
            else:
                human_readable_name = iface_name

            # Add to the dropdown list and create a map for reference
            interfaces.append(human_readable_name)
            interface_map[human_readable_name] = iface_name  # Map human-readable names to actual interface names

        return interfaces, interface_map


        return interfaces, interface_map
