import threading
from scapy.all import sniff, IP, get_if_list
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import QHeaderView

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface  # Store the interface name
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


class NetworkAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.packet_list = []  # To store packets
        self.packet_capture_thread = None

    def init_ui(self):
        self.layout = QVBoxLayout()

        # Create button layout
        self.button_layout = QHBoxLayout()
        self.start_button = QPushButton('Start', self)
        self.stop_button = QPushButton('Stop', self)
        self.start_button.setFixedSize(100, 30)
        self.stop_button.setFixedSize(100, 30)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: lightgreen;
                border: 1px solid green;
            }
            QPushButton:hover {
                background-color: darkgreen;
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
        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)

        # Interface selection dropdown
        self.interface_dropdown = QComboBox(self)
        self.interfaces = get_if_list()  # Get available network interfaces
        self.interface_dropdown.addItems(self.interfaces)
        self.interface_dropdown.setFixedWidth(150)
        self.interface_label = QLabel('Select Interface: ')
        
        # Create control layout
        self.control_layout = QHBoxLayout()
        self.control_layout.addWidget(self.interface_label)
        self.control_layout.addWidget(self.interface_dropdown)
        
        # Filter options (for search by IP or Protocol)
        self.filter_dropdown = QComboBox(self)
        self.filter_dropdown.addItems(['IP', 'Protocol'])
        self.filter_dropdown.setFixedWidth(100)
        self.input_field = QLineEdit(self)
        self.input_field.setFixedWidth(150)
        self.search_button = QPushButton('Search', self)
        self.search_button.setFixedSize(50, 30)
        self.control_layout.addWidget(self.filter_dropdown)
        self.control_layout.addWidget(self.input_field)
        self.control_layout.addWidget(self.search_button)

        # Create table for packet display
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        
        # Packet count label
        self.packet_count_label = QLabel('Packet Count: 0')

        # Adding widgets to layout
        self.layout.addLayout(self.button_layout)
        self.layout.addLayout(self.control_layout)
        self.layout.addWidget(self.packet_table)
        self.layout.addWidget(self.packet_count_label)

        self.setLayout(self.layout)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.search_button.clicked.connect(self.search_traffic)

        # Timer for periodic UI updates
        self.ui_update_timer = QTimer()
        self.ui_update_timer.timeout.connect(self.update_ui)
        self.ui_update_timer.start(10)  # Update every 10 ms

    def start_capture(self):
        # Get the selected interface
        selected_iface = self.interface_dropdown.currentText()
        print(f"Starting capture on interface: {selected_iface}")

        # Start the packet capture thread on the selected interface
        self.packet_capture_thread = PacketCaptureThread(selected_iface)
        self.packet_capture_thread.packet_captured.connect(self.process_packet)
        self.packet_capture_thread.start()
        
        # Ensure UI is properly aligned
        self.update_ui()

    def stop_capture(self):
        # Stop the packet capture thread
        if self.packet_capture_thread:
            self.packet_capture_thread.stop()
            self.packet_capture_thread.quit()
            self.packet_capture_thread.wait()
            self.packet_capture_thread = None

    def process_packet(self, packet):
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            source_port = packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            destination_port = packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            protocol = packet[IP].proto
            self.packet_list.append([source_ip, destination_ip, source_port, destination_port, protocol])
            self.packet_table.scrollToBottom()

    def update_ui(self):
        # Update the table with packet details
        self.packet_table.setRowCount(len(self.packet_list))
        for row, packet in enumerate(self.packet_list):
            for col, item in enumerate(packet):
                item_widget = QTableWidgetItem(str(item))
                item_widget.setTextAlignment(Qt.AlignCenter)  # Center-align text
                self.packet_table.setItem(row, col, item_widget)

        # Ensure all columns have the same width and occupy full space
        header = self.packet_table.horizontalHeader()
        for i in range(self.packet_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)  # Stretch columns to fit available space

        # Force a layout update to ensure proper alignment
        self.packet_table.resizeColumnsToContents()

        # Update packet count label
        self.packet_count_label.setText(f'Packet Count: {len(self.packet_list)}')

        # Ensure proper alignment of all columns
        for i in range(self.packet_table.columnCount()):
            self.packet_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)


    def search_traffic(self):
        search_type = self.filter_dropdown.currentText()
        search_value = self.input_field.text()
        
        if not search_value:
            # If search value is empty, show all packets
            filtered_packets = self.packet_list
        else:
            # Filter packets based on the search type
            if search_type == 'IP':
                filtered_packets = [p for p in self.packet_list if search_value in p[0] or search_value in p[1]]
            elif search_type == 'Protocol':
                filtered_packets = [p for p in self.packet_list if search_value == str(p[4])]
            else:
                filtered_packets = self.packet_list  # Default case if search type is unknown

        # Update the table with filtered packets
        self.packet_table.setRowCount(len(filtered_packets))
        for row, packet in enumerate(filtered_packets):
            for col, item in enumerate(packet):
                item_widget = QTableWidgetItem(str(item))
                item_widget.setTextAlignment(Qt.AlignCenter)  # Center-align text
                self.packet_table.setItem(row, col, item_widget)
        
        # Ensure all columns have the same width and occupy full space
        header = self.packet_table.horizontalHeader()
        for i in range(self.packet_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
import psutil
from scapy.all import sniff, IP
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import QHeaderView

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface  # Store the interface name
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


class NetworkAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.packet_list = []  # To store packets
        self.packet_capture_thread = None

    def init_ui(self):
        self.layout = QVBoxLayout()

        # Create button layout
        self.button_layout = QHBoxLayout()
        self.start_button = QPushButton('Start', self)
        self.stop_button = QPushButton('Stop', self)
        self.start_button.setFixedSize(100, 30)
        self.stop_button.setFixedSize(100, 30)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: lightgreen;
                border: 1px solid green;
            }
            QPushButton:hover {
                background-color: darkgreen;
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
        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)

        # Interface selection dropdown
        self.interface_dropdown = QComboBox(self)
        self.interfaces, self.interface_map = self.get_interfaces()  # Get human-readable names
        self.interface_dropdown.addItems(self.interfaces)
        self.interface_dropdown.setFixedWidth(150)
        self.interface_label = QLabel('Select Interface: ')
        
        # Create control layout
        self.control_layout = QHBoxLayout()
        self.control_layout.addWidget(self.interface_label)
        self.control_layout.addWidget(self.interface_dropdown)
        
        # Filter options (for search by IP or Protocol)
        self.filter_dropdown = QComboBox(self)
        self.filter_dropdown.addItems(['IP', 'Protocol'])
        self.filter_dropdown.setFixedWidth(100)
        self.input_field = QLineEdit(self)
        self.input_field.setFixedWidth(150)
        self.search_button = QPushButton('Search', self)
        self.search_button.setFixedSize(50, 30)
        self.control_layout.addWidget(self.filter_dropdown)
        self.control_layout.addWidget(self.input_field)
        self.control_layout.addWidget(self.search_button)

        # Create table for packet display
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        
        # Packet count label
        self.packet_count_label = QLabel('Packet Count: 0')

        # Adding widgets to layout
        self.layout.addLayout(self.button_layout)
        self.layout.addLayout(self.control_layout)
        self.layout.addWidget(self.packet_table)
        self.layout.addWidget(self.packet_count_label)

        self.setLayout(self.layout)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.search_button.clicked.connect(self.search_traffic)

        # Timer for periodic UI updates
        self.ui_update_timer = QTimer()
        self.ui_update_timer.timeout.connect(self.update_ui)
        self.ui_update_timer.start(10)  # Update every 10 ms

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

    def start_capture(self):
        # Get the selected interface (human-readable) and map to actual interface
        selected_iface = self.interface_map[self.interface_dropdown.currentText()]
        print(f"Starting capture on interface: {selected_iface}")

        # Start the packet capture thread on the selected interface
        self.packet_capture_thread = PacketCaptureThread(selected_iface)
        self.packet_capture_thread.packet_captured.connect(self.process_packet)
        self.packet_capture_thread.start()
        
        # Ensure UI is properly aligned
        self.update_ui()

    def stop_capture(self):
        # Stop the packet capture thread
        if self.packet_capture_thread:
            self.packet_capture_thread.stop()
            self.packet_capture_thread.quit()
            self.packet_capture_thread.wait()
            self.packet_capture_thread = None

    def process_packet(self, packet):
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            source_port = packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            destination_port = packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            protocol = packet[IP].proto
            self.packet_list.append([source_ip, destination_ip, source_port, destination_port, protocol])
            self.packet_table.scrollToBottom()

    def update_ui(self):
        # Update the table with packet details
        self.packet_table.setRowCount(len(self.packet_list))
        for row, packet in enumerate(self.packet_list):
            for col, item in enumerate(packet):
                item_widget = QTableWidgetItem(str(item))
                item_widget.setTextAlignment(Qt.AlignCenter)  # Center-align text
                self.packet_table.setItem(row, col, item_widget)

        # Ensure all columns have the same width and occupy full space
        header = self.packet_table.horizontalHeader()
        for i in range(self.packet_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)  # Stretch columns to fit available space

        # Force a layout update to ensure proper alignment
        self.packet_table.resizeColumnsToContents()

        # Update packet count label
        self.packet_count_label.setText(f'Packet Count: {len(self.packet_list)}')

        # Ensure proper alignment of all columns
        for i in range(self.packet_table.columnCount()):
            self.packet_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)


    def search_traffic(self):
        search_type = self.filter_dropdown.currentText()
        search_value = self.input_field.text()
        
        if not search_value:
            # If search value is empty, show all packets
            filtered_packets = self.packet_list
        else:
            # Filter packets based on the search type
            if search_type == 'IP':
                filtered_packets = [p for p in self.packet_list if search_value in p[0] or search_value in p[1]]
            elif search_type == 'Protocol':
                filtered_packets = [p for p in self.packet_list if search_value == str(p[4])]
            else:
                filtered_packets = self.packet_list  # Default case if search type is unknown

        # Update the table with filtered packets
        self.packet_table.setRowCount(len(filtered_packets))
        for row, packet in enumerate(filtered_packets):
            for col, item in enumerate(packet):
                item_widget = QTableWidgetItem(str(item))
                item_widget.setTextAlignment(Qt.AlignCenter)  # Center-align text
                self.packet_table.setItem(row, col, item_widget)
        
        # Ensure all columns have the same width and occupy full space
        header = self.packet_table.horizontalHeader()
        for i in range(self.packet_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.Stretch)

# Main application code goes here
