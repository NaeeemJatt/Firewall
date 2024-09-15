import threading
import json
import csv
from scapy.all import sniff, IP
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
import psutil
from PyQt5.QtWidgets import QHeaderView


# Class for capturing packets in a separate thread
class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.stop_event = threading.Event()  # Event to signal stop

    def run(self):
        print("Capture started on interface:", self.iface)  # Debug log
        sniff(iface=self.iface, prn=self.process_packet, stop_filter=self.should_stop_sniff)

    def process_packet(self, packet):
        if IP in packet:
            self.packet_captured.emit(packet)

    def should_stop_sniff(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        print("Stop event triggered.")  # Debug log
        self.stop_event.set()  # Signal the stop event


# Main UI for network analyzer
class NetworkAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.packet_list = []  # Stores all captured packets
        self.packet_capture_thread = None  # Will hold the capture thread
        self.interface_map = {}  # Mapping of interface friendly names to actual network interfaces
        self.packet_saved = False  # Tracks if packets are saved
        self.init_ui()

    # Initialize the UI elements
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

        # Move Save button into dropdown's position
        self.save_button = QPushButton('Save File', self)
        self.save_button.setFixedSize(100, 30)
        self.save_button.clicked.connect(self.save_file)

        # Interface selection dropdown (moved to the left side next to label)
        self.control_layout = QHBoxLayout()
        self.interface_dropdown = QComboBox(self)
        self.interface_dropdown.setFixedWidth(200)
        self.interfaces, self.interface_map = self.get_interfaces()
        self.interface_dropdown.addItems(self.interfaces)
        
        self.interface_label = QLabel('Select Interface: ')

        # Control layout (interface selection and Save File button)
        self.control_layout = QHBoxLayout()
        self.control_layout.addWidget(self.interface_label)
        self.control_layout.addWidget(self.interface_dropdown)  # Interface dropdown stays to the left
        
        # Add the Save button to the right side in place of dropdown
        self.control_layout.addWidget(self.save_button)

        # Add widgets to layout
        self.layout.addLayout(self.button_layout)
        self.layout.addLayout(self.control_layout)

        # Add the table for packet display and other components
        self.packet_table = self.setup_packet_table()
        self.packet_count_label = QLabel('Packet Count: 0')
        self.layout.addWidget(self.packet_table)
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

    # Setup control panel (interface dropdown)
    def setup_controls(self):
        self.control_layout.addWidget(self.interface_label)
        self.control_layout.addWidget(self.interface_dropdown)

    # Create table for displaying packets
    def setup_packet_table(self):
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])
        table.horizontalHeader().setStretchLastSection(True)
        return table


    # Start capturing packets
    def start_capture(self):
        if self.packet_list and not self.packet_saved:
            reply = QMessageBox.question(self, 'Save File', 'Do you want to save the captured packets before restarting?', QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.save_file()
            elif reply == QMessageBox.No:
                self.packet_list.clear()  # Clear the captured packets
                self.packet_table.setRowCount(0)  # Clear the table
                self.packet_count_label.setText('Packet Count: 0')  # Reset packet count label

        # Continue with starting the capture
        selected_iface = self.interface_map[self.interface_dropdown.currentText()]
        self.packet_capture_thread = PacketCaptureThread(selected_iface)
        self.packet_capture_thread.packet_captured.connect(self.process_packet)
        self.packet_capture_thread.start()


    def save_file(self):
        if not self.packet_list:
            self.show_message("No packets captured yet. Please capture packets first.")
            return

        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Packet File", "", "JSON Files (*.json);;CSV Files (*.csv);;PCAP Files (*.pcap)", options=options)

        if file_name:
            if file_name.endswith('.json'):
                self.save_as_json(file_name)
            elif file_name.endswith('.csv'):
                self.save_as_csv(file_name)
            elif file_name.endswith('.pcap'):
                self.save_as_pcap(file_name)

    def show_message(self, message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(message)
        msg.setWindowTitle("Information")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def save_as_json(self, file_name):
        with open(file_name, 'w') as f:
            json.dump(self.packet_list, f)

    def save_as_csv(self, file_name):
        with open(file_name, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])
            writer.writerows(self.packet_list)

    def save_as_pcap(self, file_name):
        # Implement logic to save as PCAP if needed
        pass

    # Stop packet capture
    def stop_capture(self):
        if self.packet_capture_thread:
            print("Stop button clicked, attempting to stop capture thread.")  # Debug log
            self.packet_capture_thread.stop()  # Signal the thread to stop
            self.packet_capture_thread.quit()  # Request the thread to quit
            self.packet_capture_thread.wait()  # Wait for the thread to finish
            self.packet_capture_thread = None
            print("Capture thread stopped.")  # Confirm thread has stopped

    # Process captured packet and add to list
    def process_packet(self, packet):
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            source_port = packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'
            destination_port = packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 'N/A'

            # Protocol identification
            protocol = 'Unknown'
            if packet.haslayer('TCP'):
                protocol = 'TCP'
                if packet.haslayer('HTTP'):
                    protocol = 'HTTP'
                elif packet.haslayer('TLS'):
                    protocol = 'TLS'
            elif packet.haslayer('UDP'):
                protocol = 'UDP'
                if packet.haslayer('DNS'):
                    protocol = 'DNS'
            elif packet.haslayer('ICMP'):
                protocol = 'ICMP'

            self.packet_list.append([source_ip, destination_ip, source_port, destination_port, protocol])
            self.packet_table.scrollToBottom()

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
