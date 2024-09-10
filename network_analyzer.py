from PyQt5.QtWidgets import QLabel, QPushButton, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QVBoxLayout, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt, QTimer
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from SnifferThread import SnifferThread
import csv
import json

class NetworkAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.sniffer_thread = None
        self.captured_packets = []
        self.timer = QTimer()
    def update_ui(self):
        # Update any UI elements that need refreshing
        self.packet_count_label.setText(f"Packets Captured: {self.packet_count}")

    def create_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.label = QLabel("Choose an action:", layout.parentWidget())
        layout.addWidget(self.label)

        self.analyze_button = QPushButton("Start Analyzing Network", layout.parentWidget())
        self.analyze_button.clicked.connect(self.start_sniffing_thread)
        layout.addWidget(self.analyze_button)

        self.stop_button = QPushButton("Stop Capturing", layout.parentWidget())
        self.stop_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_button)

        self.save_button = QPushButton("Save Captured Data", layout.parentWidget())
        self.save_button.clicked.connect(self.save_data)
        layout.addWidget(self.save_button)

        self.search_input = QLineEdit(layout.parentWidget())
        layout.addWidget(self.search_input)

        self.search_criteria = QComboBox(layout.parentWidget())
        self.search_criteria.addItems(["Search by IP", "Search by Protocol"])
        layout.addWidget(self.search_criteria)

        self.packet_table = QTableWidget(layout.parentWidget())
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Subprotocol"])
        layout.addWidget(self.packet_table)

        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        self.packet_count_label = QLabel(f"Packets Captured: {self.packet_count}", layout.parentWidget())
        layout.addWidget(self.packet_count_label)

        # Timer for regular updates
        self.timer.timeout.connect(self.update_ui)

    def start_sniffing_thread(self):
        self.packet_count = 0  # Reset packet counter
        self.captured_packets.clear()  # Clear captured packets
        self.label.setText("Capturing network traffic...")

        # Create and start the sniffer thread
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_signal.connect(self.process_packet)
        self.sniffer_thread.start()

        self.timer.start(100)

    def process_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol, src_port, dst_port, subprotocol = self.extract_packet_info(packet)
            self.captured_packets.append((src_ip, dst_ip, src_port, dst_port, protocol, subprotocol))
            self.add_packet_to_table(src_ip, dst_ip, src_port, dst_port, protocol, subprotocol)
            self.packet_count += 1
            self.packet_count_label.setText(f"Packets Captured: {self.packet_count}")

    def extract_packet_info(self, packet):
        if packet.haslayer(TCP):
            return "TCP", packet[TCP].sport, packet[TCP].dport, "HTTP" if packet.haslayer(Raw) else "Other"
        elif packet.haslayer(UDP):
            return "UDP", packet[UDP].sport, packet[UDP].dport, "DNS" if packet.haslayer(DNS) else "Other"
        else:
            return "Other", "N/A", "N/A", "N/A"

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.packet_signal.disconnect(self.process_packet)
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        self.analyze_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.label.setText("Stopped capturing network traffic.")
        self.timer.stop()

    def add_packet_to_table(self, src_ip, dst_ip, src_port, dst_port, protocol, subprotocol):
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(src_ip))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(dst_ip))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(str(src_port)))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(str(dst_port)))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(protocol))
        self.packet_table.setItem(row_position, 5, QTableWidgetItem(subprotocol))

    def save_data(self):
        file_name, _ = QFileDialog.getSaveFileName(None, "Save Data", "", "CSV Files (*.csv);;JSON Files (*.json);;TXT Files (*.txt)")
        if file_name.endswith(".csv"):
            with open(file_name, "w", newline="") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Subprotocol"])
                writer.writerows(self.captured_packets)
        elif file_name.endswith(".json"):
            with open(file_name, "w") as json_file:
                json.dump(self.captured_packets, json_file)
