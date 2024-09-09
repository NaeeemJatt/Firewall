import sys
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt, QTimer
from scapy.all import sniff, IP, TCP, UDP

class FirewallApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Initialize packet count and sniffing flag before UI
        self.packet_count = 0
        self.sniffing = False

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Python Firewall')
        self.setGeometry(100, 100, 800, 400)

        # Main Layout
        self.layout = QVBoxLayout()

        # Label
        self.label = QLabel("Choose an action:", self)
        self.layout.addWidget(self.label)

        # Button for Network Analysis
        self.analyze_button = QPushButton("Start Analyzing Network", self)
        self.analyze_button.clicked.connect(self.start_sniffing_thread)
        self.layout.addWidget(self.analyze_button)

        # Stop Button
        self.stop_button = QPushButton("Stop Capturing", self)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        self.layout.addWidget(self.stop_button)

        # Button to Save Data
        self.save_button = QPushButton("Save Captured Data", self)
        self.save_button.clicked.connect(self.save_data)
        self.layout.addWidget(self.save_button)

        # Table to display captured packets
        self.packet_table = QTableWidget(self)
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"])
        self.layout.addWidget(self.packet_table)

        # Set equal column widths
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        # Center align the text in columns
        self.packet_table.setStyleSheet("QTableWidget::item { text-align: center; }")

        # Packet count label
        self.packet_count_label = QLabel(f"Packets Captured: {self.packet_count}", self)
        self.layout.addWidget(self.packet_count_label)

        # Set layout
        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

        # Timer for regular updates to avoid blocking the event loop
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_ui)

    def start_sniffing_thread(self):
        self.label.setText("Capturing network traffic...")
        self.sniffing = True
        self.analyze_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Start sniffing traffic in a separate thread
        self.sniffing_thread = threading.Thread(target=self.analyze_network)
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()
        # Start the timer
        self.timer.start(100)

    def analyze_network(self):
        # Start sniffing traffic and pass each packet to process_packet for processing
        sniff(prn=self.process_packet, store=0, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        if not self.sniffing:
            return

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

            # Add packet info to the table
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

            # Increment packet count
            self.packet_count += 1
            self.packet_count_label.setText(f"Packets Captured: {self.packet_count}")


    def update_ui(self):
        # Scroll to the bottom to show the latest packet
        if self.packet_table.rowCount() > 0:
            self.packet_table.verticalScrollBar().setValue(self.packet_table.verticalScrollBar().maximum())

    def stop_sniffing(self):
        self.sniffing = False
        self.analyze_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.label.setText("Stopped capturing packets.")
        # Stop the timer
        self.timer.stop()

    def save_data(self):
        with open('captured_packets.txt', 'w') as f:
            for row in range(self.packet_table.rowCount()):
                row_data = []
                for column in range(self.packet_table.columnCount()):
                    item = self.packet_table.item(row, column)
                    row_data.append(item.text() if item else '')
                f.write("\t".join(row_data) + "\n")
        self.label.setText("Data saved to captured_packets.txt")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    firewall = FirewallApp()
    firewall.show()
    sys.exit(app.exec_())
