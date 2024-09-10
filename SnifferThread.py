from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff

class SnifferThread(QThread):
    packet_signal = pyqtSignal(object)  # Signal to send captured packets to the GUI

    def __init__(self, iface=None, filter=None):
        super().__init__()
        self.iface = iface  # Specify the network interface to sniff on (optional)
        self.filter = filter  # Set BPF filter (optional)
        self.sniffing = True  # Control variable to stop sniffing

    def run(self):
        # Start the packet sniffing process
        sniff(iface=self.iface, filter=self.filter, prn=self.emit_packet, stop_filter=self.stop_sniffing)

    def emit_packet(self, packet):
        if self.sniffing:
            self.packet_signal.emit(packet)  # Send packet to the connected slot in the GUI

    def stop(self):
        self.sniffing = False  # Stop sniffing

    def stop_sniffing(self, packet):
        # This method will stop sniffing if self.sniffing is set to False
        return not self.sniffing
