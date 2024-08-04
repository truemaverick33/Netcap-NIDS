import sys
import os
import socket
import struct
import subprocess
import geoip2.database
import geopandas as gpd
import matplotlib.pyplot as plt
import re
import binascii
import json
import pandas as pd
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas, NavigationToolbar2QT as MatplotlibToolbar
from datetime import datetime, timedelta
from PyQt6.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout, QWidget, QTabWidget, QLabel, QTextEdit, QTreeView, QPushButton
from PyQt6.QtGui import QIcon, QAction, QStandardItem, QStandardItemModel
from PyQt6.QtCore import QTimer, QThread, Qt, pyqtSignal
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
import pickle
import warnings
import requests
import operator

#------------Global Declarations-------------#

data_packets = []
capture_rate = 0
current_dir = os.path.dirname(os.path.realpath(__file__))
icon_path = os.path.join(current_dir, "static/favicon.ico")
stopped_icon_path = os.path.join(current_dir, "static/stopped.ico")
save_icon_path = os.path.join(current_dir, "static/save.ico")
le1_path = os.path.join(current_dir,"static/LE/sgdc_label_encoder1.pkl")
with open(le1_path, 'rb') as encoder_file:
    label_encoder1 = pickle.load(encoder_file)
le2_path = os.path.join(current_dir,"static/LE/sgdc_label_encoder2.pkl")
with open(le2_path, 'rb') as encoder_file:
    label_encoder2 = pickle.load(encoder_file)
le3_path = os.path.join(current_dir,"static/LE/sgdc_label_encoder3.pkl")
with open(le3_path, 'rb') as encoder_file:
    label_encoder3 = pickle.load(encoder_file)
le4_path = os.path.join(current_dir,"static/LE/sgdc_label_encoder4.pkl")
with open(le4_path, 'rb') as encoder_file:
    label_encoder4 = pickle.load(encoder_file)
le5_path = os.path.join(current_dir,"static/LE/sgdc_label_encoder5.pkl")
with open(le5_path, 'rb') as encoder_file:
    label_encoder5 = pickle.load(encoder_file)
scaler_path = os.path.join(current_dir,"static/Scaler/sgdc_scaler.pkl")
with open(scaler_path, 'rb') as encoder_file:
    scaler = pickle.load(encoder_file)
model_path = os.path.join(current_dir,"static/Model/sgdc_model.pkl")
with open(model_path, 'rb') as file:
    loaded_lr_model = pickle.load(file)

warnings.filterwarnings("ignore")

def get_public_ip():
    try:
        response = requests.get('https://httpbin.org/ip')
        return response.json()['origin']
    except Exception as e:
        print(f"Error: {e}")
        return None
        
public_ip = get_public_ip()        

#--------------------------------------------#

class PacketCaptureThread(QThread):

    packet_received = pyqtSignal(tuple)
    
    def __init__(self, parent=None):
        super(PacketCaptureThread, self).__init__(parent)
        self._stop_event = False
        self.interface_name = "ens33"
        self.eth_type_map = {
        "0800": 'IPv4',
        "86DD":'IPV6',
        "0806": 'ARP'
        }
        self.ip_protocol_map = {
        socket.IPPROTO_TCP: 'TCP',
        socket.IPPROTO_UDP: 'UDP',
        socket.IPPROTO_ICMP: 'ICMP'
        }
        self.tcp_flags_map = {
        1: 'FIN',
        2: 'SYN',
        4: 'RST',
        8: 'PSH',
        16: 'ACK',
        32: 'URG'
        }
        self.arp_opt_map = {
        1: 'Request',
        2: 'Reply',
        }
        self.imcp_type_map = {
        0:'Echo Reply',
        3:'Destination Unreachable',
        5:'Redirect Message',
        8:'Echo Request',
        11:'Time Exceeded',
        12:'Parameter Problem'
        }
        self.hardware_type_mapping = {
        1: "Ethernet",
        6: "IEEE 802 Networks",
        15: "Frame Relay",
        16: "Asynchronous Transfer Mode (ATM)",
        17: "HDLC (High-Level Data Link Control)"
        }
        
    
    def parse_eth(self,pkt=None):
        eth_header = pkt[:14]
        dest_mac = ':'.join('%02x' % byte for byte in eth_header[:6])
        src_mac = ':'.join('%02x' % byte for byte in eth_header[6:12])
        ethertype = self.eth_type_map.get(str(eth_header[12:14].hex()), 'Unknown')
        return  src_mac, dest_mac, ethertype
    
    def parse_ip(self,ip_header=None):
        src_ip = '.'.join(map(str, ip_header[12:16]))
        dest_ip = '.'.join(map(str, ip_header[16:20]))
        ip_proto = ip_header[9]
        protocol = self.ip_protocol_map.get(ip_proto, 'Unknown')
        fragmented = (ip_header[6] & 0x1) == 1
        return src_ip, dest_ip, protocol, fragmented
        
    def parse_arp(self,arp_header=None):
        hardware_type = self.hardware_type_mapping.get(int.from_bytes(arp_header[0:2], byteorder='big'), "Unknown")
        protocol_type = self.eth_type_map.get(str(binascii.hexlify(arp_header[2:4]).decode('ascii')), "Unknown")
        hardware_addr_length = int.from_bytes(arp_header[4:5], byteorder='big')
        protocol_addr_length = int.from_bytes(arp_header[5:6], byteorder='big')
        operation = self.arp_opt_map.get(int.from_bytes(arp_header[6:8], "big"), 'Unknown')
        sender_hw_addr = ':'.join('%02x' % byte for byte in arp_header[8:14])
        sender_ip_addr = '.'.join(map(str, arp_header[14:18]))
        target_hw_addr = ':'.join('%02x' % byte for byte in arp_header[18:24])
        target_ip_addr = '.'.join(map(str, arp_header[24:28]))
        return hardware_type, protocol_type, hardware_addr_length, protocol_addr_length, operation, sender_hw_addr, sender_ip_addr, target_hw_addr ,target_ip_addr   
    
    def get_flags(self,flags=None):
        tcp_flags = []
        for flag_value, flag_name in self.tcp_flags_map.items():
            if flags & flag_value:
                tcp_flags.append(flag_name)
        return tcp_flags
        
    def checksum(self,msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s
        
    def parse_tcp(self,tcp_header=None):
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        data_offset = (tcp_header[4] >> 4) * 4
        flags = self.get_flags(tcp_header[5])
        window = tcp_header[6]
        checksum = tcp_header[7]
        urg_ptr = tcp_header[8]
        return src_port, dest_port, seq_num, ack_num, data_offset, flags, window, checksum, urg_ptr
        
    def parse_udp(self,udp_header=None):
        udp_header = struct.unpack('!HHHH', udp_header)
        src_port = udp_header[0]
        dest_port = udp_header[1] 
        length = udp_header[2] 
        checksum = udp_header[3] 
        return src_port, dest_port, length, checksum
        
    def parse_icmp(self,icmp_header=None):
        icmp_header = struct.unpack('!BBH', icmp_header)
        icmp_type = self.imcp_type_map.get(icmp_header[0],'Unknown')
        icmp_code = icmp_header[1]
        icmp_checksum = icmp_header[2]
        return icmp_type, icmp_code, icmp_checksum
        
    def parse_data(self,pkt=None):
        ascii_string = pkt.decode('ascii', errors='ignore')
        return str(ascii_string)
        
    def unhex(self,pkt=None):
        hex_string = ' '.join('{:02x}'.format(byte) for byte in pkt)
        return hex_string
        
    def run(self):
      try:
        self.turn_on_promsc()
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.count = 0
        global capture_rate
        while not self._stop_event:
            pkt = s.recvfrom(65565)
            len_pkt = len(pkt[0])
            timestamp = datetime.now()
            fts = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            src_mac, dest_mac, eth_type = self.parse_eth(pkt[0])
            if eth_type == "IPv4":
                src_ip, dest_ip, protocol, fragmented = self.parse_ip(pkt[0][14:34])
                if protocol == "TCP":
                    src_port, dest_port, seq_num, ack_num, data_offset, flags, window, checksum, urg_ptr = self.parse_tcp(pkt[0][34:54])
                    data = self.parse_data(pkt[0][54:])
                    parsed_netpack = {"Ethernet Header":{"Source MAC":src_mac, "Destination MAC":dest_mac, "Ethernet Type":eth_type}, "IPv4 Header":{"Source IP":src_ip, "Destination IP":dest_ip, "Protocol":protocol, "Fragmented": fragmented}, "TCP Header":{"Source Port":src_port, "Destination Port":dest_port, "Sequence Number":seq_num, "Acknowledgment Number":ack_num, "Data Offset":data_offset, "Flags":flags, "Window":window, "Checksum":checksum, "Urgent Pointer":urg_ptr}, "Payload":data, "Time Stamp":fts, "Packet Length": len_pkt, "Raw":pkt[0], "CPR":capture_rate}
                    data_packets.append(parsed_netpack)
                    self.count += 1                  
                    self.packet_received.emit((fts, eth_type, protocol, src_ip,  dest_ip, src_port, dest_port, flags))
                    
                elif protocol == "UDP":
                    src_port, dest_port, length, checksum = self.parse_udp(pkt[0][34:42])
                    data = self.parse_data(pkt[0][42:])
                    parsed_netpack = {"Ethernet Header":{"Source MAC":src_mac, "Destination MAC":dest_mac, "Ethernet Type":eth_type}, "IPv4 Header":{"Source IP":src_ip, "Destination IP":dest_ip, "Protocol":protocol, "Fragmented": fragmented}, "UDP Header":{"Source Port":src_port, "Destination Port":dest_port, "Length": length, "Checksum":checksum}, "Payload":data, "Time Stamp":fts, "Packet Length": len_pkt, "Raw":pkt[0], "CPR":capture_rate}
                    data_packets.append(parsed_netpack)
                    self.count += 1
                    self.packet_received.emit((fts, eth_type, protocol, src_ip, dest_ip, src_port, dest_port))
                    
                elif protocol == "ICMP":
                    icmp_type, icmp_code, icmp_checksum = self.parse_icmp(pkt[0][34:38])
                    parsed_netpack = {"Ethernet Header":{"Source MAC":src_mac, "Destination MAC":dest_mac, "Ethernet Type":eth_type}, "IPv4 Header":{"Source IP":src_ip, "Destination IP":dest_ip, "Protocol":protocol, "Fragmented": fragmented}, "ICMP Header":{"ICMP Type":icmp_type, "ICMP Code": icmp_code, "Checksum": icmp_checksum}, "Time Stamp":fts, "Packet Length": len_pkt, "Raw":pkt[0], "CPR":capture_rate}
                    data_packets.append(parsed_netpack)
                    self.count += 1
                    self.packet_received.emit((fts, eth_type, protocol, src_ip, dest_ip, icmp_type, icmp_code))
                    
            elif eth_type == "ARP":
                hardware_type, protocol_type, hardware_addr_length, protocol_addr_length, operation, sender_hw_addr, sender_ip_addr, target_hw_addr, target_ip_addr = self.parse_arp(pkt[0][14:])
                parsed_netpack = {"Ethernet Header":{"Source MAC":src_mac, "Destination MAC":dest_mac, "Ethernet Type":eth_type}, "ARP Header":{"Hardware Type":hardware_type, "Protocol Type":protocol_type, "Hardware Address Length":hardware_addr_length, "Protocol Address Length":protocol_addr_length, "Operation":operation, "Sender Hardware Address":sender_hw_addr, "Sender IP Address":sender_ip_addr, "Target Hardware Address":target_hw_addr, "Target IP Address":target_ip_addr}, "Time Stamp":fts, "Packet Length":len_pkt, "Raw":pkt[0], "CPR":capture_rate}
                data_packets.append(parsed_netpack)
                self.count += 1
                self.packet_received.emit((fts, eth_type, operation, sender_ip_addr,"Broadcast"))
            elif eth_type == "IPv6":
                pass
                
      finally:
        s.close()
        self.turn_off_promsc()

    def stop(self):
        self._stop_event = True
        
    def turn_on_promsc(self):
        subprocess.run(["sudo", "ifconfig", self.interface_name, "promisc"])

    def turn_off_promsc(self):
        subprocess.run(["sudo", "ifconfig", self.interface_name, "-promisc"])
        
#-------------------------------------------------------------------------------------#

class MyWindow(QMainWindow):

    ids_packet = pyqtSignal(tuple)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NETरा")
        self.setGeometry(100, 100, 800, 600)
        self.active_icon = QIcon(icon_path)
        self.stopped_icon = QIcon(stopped_icon_path)
        self.initUI()
        self.sx = []
        self.sy = []
        self.dx = []  
        self.dy = [] 
        self.entry_count = 0
        self.packet_count = 0
        self.time_window = 1 
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_capture_rate)
        self.timer.start(self.time_window * 1000)
        self.buff_size = 50
        
    def initUI(self):
        self.toolbar = self.addToolBar("Toolbar")
        self.toolbar.setStyleSheet("background-color:#242424; color:white;")

        self.action_button1 = QAction(self.stopped_icon, "Capture", self)
        self.action_button1.setCheckable(True)
        self.action_button1.triggered.connect(self.on_capture_clicked)
        self.toolbar.addAction(self.action_button1)
        
        self.save_icon = QIcon(save_icon_path)
        self.action_button2 = QAction(self.save_icon, "Save", self)
        self.action_button2.triggered.connect(self.save_file)
        self.toolbar.addAction(self.action_button2)

        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.packet_capture_tab = QWidget()
        self.tab_widget.addTab(self.packet_capture_tab, "Packet Capture")
        layout1 = QVBoxLayout(self.packet_capture_tab)
        self.create_table_widget(layout1)
        self.create_bottom_sections(layout1)
        self.create_rule_section(layout1)

        self.ids_tab = QWidget()
        self.tab_widget.addTab(self.ids_tab, "IDS")
        layout2 = QVBoxLayout(self.ids_tab)
        self.create_ids_table_widget(layout2)
        
        self.geo_tab = QWidget()
        self.tab_widget.addTab(self.geo_tab, "Geo")
        layout3 = QVBoxLayout()
        self.geo_tab.setLayout(layout3)
        self.left_section = QVBoxLayout()
        self.figure = plt.figure(figsize=(20,10))
        self.canvas = FigureCanvas(self.figure)
        self.left_section.addWidget(self.canvas)
        self.matplotlib_toolbar = MatplotlibToolbar(self.canvas, self)
        self.left_section.addWidget(self.matplotlib_toolbar)
        self.right_section = QVBoxLayout()
        self.sec_label = QLabel("Geographical Information")
        self.right_section.addWidget(self.sec_label)
        self.geo_tree_view = QTreeView()
        self.geo_tree_view.setHeaderHidden(True)
        self.geo_tree_model = QStandardItemModel()
        self.geo_tree_view.setModel(self.geo_tree_model)
        self.right_section.addWidget(self.geo_tree_view)
        layout3.addLayout(self.left_section, stretch=3)
        layout3.addLayout(self.right_section, stretch=1)
        
        self.total_pkts = 0
        self.status_label1 = QLabel('-')
        self.status_label2 = QLabel("- pkt/s")
        self.statusBarWidget = self.statusBar()
        self.statusBarWidget.showMessage("Disconnected")
        self.statusBarWidget.addPermanentWidget(self.status_label1)
        self.statusBarWidget.addPermanentWidget(self.status_label2)
        
    def create_table_widget(self, layout):
        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(5)
        self.tableWidget.setHorizontalHeaderLabels(["timestamp", "IP Protocol", "Transmission Protocol", "Source", "Destination"])
        self.tableWidget.setColumnWidth(0, 150)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 150)
        self.tableWidget.setColumnWidth(3, 150)
        self.tableWidget.setColumnWidth(4, 150)
        self.tableWidget.setContentsMargins(0, 0, 0, 0)
        self.tableWidget.cellClicked.connect(self.on_cell_clicked)
        layout.addWidget(self.tableWidget)
        
    def create_ids_table_widget(self, layout):
        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(["Timestamp", "Message", "Packet No."])
        self.tableWidget.setColumnWidth(0, 150)
        self.tableWidget.setColumnWidth(1, 400)
        self.tableWidget.setColumnWidth(2, 120)
        self.tableWidget.setContentsMargins(0, 0, 0, 0)
        self.tableWidget.cellClicked.connect(self.highlightCellInTable2)
        layout.addWidget(self.tableWidget)


    def on_capture_clicked(self, checked):
        if checked:
            self.action_button1.setIcon(self.active_icon)
            self.statusBarWidget.showMessage('Capturing')
            self.action_button1.setToolTip("Stop")
            self.packet_capture_thread = PacketCaptureThread()
            self.AI_thread = AI()
            self.packet_capture_thread.packet_received.connect(self.add_content_to_table)
            self.ids_packet.connect(self.add_ids_alert)
            self.AI_thread.alert_mesg.connect(self.add_ids_alert)
            self.AI_thread.prediction_res.connect(self.prediction_update)
            self.packet_capture_thread.start()
            self.AI_thread.start()
        else:
            self.statusBarWidget.showMessage('Stopped')
            self.action_button1.setToolTip("Capture")
            self.action_button1.setIcon(self.stopped_icon)
            if hasattr(self, 'packet_capture_thread'):
                self.packet_capture_thread.stop()
                self.AI_thread.stop()

    def add_content_to_table(self, data):
        ids = IDS()
        tableWidget = self.packet_capture_tab.findChild(QTableWidget)
        rowCount = tableWidget.rowCount()
        tableWidget.insertRow(rowCount)
        self.packet_count += 1
        self.total_pkts += 1
        self.status_label1.setText('Packets Captured: '+str(self.total_pkts))
        for i, item in enumerate(data):
            table_item = QTableWidgetItem(str(item))
            tableWidget.setItem(rowCount, i, table_item)
            if i == 3 or i == 4:
                if not self.is_private_ip(item):
                    self.plot_geoip_location(item,i,self.total_pkts)
                else:
                    self.plot_geoip_location(public_ip,i,self.total_pkts)
                        
        mesg = ids.rule_parser(data_packets[self.total_pkts-1])
        if mesg['alert']:
                self.ids_packet.emit((data_packets[self.total_pkts-1]['Time Stamp'],mesg['message'],self.total_pkts))
                        
    def add_ids_alert(self, data):
        tableWidget = self.ids_tab.findChild(QTableWidget)
        rowCount = tableWidget.rowCount()
        tableWidget.insertRow(rowCount)
        for i, item in enumerate(data):
            table_item = QTableWidgetItem(str(item))
            tableWidget.setItem(rowCount, i, table_item)
            
    def is_private_ip(self, ip):
        private_ip_patterns = [r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', r'^192\.168\.', r'^127\.']
        for pattern in private_ip_patterns:
            if re.match(pattern, ip):
                return True
        return False
        
    def plot_geoip_location(self, ip, t, tp):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(current_dir, 'GeoLite2-City.mmdb')
        reader = geoip2.database.Reader(file_path)
        try:
            response = reader.city(ip)
            if not self.is_private_ip(ip):
                if t == 3:
                    geoip_info = {'Latitude': response.location.latitude, 'Longitude': response.location.longitude, 'City Name': response.city.names.get('en', ''), 'Country Name': response.country.names.get('en', ''), 'Country ISO Code': response.country.iso_code, 'Continent Name': response.continent.names.get('en', ''), 'Postal Code': response.postal.code, 'Registered Country': {'name': response.registered_country.names.get('en', ''), 'ISO Code': response.registered_country.iso_code}, 'Subdivision': {'name': response.subdivisions[0].names.get('en', '') if response.subdivisions else 'N/A', 'ISO Code': response.subdivisions[0].iso_code if response.subdivisions else 'N/A'}, 'Traits': {'IP Address': response.traits.ip_address}}
                    data_packets[tp-1]['Source Geography'] = geoip_info
                    
                elif t == 4:
                    geoip_info = {'Latitude': response.location.latitude, 'Longitude': response.location.longitude, 'City Name': response.city.names.get('en', ''), 'Country Name': response.country.names.get('en', ''), 'Country ISO Code': response.country.iso_code, 'Continent Name': response.continent.names.get('en', ''), 'Postal Code': response.postal.code, 'Registered Country': {'name': response.registered_country.names.get('en', ''), 'ISO Code': response.registered_country.iso_code}, 'Subdivision': {'name': response.subdivisions[0].names.get('en', '') if response.subdivisions else 'N/A', 'ISO Code': response.subdivisions[0].iso_code if response.subdivisions else 'N/A'}, 'Traits': {'IP Address': response.traits.ip_address}}
                    data_packets[tp-1]['Destination Geography'] = geoip_info
        except Exception as e:
            if t == 3:
                 data_packets[tp-1]['Source Geography'] = 'Private'
            elif t == 4:
                data_packets[tp-1]['Destination Geography'] = 'Private'
            return

    def plot_geoip(self,n):
        self.figure.clf()
        self.canvas.draw()
        world = gpd.read_file(gpd.datasets.get_path('naturalearth_lowres'))
        world.plot(ax=self.figure.add_subplot(111), facecolor='#D0D3D5', edgecolor='white')
        if data_packets[n]["Ethernet Header"]["Ethernet Type"] != "ARP":
            if data_packets[n]['Source Geography'] != 'Private':
                self.slat = data_packets[n]['Source Geography']['Latitude']
                self.slon = data_packets[n]['Source Geography']['Longitude']
                self.country = data_packets[n]['Source Geography']['Country Name']
                plt.scatter(self.slon, self.slat, color='red', marker='v', s=25, alpha=1.0)
                plt.annotate(f'{self.country}(Lat:{self.slat},Lon:{self.slon})', xy=(self.slon, self.slat), textcoords="offset points", xytext=(0,10), ha='center')
            if data_packets[n]['Destination Geography'] != 'Private':
                self.dlat = data_packets[n]['Destination Geography']['Latitude']
                self.dlon = data_packets[n]['Destination Geography']['Longitude']
                self.country = data_packets[n]['Destination Geography']['Country Name']
                plt.scatter(self.dlon, self.dlat, color='blue', marker='v', s=25, alpha=1.0)
                plt.annotate(f'{self.country}(Lat:{self.dlat},Lon:{self.dlon})', xy=(self.dlon, self.dlat), textcoords="offset points", xytext=(0,10), ha='center')
            if data_packets[n]['Source Geography'] != 'Private' and data_packets[n]['Destination Geography'] != 'Private':
                plt.plot([self.slon, self.dlon], [self.slat, self.dlat], color='orange', linestyle='--', linewidth=1, alpha=0.8)           
        plt.title('Geolocation')
        plt.xlabel('Longitude')
        plt.ylabel('Latitude')
        plt.axis('off')
        self.canvas.draw()
        
    def update_capture_rate(self):
        global capture_rate
        capture_rate = self.packet_count / self.time_window
        self.status_label2.setText("Capture Rate: "+str(int(capture_rate))+' pkt/s')
        if capture_rate >= self.buff_size:
            self.buff_size = int(capture_rate) + 100
        elif capture_rate < 100 and capture_rate >= 50:
            self.buff_size = 100
        elif capture_rate < 50:
            self.buff_size = 50
        self.packet_count = 0
        
    def create_bottom_sections(self, layout):
        bottom_layout = QHBoxLayout()
        header_label = QLabel("Packet Dissection")
        self.header_layout = QVBoxLayout()
        self.header_layout.addWidget(header_label)
        self.tree_view = QTreeView()
        self.tree_view.setHeaderHidden(True)
        self.tree_model = QStandardItemModel()
        self.tree_view.setModel(self.tree_model)
        self.header_layout.addWidget(self.tree_view)
        bottom_layout.addLayout(self.header_layout)
        self.hex_label = QLabel("Hex Data")
        self.hex_text_edit = QTextEdit()
        self.hex_layout = QVBoxLayout()
        self.hex_layout.addWidget(self.hex_label)
        self.hex_layout.addWidget(self.hex_text_edit)
        bottom_layout.addLayout(self.hex_layout)
        self.ascii_label = QLabel("ASCII Data")
        self.ascii_text_edit = QTextEdit()
        self.ascii_layout = QVBoxLayout()
        self.ascii_layout.addWidget(self.ascii_label)
        self.ascii_layout.addWidget(self.ascii_text_edit)
        bottom_layout.addLayout(self.ascii_layout)
        layout.addLayout(bottom_layout)
        
    def create_rule_section(self, layout):
        bottom_layout = QHBoxLayout()
        self.createrule_layout = QVBoxLayout()
        self.prediction_header = QLabel("AI Prediction: ")
        self.createrule_layout.addWidget(self.prediction_header)
        self.prediction_label = QLabel("")
        self.createrule_layout.addWidget(self.prediction_label)
        self.true_positive_button = QPushButton("True Positive")
        self.true_positive_button.setStyleSheet("background-color: blue; color: white;")
        self.true_positive_button.clicked.connect(self.on_truepos_clicked)
        self.false_positive_button = QPushButton("False Positive")
        self.false_positive_button.setStyleSheet("background-color: red; color: white;")
        self.false_positive_button.clicked.connect(self.on_falsepos_clicked)
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.true_positive_button)
        button_layout.addWidget(self.false_positive_button)
        self.createrule_layout.addLayout(button_layout)
        bottom_layout.addLayout(self.createrule_layout)
        layout.addLayout(bottom_layout)
        
    def on_truepos_clicked(self):
        print("True Positive")
        if self.prediction_label.text() != "":
            print(self.prediction_label.text())
            print(self.packet)
            # code for partial_fit() 
        
    def on_falsepos_clicked(self):
        print("False Positive")
        if self.prediction_label.text() != "":
            print(self.prediction_label.text())
            print(self.packet)
            # code for partial_fit() 
        
    def prediction_update(self,data):
        self.prediction_label.setText(data)

    def populate_model(self, parent_item, data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "Source Geography" or key == "Destination Geography":
                    continue
                key_item = QStandardItem(str(key))
                parent_item.appendRow(key_item)
                self.populate_model(key_item, value)
        else:
            value_item = QStandardItem(str(data))
            parent_item.appendRow(value_item)
            
            
    def populate_geo(self, parent_item, data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "Source Geography" or key == "Destination Geography":
                    key_item = QStandardItem(str(key))
                    parent_item.appendRow(key_item)
                    self.populate_model(key_item, value)
                else:
                    continue
        else:
            value_item = QStandardItem(str(data))
            parent_item.appendRow(value_item)
            
    def on_cell_clicked(self, row, column):
        ids = IDS()
        self.packet = data_packets[row]
        self.tree_model.clear()
        self.geo_tree_model.clear()
        self.prediction_label.setText("")
        pc = PacketCaptureThread()
        root_item = self.tree_model.invisibleRootItem()
        root_item_geo = self.geo_tree_model.invisibleRootItem()
        self.populate_model(root_item, self.packet)
        self.populate_geo(root_item_geo, self.packet)
        self.plot_geoip(row)
        if 'Label' in self.packet:
            self.prediction_update(self.packet['Label'])
        try:
            self.hex_text_edit.clear()
            self.hex_text_edit.insertPlainText(pc.unhex(self.packet['Raw']))
            self.ascii_text_edit.clear()
            self.ascii_text_edit.insertPlainText(pc.parse_data(self.packet['Raw']))
        except Exception as e:
            print(e)
            pass
            
    def highlightCellInTable2(self, row, column):
        table1Widget = self.ids_tab.findChild(QTableWidget)
        table2Widget = self.packet_capture_tab.findChild(QTableWidget)        
        value = table1Widget.item(row, 2).text()
        table2Widget.selectRow(int(value)-1)
        self.on_cell_clicked(int(value)-1,0)
        self.tab_widget.setCurrentIndex(0)
        
        
    def flatten_dict(self, d, parent_key='', sep='_'):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def save_file(self):
        if os.path.exists('network_packets_dataset.csv'):
            df_existing = pd.read_csv('network_packets_dataset.csv')
            for packet in data_packets:
                flattened = self.flatten_dict(packet)
                df_new = pd.DataFrame([flattened])
                df_existing = pd.concat([df_existing, df_new], ignore_index=True)
            df_existing.to_csv('network_packets_dataset.csv', index=False)
        else:
            dfs = []
            for packet in data_packets:
                flattened = self.flatten_dict(packet)
                df = pd.DataFrame([flattened])
                dfs.append(df)
            df = pd.concat(dfs, ignore_index=True)
            df.to_csv('network_packets_dataset.csv', index=False)
            
#------------------------------------------------------------------------------------#

class IDS():
    def __init__(self):
        super().__init__()
        self.static_rules = os.path.join(current_dir, 'rules/local.rules')
        self.operators = {
            '$gt': operator.gt,
            '$lt': operator.lt,
            '$gte': operator.ge,
            '$lte': operator.le,
            '$eq': operator.eq,
            '$ne': operator.ne,
            '$bw': self.between,
            '$in': self.contains,
            '$nin': self.contains_not,
            '$inprev': self.in_prev
        }
        
        
    def in_prev(self,value,prev):
        if len(data_packets) < 2:
            return False
        p = data_packets[len(data_packets)-2]
        res = self.evaluate_condition(prev,p)
        return res
        
    def contains(self,value,list_values):
        if isinstance(value,list):
            are_equal = sorted(value) == sorted(list_values)
            return are_equal
        else:
            return value in list_values
                
    def contains_not(self,value,list_values):
        if isinstance(value,list):
            are_equal = sorted(value) != sorted(list_values)
            return are_equal
        else:
            return value not in list_values
            
    def between(self, value, range_values):
        if isinstance(range_values, list) and len(range_values) == 2:
            return range_values[0] <= value <= range_values[1]
        return False

    def evaluate_condition(self, condition, data):
        if "and" in condition:
            return all(self.evaluate_condition(c, data) for c in condition["and"])
        elif "or" in condition:
            return any(self.evaluate_condition(c, data) for c in condition["or"])
        elif "not" in condition:
            return not self.evaluate_condition(condition["not"], data)
        else:
            return self.evaluate_expression(condition, data)

    def evaluate_expression(self, condition, data):
        condition_keys = set(condition.keys())
        data_keys = set(data.keys())
        if not condition_keys.issubset(data_keys):
            for dkey in data_keys:
                try:
                    nested_dict = data[dkey]
                    if isinstance(nested_dict, dict) and all(key in nested_dict and self.match_condition(nested_dict[key], condition[key]) for key in condition_keys):
                        return True
                except Exception as e:
                    continue
            return False
        else:
            if all(key in data and self.match_condition(data[key], condition[key]) for key in condition_keys):
                return True
            else:
                return False

    def match_condition(self, data_value, condition_value):
        if isinstance(condition_value, dict):
            for op, op_val in condition_value.items():
                if op in self.operators:
                    if not self.operators[op](data_value, op_val):
                        return False
            return True
        return data_value == condition_value
        
    def check_expiry(self, c, e, pd):
        e = e.strip()       
        try:
            c_datetime = datetime.strptime(c, "%d-%m-%Y")
        except ValueError:
            return False
            
        try:
            pd_datetime = datetime.strptime(pd, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False

        if bool(re.match(r'^(\d+)\s+(hours?|mins?|secs?)$', e, re.IGNORECASE)):
            match = re.match(r'^(\d+)\s+(hours?|mins?|secs?)$', e, re.IGNORECASE)
            quantity = int(match.group(1))
            unit = match.group(2).lower()
            if unit.startswith('hour'):
                expiry_delta = timedelta(hours=quantity)
            elif unit.startswith('min'):
                expiry_delta = timedelta(minutes=quantity)
            elif unit.startswith('sec'):
                expiry_delta = timedelta(seconds=quantity)
            expiry_datetime = c_datetime + expiry_delta
            return pd_datetime > expiry_datetime
            
        elif bool(re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}([ ]?[AP]M)?$', e, re.IGNORECASE)):
            try:
                expiry_datetime = datetime.strptime(e, "%Y-%m-%d %H:%M:%S")
                return pd_datetime > expiry_datetime
            except ValueError:
                return False

        elif bool(re.match(r'^\d{2}-\d{2}-\d{4}$', e)):
            try:
                expiry_datetime = datetime.strptime(e, "%d-%m-%Y")
                expiry_end_of_day = expiry_datetime.replace(hour=23, minute=59, second=59)
                return pd_datetime > expiry_end_of_day
            except ValueError:
                return False
            
        return False
            
    def rule_parser(self, netpack):
        with open(self.static_rules, 'r') as file:
            rules = json.load(file)
            for rule in rules:
                if 'expiry' in rule['metadata'] and self.check_expiry(rule['metadata']['created_at'],rule['metadata']['expiry'],netpack['Time Stamp']):
                    continue
                    
                result = self.evaluate_condition(rule["condition"], netpack)
                if result:
                    if rule["action"]["type"] == "alert":
                        if "message" in rule["action"]:
                            return {"alert": True, "message": rule["action"]["message"]}
                        else:
                            return {"alert": True, "message": "Alert!"}
                    elif rule["action"]["type"] == "log":
                        if "message" in rule["action"]:
                            return {"alert": True, "message": rule["action"]["message"]}
                        else:
                            return {"alert": True, "message": "Network Event Logged!"}
                    elif rule["action"]["type"] == "block":
                        if "message" in rule["action"]:
                            return {"alert": True, "message": rule["action"]["message"]}
                        else:
                            return {"alert": True, "message": "Blocked an IP address!"}
        return {"alert": False, "message": ""}
        
    def prevent(b_src,n_host,dt,exp,act):
        return 0
        
        
#------------------------------------------------------------------------------------------#

class AI(QThread):
    
    prediction_res = pyqtSignal(tuple)
    alert_mesg = pyqtSignal(tuple)
    
    def __init__(self, parent=None):
        super(AI, self).__init__(parent)
        self.n = 0
        self._stop_event = False
        
    def AI_Model(self,pkt=None):
        data = {
        "Ethernet Header_Source MAC": pkt.get('Ethernet Header', {}).get('Source MAC', None),
        "Ethernet Header_Destination MAC": pkt.get('Ethernet Header', {}).get('Destination MAC', None),
        "IPv4 Header_Source IP": pkt.get('IPv4 Header', {}).get('Source IP', None),
        "IPv4 Header_Destination IP": pkt.get('IPv4 Header', {}).get('Destination IP', None),
        "IPv4 Header_Protocol": pkt.get('IPv4 Header', {}).get('Protocol', None),
        "TCP Header_Source Port": pkt.get('TCP Header', {}).get('Source Port', None),
        "TCP Header_Destination Port": pkt.get('TCP Header', {}).get('Destination Port', None),
        "TCP Header_Flags": pkt.get('TCP Header', {}).get('Flags', None),
        "Packet Length": pkt.get('Packet Length', None),
        "CPR": pkt.get('CPR', None)
        }
        req = pd.DataFrame([data])
        req['TCP Header_Flags'].fillna('[]',inplace=True)
        req['TCP Header_Flags'] = req['TCP Header_Flags'].apply(lambda x: '[]' if x in ['United States', 'United Kingdom'] else x)
        possible_flags = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'NS']
        for flag in possible_flags:
              req[flag] = req['TCP Header_Flags'].apply(lambda x: 1 if flag in x else 0)
        req['TCP Header_Destination Port'] = req['TCP Header_Destination Port'].apply(lambda x: 0 if x in ['United States', 'United Kingdom'] else x)
        req.fillna(0,inplace=True)
        req['IPv4 Header_Source IP'] = req['IPv4 Header_Source IP'].apply(lambda x: label_encoder1.transform([x])[0] if x in label_encoder1.classes_ else -1)
        req['IPv4 Header_Destination IP'] = req['IPv4 Header_Destination IP'].apply(lambda x: label_encoder2.transform([x])[0] if x in label_encoder2.classes_ else -1)
        req['Ethernet Header_Source MAC'] = req['Ethernet Header_Source MAC'].apply(lambda x: label_encoder3.transform([x])[0] if x in label_encoder3.classes_ else -1)
        req['Ethernet Header_Destination MAC'] = req['Ethernet Header_Destination MAC'].apply(lambda x: label_encoder4.transform([x])[0] if x in label_encoder4.classes_ else -1)
        req['IPv4 Header_Protocol'] = req['Ethernet Header_Destination MAC'].apply(lambda x: label_encoder5.transform([x])[0] if x in label_encoder5.classes_ else -1)
        req = req.drop(columns=['TCP Header_Flags'])
        req = scaler.transform(req)
        predictions = loaded_lr_model.predict(req)
        return predictions
        
    def run(self):
        while not self._stop_event:
            if len(data_packets) > self.n:
                prediction = self.AI_Model(data_packets[self.n])
                data_packets[self.n]['Label'] = prediction[0]
                if prediction[0] == "Abnormal":
                    mesg = "Abnormal activity detected by AI!"
                    self.alert_mesg.emit((data_packets[self.n]['Time Stamp'],mesg,self.n))
                self.n+=1
            else:
                QThread.sleep(2)
                
    def stop(self):
        self._stop_event = True
        

#------------------------------------------------------------------------------------------#

def main():
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
    
    
