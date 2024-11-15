import sqlite3
import random
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QApplication, QPushButton, QLineEdit, QVBoxLayout, QHBoxLayout, QWidget, QMenu, QMessageBox, QComboBox, QInputDialog
import sys
import requests
import concurrent.futures
import time
import socket
import socks
import speedtest
import re
import subprocess

# Khởi tạo cơ sở dữ liệu SQLite
def init_db():
    conn = sqlite3.connect('proxies.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS proxies
                 (protocol TEXT, ip TEXT, port INTEGER, user TEXT, pass TEXT, 
                 speed REAL, location TEXT, latency REAL, status TEXT)''')
    conn.commit()
    conn.close()

# Ghi dữ liệu vào file proxychains4.conf
def update_proxychains_conf(dynamic_chain):
    with open("proxychains4.conf", "r") as conf_file:
        lines = conf_file.readlines()

    # Cập nhật chế độ ngẫu nhiên theo yêu cầu
    for i, line in enumerate(lines):
        if "dynamic_chain" in line:
            lines[i] = "random_chain\n"
        elif "random_chain" in line:
            lines[i] = "dynamic_chain\n" 

    # Ghi lại file với cấu hình đã cập nhật
    with open("proxychains4.conf", "w") as conf_file:
        conf_file.writelines(lines)

# Chức năng kiểm tra tốc độ, vị trí và độ trễ của proxy với kết quả làm tròn
def check_proxy_status(ip, port, protocol, user=None, password=None):
    try:
        if protocol == "socks5":
            sock = socks.socksocket()
            if user and password:
                sock.set_proxy(socks.SOCKS5, ip, int(port), username=user, password=password)
            else:
                sock.set_proxy(socks.SOCKS5, ip, int(port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Đo độ trễ (latency)
        start_time = time.time()
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        latency_ms = round((time.time() - start_time) * 1000, 4)  # Làm tròn đến 4 chữ số
        sock.close()

        # Đo tốc độ bằng speedtest-cli
        st = speedtest.Speedtest()
        st.get_best_server()
        speed_mbps = round(st.download() / 1_000_000, 4)  # Làm tròn đến 4 chữ số

        # Lấy vị trí từ IP
        location = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json().get("city", "Unknown")

        return speed_mbps, latency_ms, location, "running"
    except socks.ProxyError:
        return None, None, None, "Proxy authentication failed"
    except Exception as e:
        print(f"Error checking proxy status: {e}")
        return None, None, None, "stopped"

class ProxyManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ẩn danh tác chiến")
        self.setGeometry(100, 100, 1000, 800)

        # Store passwords in an internal structure to keep them unmasked for saving
        self.passwords = {}

        # Layout chính
        self.main_layout = QVBoxLayout()

        # Bảng hiển thị danh sách proxy
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["Protocol", "IP", "Port", "User", "Password", "Speed (Mbps)", "Location", "Latency (ms)", "Status"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        # Thêm bảng vào layout chính
        self.main_layout.addWidget(self.table)

        # Nút sắp xếp định tuyến và kiểm tra proxy
        self.route_button = QPushButton('Sắp xếp định tuyến tự động')
        self.check_button = QPushButton('Kiểm tra trạng thái')

        # Nút gạt chế độ ngẫu nhiên
        self.toggle_random_button = QPushButton("Ngẫu nhiên")
        self.toggle_random_button.setCheckable(True)
        self.toggle_random_button.setStyleSheet("background-color: red")  # Màu đỏ khi tắt
        self.toggle_random_button.clicked.connect(self.toggle_random_mode)

        # Layout cho hàng nút
        self.button_layout = QHBoxLayout()
        self.button_layout.addWidget(self.check_button)
        self.button_layout.addWidget(self.route_button)
        self.button_layout.addWidget(self.toggle_random_button)

        self.main_layout.addLayout(self.button_layout)

        # Ô nhập lệnh và nút chạy lệnh
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Nhập lệnh nmap, nikto...")
        self.run_command_button = QPushButton('Chạy lệnh')

        # Layout cho phần lệnh
        self.command_layout = QHBoxLayout()
        self.command_layout.addWidget(self.command_input)
        self.command_layout.addWidget(self.run_command_button)

        self.main_layout.addLayout(self.command_layout)

        # Thiết lập layout chính cho cửa sổ
        container = QWidget()
        container.setLayout(self.main_layout)
        self.setCentralWidget(container)

        # Tải danh sách proxy
        self.load_proxies()

        # Liên kết các nút với chức năng
        self.route_button.clicked.connect(self.route_proxies)
        self.check_button.clicked.connect(self.check_proxies)
        self.run_command_button.clicked.connect(self.run_command)

        # Chế độ ngẫu nhiên mặc định là tắt
        self.dynamic_chain = True  # Đặt mặc định là dynamic_chain
        update_proxychains_conf(self.dynamic_chain)

    def toggle_random_mode(self):
        # Toggle chế độ ngẫu nhiên mà không thay đổi danh sách proxy
        self.dynamic_chain = not self.dynamic_chain
        
        # Cập nhật nút và file config theo trạng thái của dynamic_chain
        if self.dynamic_chain:
            self.toggle_random_button.setStyleSheet("background-color: red")  # Tắt thì màu đỏ (dynamic_chain)
        else:
            self.toggle_random_button.setStyleSheet("background-color: green")  # Bật thì màu xanh (random_chain)

        update_proxychains_conf(self.dynamic_chain)

    def load_proxies(self):
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        c.execute("SELECT protocol, ip, port, user, pass, speed, location, latency, status FROM proxies ORDER BY rowid")
        proxies = c.fetchall()
        self.table.setRowCount(len(proxies))
        for row_num, proxy in enumerate(proxies):
            for col_num, data in enumerate(proxy):
                if col_num == 4 and data:  # Cột mật khẩu
                    self.passwords[row_num] = data  # Lưu trữ mật khẩu thực tế vào bộ nhớ
                    masked_password = '*' * len(data)
                    self.table.setItem(row_num, col_num, QTableWidgetItem(masked_password))
                else:
                    self.table.setItem(row_num, col_num, QTableWidgetItem(str(data) if data is not None else "None"))
        conn.close()

    def route_proxies(self):
        # Hiển thị hộp thoại để nhập số lượng node cần sử dụng
        num_nodes, ok = QInputDialog.getInt(self, "Số lượng node", "Nhập số lượng node cần sử dụng:")
        
        if not ok:
            return  # Hủy bỏ nếu người dùng nhấn Cancel

        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()

        # Chọn các proxy có giá trị speed hợp lệ
        c.execute("SELECT protocol, ip, port, user, pass, speed FROM proxies WHERE speed IS NOT NULL ORDER BY speed DESC")
        proxies = c.fetchall()

        if len(proxies) < num_nodes:
            QMessageBox.warning(self, "Lỗi", "Số lượng node yêu cầu vượt quá số lượng hiện có!")
            return

        # Lựa chọn số lượng node cần thiết
        selected_proxies = proxies[:num_nodes]
        
        # Node đầu tiên là node có tốc độ cao nhất, các node còn lại được sắp xếp ngẫu nhiên
        first_node = selected_proxies[0]
        remaining_nodes = selected_proxies[1:]
        random.shuffle(remaining_nodes)
        final_route = [first_node] + remaining_nodes

        # Ghi các node đã chọn vào file proxychains4.conf
        with open("proxychains4.conf", "r") as conf_file:
            lines = conf_file.readlines()

        # Giữ lại mọi thứ trước [ProxyList]
        before_proxylist = []
        for line in lines:
            if "[ProxyList]" in line:
                break
            before_proxylist.append(line)

        with open("proxychains4.conf", "w") as conf_file:
            conf_file.writelines(before_proxylist)
            conf_file.write("[ProxyList]\n")  # Thêm lại dòng [ProxyList]
            conf_file.write("# Proxy list updated by Proxy Manager\n")
            for proxy in final_route:
                protocol, ip, port, user, password, speed = proxy
                if user and password:
                    conf_file.write(f"{protocol} {ip} {port} {user} {password}\n")
                else:
                    conf_file.write(f"{protocol} {ip} {port}\n")

        conn.close()

        # Thông báo kết quả
        selected_ips = [f"{ip}:{port}" for protocol, ip, port, user, password, speed in final_route]
        QMessageBox.information(self, "Định tuyến hoàn tất", f"Đã lựa chọn các node sau:\n{', '.join(selected_ips)}")

    def check_proxies(self):
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        c.execute("SELECT rowid, ip, port, protocol, user, pass FROM proxies")
        proxies = c.fetchall()
        conn.close()  # Close the connection after fetching data to avoid concurrent access issues

        def update_proxy_status(row_num, proxy):
            rowid, ip, port, protocol, user, password = proxy
            speed, latency, location, status = check_proxy_status(ip, port, protocol, user, password)
            
            self.table.setItem(row_num, 5, QTableWidgetItem(str(speed) if speed else "N/A"))
            self.table.setItem(row_num, 6, QTableWidgetItem(location if location else "N/A"))
            self.table.setItem(row_num, 7, QTableWidgetItem(str(latency) if latency else "N/A"))
            self.table.setItem(row_num, 8, QTableWidgetItem(status))

            # Cập nhật trạng thái vào cơ sở dữ liệu
            conn_update = sqlite3.connect('proxies.db')
            c_update = conn_update.cursor()
            c_update.execute("UPDATE proxies SET speed=?, location=?, latency=?, status=? WHERE rowid=?", 
                      (speed, location, latency, status, rowid))
            conn_update.commit()
            conn_update.close()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(update_proxy_status, row_num, proxy) for row_num, proxy in enumerate(proxies)]
            concurrent.futures.wait(futures)  # Wait for all threads to finish

        QMessageBox.information(self, "Kiểm tra hoàn tất", "Trạng thái proxy đã được cập nhật.")

    def run_command(self):
        command = self.command_input.text()
        if command:
            subprocess.run(f"x-terminal-emulator -e 'proxychains -f proxychains4.conf {command}'", shell=True)

    # Hiển thị menu chuột phải cho thêm, sửa, xóa node
    def show_context_menu(self, pos):
        menu = QMenu()

        # Thêm, sửa, xóa node
        add_action = menu.addAction("Thêm node")
        edit_action = menu.addAction("Sửa node")
        delete_action = menu.addAction("Xóa node")

        action = menu.exec_(self.table.viewport().mapToGlobal(pos))

        selected_row = self.table.currentRow()

        if action == add_action:
            self.add_or_edit_node()
        elif action == edit_action and selected_row >= 0:
            self.add_or_edit_node(selected_row)
        elif action == delete_action and selected_row >= 0:
            self.delete_node(selected_row)

    # Thêm hoặc sửa node
    def add_or_edit_node(self, row=None):
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Thêm/Sửa Proxy")
        dialog.setModal(True)
        
        layout = QVBoxLayout(dialog)

        protocol_box = QComboBox()
        protocol_box.addItems(["socks5", "http", "socks4"])
        layout.addWidget(QtWidgets.QLabel("Chọn giao thức:"))
        layout.addWidget(protocol_box)

        ip_edit = QLineEdit()
        layout.addWidget(QtWidgets.QLabel("Nhập IP:"))
        layout.addWidget(ip_edit)

        port_edit = QLineEdit()
        layout.addWidget(QtWidgets.QLabel("Nhập Port:"))
        layout.addWidget(port_edit)

        user_edit = QLineEdit()
        layout.addWidget(QtWidgets.QLabel("Nhập User (tùy chọn):"))
        layout.addWidget(user_edit)

        pass_edit = QLineEdit()
        pass_edit.setEchoMode(QLineEdit.Password)  # Ẩn mật khẩu khi nhập
        layout.addWidget(QtWidgets.QLabel("Nhập Password (tùy chọn):"))
        layout.addWidget(pass_edit)

        if row is not None:
            # Điền sẵn thông tin khi chỉnh sửa
            protocol_box.setCurrentText(self.table.item(row, 0).text())
            ip_edit.setText(self.table.item(row, 1).text())
            port_edit.setText(self.table.item(row, 2).text())
            user_edit.setText(self.table.item(row, 3).text())
            pass_edit.setText(self.passwords.get(row, ""))  # Lấy mật khẩu thực tế từ bộ nhớ

        button_box = QHBoxLayout()
        submit_button = QPushButton("Lưu")
        submit_button.clicked.connect(dialog.accept)
        button_box.addWidget(submit_button)

        layout.addLayout(button_box)
        
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            protocol = protocol_box.currentText()
            ip = ip_edit.text()
            port = port_edit.text()
            user = user_edit.text()
            password = pass_edit.text()

            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                QMessageBox.critical(self, "Lỗi", "Địa chỉ IP không hợp lệ!")
                return
            if not (1 <= int(port) <= 65535):
                QMessageBox.critical(self, "Lỗi", "Port không hợp lệ!")
                return

            conn = sqlite3.connect('proxies.db')
            c = conn.cursor()

            if row is None:
                # Thêm node mới
                c.execute("INSERT INTO proxies (protocol, ip, port, user, pass) VALUES (?, ?, ?, ?, ?)",
                          (protocol, ip, port, user, password))
            else:
                # Cập nhật node hiện có
                c.execute("UPDATE proxies SET protocol=?, ip=?, port=?, user=?, pass=? WHERE rowid=?",
                          (protocol, ip, int(port), user, password, row + 1))

            conn.commit()
            conn.close()
            self.load_proxies()

    # Xóa node
    def delete_node(self, row):
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        c.execute("DELETE FROM proxies WHERE rowid=?", (row + 1,))
        conn.commit()
        conn.close()
        self.load_proxies()

# Chạy ứng dụng
if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    window = ProxyManager()
    window.show()
    sys.exit(app.exec_())
