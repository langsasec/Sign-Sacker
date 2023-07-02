import io
import struct
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QFileDialog, QVBoxLayout, \
    QWidget, QMessageBox
import sys
import os
import shutil
from PyQt5.QtWidgets import QDesktopWidget


class SignSacker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sign-Sacker(签名掠夺者) By 浪飒 (关注浪飒sec公众号)")
        self.setWindowIcon(QIcon('favicon.ico'))  # 设置窗口图标
        self.resize(700, 400)

        # 设置窗口居中显示
        screen = QDesktopWidget().screenGeometry()
        window_size = self.geometry()
        x = int((screen.width() - window_size.width()) / 2)
        y = int((screen.height() - window_size.height()) / 2)
        self.move(x, y)

        widget = QWidget(self)
        layout = QVBoxLayout()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.file1_label = QLabel("受害者:", self)
        layout.addWidget(self.file1_label)

        self.file1_entry = QLineEdit(self)
        layout.addWidget(self.file1_entry)

        self.choose_button1 = QPushButton("选择含有签名的文件", self)
        layout.addWidget(self.choose_button1)
        self.choose_button1.clicked.connect(self.choose_file1)

        self.file2_label = QLabel("掠夺者:", self)
        layout.addWidget(self.file2_label)

        self.file2_entry = QLineEdit(self)
        layout.addWidget(self.file2_entry)

        self.choose_button2 = QPushButton("选择需要伪造签名的文件", self)
        layout.addWidget(self.choose_button2)
        self.choose_button2.clicked.connect(self.choose_file2)

        self.output_label = QLabel("生成文件名:", self)
        layout.addWidget(self.output_label)

        self.output_entry = QLineEdit(self)
        layout.addWidget(self.output_entry)

        self.process_button = QPushButton("生成文件", self)
        layout.addWidget(self.process_button)
        self.process_button.clicked.connect(self.process_files)



        self.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #333;
            }
            QLineEdit, QPushButton {
                font-size: 14px;
                height: 30px;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 6px 12px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px;

                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)


    def choose_file1(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件1", "", "Executable Files (*.exe)")
        if file_name:
            self.file1_entry.setText(file_name)

    def choose_file2(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件2", "", "Executable Files (*.exe)")
        if file_name:
            self.file2_entry.setText(file_name)
            # 自动填充生成文件名的文本框
            base_name = os.path.basename(file_name)
            output_file = os.path.splitext(base_name)[0] + "-Signed.exe"
            self.output_entry.setText(output_file)

    def process_files(self):
        file1_path = self.file1_entry.text()
        file2_path = self.file2_entry.text()
        output_file = self.output_entry.text()
        # 验证文件的有效性
        if not os.path.exists(file1_path) or not os.path.isfile(file1_path):
            self.show_message_box("错误", "文件1无效！")
            return
        if not os.path.exists(file2_path) or not os.path.isfile(file2_path):
            self.show_message_box("错误", "文件2无效！")
            return
        if not file1_path.endswith(".exe"):
            self.show_message_box("错误", "文件1必须是.exe文件！")
            return
        if not file2_path.endswith(".exe"):
            self.show_message_box("错误", "文件2必须是.exe文件！")
            return
        if not output_file.endswith(".exe"):
            self.show_message_box("错误", "生成的文件必须是.exe文件！")
            return
        writeCert(copyCert(file1_path), file2_path, output_file)
        message = f"签名已写入：{output_file}"
        self.show_message_box("生成文件", message)

    def show_message_box(self, title, message):
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec_()


# 获取可执行文件的一些信息，包括PE头中的各个字段的数值。
def gather_file_info_win(binary):
    """
    Borrowed from BDF...
    I could just skip to certLOC... *shrug*
    """
    flItms = {}
    binary = open(binary, 'rb')
    binary.seek(int('3C', 16))
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    binary.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
    binary.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
    binary.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

    binary.seek(flItms['OptionalHeader_start'])
    flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                      binary.read(4))[0]
    flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
    flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
    flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
    if flItms['Magic'] != 0x20B:
        flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]

    if flItms['Magic'] == 0x20B:
        flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
    else:
        flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                          binary.read(2))[0]
    flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                          binary.read(2))[0]
    flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfImageLoc'] = binary.tell()
    flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
    flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
    flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
    flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
    if flItms['Magic'] == 0x20B:
        flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

    else:
        flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
    flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
    flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]

    flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()

    flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['CertTableLOC'] = binary.tell()
    flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
    flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
    binary.close()
    return flItms


# 用于从可执行文件中提取签名证书
def copyCert(exe):
    flItms = gather_file_info_win(exe)

    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        # 无证书则退出
        sys.exit(-1)

    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert

# 写入证书并输出
def writeCert(cert, exe, output):
    flItms = gather_file_info_win(exe)

    if not output:
        output = str(exe) + "_signed"

    shutil.copy2(exe, output)

    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SignSacker()
    window.show()
    sys.exit(app.exec_())
