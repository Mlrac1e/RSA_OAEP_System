import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QMessageBox, QStackedWidget
from PySide6.QtCore import Qt

import importlib

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA-OAEP的实现")
        self.setFixedSize(1280, 960)  # 设置窗口大小为1280x960
        self.central_widget = QStackedWidget(self)
        
        self.setStyleSheet("""
            QMainWindow {
                background: url(image/Background1.jpg);
            }

            QLabel {
            font-size: 48px;
            color: #333333;
            padding: 20px;
            background-color: rgba(255, 255, 255, 0.5); 
            border-radius: 25px;
            }

            QPushButton {
                font-size: 18px;ss
                color: #ffffff;
                background-color: rgba(255, 255, 255, 0.42); 
                padding: 10px 20px;
                border-radius: 25px;
            }
            QPushButton:pressed {
                background-color: rgba(255, 255, 255, 0.7);
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.74)
            }
        """)

        self.title_label = QLabel("RSA-OAEP的实现", self.central_widget)
        self.title_label.setGeometry(400, 300, 480, 100)  # 设置标题的位置和大小
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.button1 = QPushButton("消息加密", self.central_widget)
        self.button1.setGeometry(400, 550, 200, 50)  # 设置按钮1的位置和大小
        self.button1.clicked.connect(self.open_RSAOAEPEncryptionApp)  # 连接按钮的点击事件到槽函数

        self.button2 = QPushButton("消息解密", self.central_widget)
        self.button2.setGeometry(680, 550, 200, 50)  # 设置按钮2的位置和大小
        self.button2.clicked.connect(self.open_RSAOAEPDecryptionApp)  # 连接按钮的点击事件到槽函数

        self.button3 = QPushButton("退出", self.central_widget)
        self.button3.setGeometry(1000, 800, 200, 50)
        self.button3.clicked.connect(self.close)

        self.setCentralWidget(self.central_widget)

    def open_RSAOAEPEncryptionApp(self):
        encryption_module = importlib.import_module('EncryptionWindow')
        encryption_app = encryption_module.RSAOAEPEncryptionApp()
        self.central_widget.addWidget(encryption_app)
        self.central_widget.setCurrentWidget(encryption_app)

    def open_RSAOAEPDecryptionApp(self):
        decryption_module = importlib.import_module('DecryptionWindow')
        decryption_app = decryption_module.RSAOAEPDecryptionAPP()
        self.central_widget.addWidget(decryption_app)
        self.central_widget.setCurrentWidget(decryption_app)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()
