import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QMessageBox, QStackedWidget, QFileDialog, QInputDialog,QLineEdit
from PySide6.QtCore import Qt
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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

        self.button3 = QPushButton("聊天", self.central_widget)
        self.button3.setGeometry(540, 650, 200, 50)
        self.button3.clicked.connect(self.open_chat_window)

        self.button4 = QPushButton("生成密钥对", self.central_widget)
        self.button4.setGeometry(100, 800, 200, 50)
        self.button4.clicked.connect(self.generate_key_pair)

        self.button5 = QPushButton("退出", self.central_widget)
        self.button5.setGeometry(1000, 800, 200, 50)
        self.button5.clicked.connect(self.close)

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
    
    def open_chat_window(self):
        chat_module = importlib.import_module('chat')
        chat_app = chat_module.ChatWindow()
        self.central_widget.addWidget(chat_app)
        self.central_widget.setCurrentWidget(chat_app)
    def save_encrypted_text(self):
        if self.ciphertext is None:
            QMessageBox.critical(self, "错误", "没有加密的文本")
            return
        # 保存加密后的文本到文件
        file_name, _ = QFileDialog.getSaveFileName(self, "保存加密后的文本", "", "文本文件(*.txt)")
        if file_name:
            with open(file_name, "wb") as file:
                file.write(self.encrypted_text_display.toPlainText().encode('utf-8'))
            QMessageBox.information(self, "成功", "加密后的文本保存成功")


    def generate_key_pair(self):
        # 获取用户名（Bob或Alice）
        user_name, ok = QInputDialog.getItem(self, "创建公钥密钥对", "创建公钥密钥对:", ["BOB", "Alice"], 0, False)

        if not ok:
            return  # 用户取消了操作

        password, ok = QInputDialog.getText(self, "自定义密码", "请输入密码:", QLineEdit.Password)
        if not ok:
            return  # 用户取消了操作

        password = password.encode('utf-8')

        # 创建用户文件夹
        user_folder = f"{user_name.lower()}_keys"
        os.makedirs(user_folder, exist_ok=True)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )

        private_key_file = os.path.join(user_folder, "private_key.pem")
        with open(private_key_file, "wb") as key_file:
            key_file.write(private_pem)

        # 设置私钥文件为不可读写
        os.chmod(private_key_file, 0o400)

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file = os.path.join(user_folder, "public_key.pem")
        with open(public_key_file, "wb") as key_file:
            key_file.write(public_pem)

        QMessageBox.information(self, "成功", f"{user_name}的密钥保存成功")
        public_key = None
        private_key = None

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()
