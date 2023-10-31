import sys
import os

from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QFileDialog,QMessageBox
from PySide6.QtGui import QFont
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from main import MainWindow

class RSAOAEPEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA-OAEP Encryption")
        self.setFixedSize(1280, 960)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # 文本输入
        input_layout = QHBoxLayout()
        self.plain_text_input = QTextEdit()
        font = QFont()
        font.setPointSize(25)
        self.plain_text_input.setFont(font)
        self.plain_text_input.setPlaceholderText("输入要加密的文本")
        input_layout.addWidget(self.plain_text_input)
        layout.addLayout(input_layout)

        # 加密按钮
        self.encrypt_button = QPushButton("加密")
        self.encrypt_button.clicked.connect(self.encrypt_text)
        layout.addWidget(self.encrypt_button)

        # 保存按钮
        self.save_button = QPushButton("保存加密结果")
        self.save_button.clicked.connect(self.save_encrypted_text)
        layout.addWidget(self.save_button)

        # 生成密钥按钮
        self.generate_key_button = QPushButton("生成密钥")
        self.generate_key_button.clicked.connect(self.generate_key_pair)
        layout.addWidget(self.generate_key_button)

        # 加密后的文本显示(Readonly)
        self.encrypted_text_display = QTextEdit()
        self.encrypted_text_display.setReadOnly(True)
        self.encrypted_text_display.setPlaceholderText("加密后的文本将在这里显示")
        
        layout.addWidget(self.encrypted_text_display)
        
        # 返回主页按钮
        self.return_button = QPushButton("返回主页")
        self.return_button.clicked.connect(self.close_window)
        layout.addWidget(self.return_button)
        
       
        central_widget.setLayout(layout)

        self.ciphertext = None

    def encrypt_text(self):
        
        plaintext = self.plain_text_input.toPlainText()
        if plaintext == "":
            QMessageBox.critical(self, "错误", "输入为空")
            return
        
        # 如果没有私钥和公钥，提示用户没有公钥与私钥
        public_key_file = "public_key.pem"
        if not os.path.exists(public_key_file):
            QMessageBox.critical(self, "错误", "公钥文件不存在")
            return
        
        with open(public_key_file, "rb") as key_file:
            if key_file is None:
                QMessageBox.critical(self, "错误", "公钥错误")
                return
        
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        
        
        
        # 公钥解密
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 显示加密后的文本
        self.ciphertext = ciphertext
        self.encrypted_text_display.setPlainText(ciphertext.hex())

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
        # 生成密钥对
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Save private key to a file
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private_key.pem", "wb") as key_file:
            key_file.write(private_pem)

        # Get the public key
        public_key = private_key.public_key()

        # Save public key to a file
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("public_key.pem", "wb") as key_file:
            key_file.write(public_pem)
        #密钥保存成功
        QMessageBox.information(self, "成功", "密钥保存成功")
    
    def close_window(self):
        self.close()  # 关闭子窗口
        MainWindow.setCentralWidget(MainWindow.central_widget)
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RSAOAEPEncryptionApp()
    window.show()
    sys.exit(app.exec_())
