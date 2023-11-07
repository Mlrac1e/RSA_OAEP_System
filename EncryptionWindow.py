import sys
import os
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QFileDialog, QMessageBox, QInputDialog,QLineEdit
from PySide6.QtGui import QFont
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from main import MainWindow

#定义RSA_OAEP_MAX_SIZE
#MAX_Message_Size = keyLength - 2 - 2 * hashLength
#SHA256 = 32
#MAX_Message_Size = 256 - 2 - 2 * 32 = 190

RSA_OAEP_MAX_SIZE = 190

class RSAOAEPEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
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
        # 获取接收者（Bob或Alice）
        recipient, ok = QInputDialog.getItem(self, "使用密钥", "使用密钥:", ["bob", "alice"], 0, False)
        if not ok:
            return  # 用户取消了操作

        plaintext = self.plain_text_input.toPlainText()
        if plaintext == "":
            QMessageBox.critical(self, "错误", "输入为空")
            return

        plaintext_bytes = plaintext.encode('utf-8')
        if len(plaintext_bytes) > RSA_OAEP_MAX_SIZE:
            QMessageBox.critical(self, "错误", "输入过长")
            return
        
        user_folder = f"{recipient.lower()}_keys"
        public_key_file = os.path.join(user_folder, "public_key.pem")

        if not os.path.exists(public_key_file):
            QMessageBox.critical(self, "错误", f"{recipient}的公钥文件不存在")
            return

        with open(public_key_file, "rb") as key_file:
            if key_file is None:
                QMessageBox.critical(self, "错误", f"{recipient}的公钥错误")
                return

            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

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
    
    def decrypt_text(self,name,plaintext):
        if self.encrypted_text_input.toPlainText() == "":
            QMessageBox.critical(self, "错误", "没有解密的文本")
            return

        sender, ok = QInputDialog.getItem(self, "使用密钥", "使用密钥:", ["Bob", "Alice"], 0, False)
        if not ok:
            return

        password, ok = QInputDialog.getText(self, "解密私钥", "请输入私钥密码:", QLineEdit.Password)
        if not ok:
            return

        password = password.encode('utf-8')

        user_folder = f"{sender.lower()}_keys"
        private_key_file = os.path.join(user_folder, "private_key.pem")

        if not os.path.exists(private_key_file):
            QMessageBox.critical(self, "错误", f"{sender}的私钥文件不存在")
            return

        with open(private_key_file, "rb") as key_file:
            if key_file is None:
                QMessageBox.critical(self, "错误", f"{sender}的私钥文件错误")
                return

            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )

        ciphertext_hex = self.encrypted_text_input.toPlainText()
        ciphertext = bytes.fromhex(ciphertext_hex)

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.decrypted_text = plaintext.decode('utf-8')
        self.decrypted_text_display.setPlainText(self.decrypted_text)
    #返回主页
    def close_window(self):
        self.close()  # 关闭子窗口
        MainWindow.setCentralWidget(MainWindow.central_widget)
    


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RSAOAEPEncryptionApp()
    window.show()
    sys.exit(app.exec_())

