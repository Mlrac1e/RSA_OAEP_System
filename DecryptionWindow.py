import sys
import os
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QMessageBox, QFileDialog,QInputDialog,QLineEdit
from PySide6.QtGui import QFont
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from main import MainWindow

class RSAOAEPDecryptionAPP(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setFixedSize(1280, 960)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # 解密文本输入框
        input_layout = QHBoxLayout()
        self.encrypted_text_input = QTextEdit()
        self.encrypted_text_input.setPlaceholderText("输入要解密的文本")
        input_layout.addWidget(self.encrypted_text_input)
        layout.addLayout(input_layout)

        # 解密按钮
        self.decrypt_button = QPushButton("解密")
        self.decrypt_button.clicked.connect(self.decrypt_text)
        layout.addWidget(self.decrypt_button)

        # 保存解密结果按钮
        self.save_button = QPushButton("保存解密结果")
        self.save_button.clicked.connect(self.save_decrypted_text)
        layout.addWidget(self.save_button)

        # 解密消息(只读ReadOnly)
        self.decrypted_text_display = QTextEdit()
        self.decrypted_text_display.setPlaceholderText("解密后的文本将在这里显示")
        self.decrypted_text_display.setReadOnly(True)
        font = QFont()
        font.setPointSize(25)
        self.decrypted_text_display.setFont(font)
        layout.addWidget(self.decrypted_text_display)

        # 返回主页按钮
        self.return_button = QPushButton("返回主页")
        self.return_button.clicked.connect(self.close_window)
        layout.addWidget(self.return_button)

        # 设置布局
        central_widget.setLayout(layout)
        self.decrypted_text = None

    def decrypt_text(self):
        if self.encrypted_text_input.toPlainText() == "":
            QMessageBox.critical(self, "错误", "没有解密的文本")
            return

        sender, ok = QInputDialog.getItem(self, "使用密钥", "使用密钥:", ["Bob", "Alice"], 0, False)
        if not ok:
            return
        user_folder = f"{sender.lower()}_keys"
        private_key_file = os.path.join(user_folder, "private_key.pem")

        if not os.path.exists(private_key_file):
            QMessageBox.critical(self, "错误", f"{sender}的私钥文件不存在")
            return
        
        password, ok = QInputDialog.getText(self, "解密私钥", "请输入私钥密码:", QLineEdit.Password)
        if not ok:
            return

        password = password.encode('utf-8')

        

        try:
            with open(private_key_file, "rb") as key_file:
                if key_file is None:
                    QMessageBox.critical(self, "错误", f"{name}的私钥文件错误")
                    return

                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password,
                    backend=default_backend()
                )
        except ValueError:
            QMessageBox.critical(self, "错误", "密码错误")
            return

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

    def save_decrypted_text(self):
        if self.decrypted_text is None:
            QMessageBox.critical(self, "错误", "没有解密的文本")
            return

        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getSaveFileName(self, "保存解密结果", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_name:
            with open(file_name, "w") as file:
                file.write(self.decrypted_text)
            QMessageBox.information(self, "成功", "解密结果已保存")
    
    def close_window(self):
        self.close()  # 关闭子窗口
        MainWindow.setCentralWidget(MainWindow.central_widget)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RSAOAEPDecryptionAPP()
    window.show()
    sys.exit(app.exec_())
