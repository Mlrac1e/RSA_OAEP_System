import sys
import os

from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QMessageBox, QFileDialog
from PySide6.QtGui import QFont
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from main import MainWindow

class RSAOAEPDecryptionAPP(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("RSA-OAEP Decryption")
        self.setFixedSize(1280, 960)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Encrypted text input
        input_layout = QHBoxLayout()
        self.encrypted_text_input = QTextEdit()
        self.encrypted_text_input.setPlaceholderText("输入要解密的文本")
        input_layout.addWidget(self.encrypted_text_input)
        layout.addLayout(input_layout)

        # Decryption button
        self.decrypt_button = QPushButton("解密")
        self.decrypt_button.clicked.connect(self.decrypt_text)
        layout.addWidget(self.decrypt_button)

        # Save button
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
       
        
        central_widget.setLayout(layout)

        self.decrypted_text = None

    def decrypt_text(self):
        # Load the private key from a file
        private_key_file = "private_key.pem"
        if not os.path.exists(private_key_file):
            QMessageBox.critical(self, "错误", "私钥文件不存在")
            return
        
        with open(private_key_file, "rb") as key_file:
            if key_file is None:
                QMessageBox.critical(self, "错误", "公钥错误")
                return
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

        if key_file is None:
            return
    
        # Get the text to decrypt from the input field
        ciphertext_hex = self.encrypted_text_input.toPlainText()
        ciphertext = bytes.fromhex(ciphertext_hex)

        # Decrypt the text with the private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Display the decrypted text
        self.decrypted_text = plaintext.decode('utf-8')
        self.decrypted_text_display.setPlainText(self.decrypted_text)

    def save_decrypted_text(self):
        if self.decrypted_text is None:
            QMessageBox.critical(self, "错误", "没有解密的文本")

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
