import sys
import os
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QMessageBox, QLabel,QInputDialog,QLineEdit
from PySide6.QtGui import QFont
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from main import MainWindow

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setFixedSize(1280, 960)
        self.initUI()

    def initUI(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout()

        # Create BOB's chat container
        bob_container = QWidget()
        bob_layout = QVBoxLayout()
        bob_title_label = QLabel("BOB")
        bob_layout.addWidget(bob_title_label)

        bob_send_plain_text = QTextEdit()
        bob_layout.addWidget(bob_send_plain_text)

        bob_send_encrypted_text = QTextEdit()
        bob_send_encrypted_text.setReadOnly(True)
        bob_layout.addWidget(bob_send_encrypted_text)

        bob_receive_plain_text = QTextEdit()
        bob_receive_plain_text.setReadOnly(True)
        bob_layout.addWidget(bob_receive_plain_text)

        bob_receive_decrypted_text = QTextEdit()
        bob_receive_decrypted_text.setReadOnly(True)
        bob_layout.addWidget(bob_receive_decrypted_text)

        bob_container.setLayout(bob_layout)
        layout.addWidget(bob_container)

        # 创建按钮容器
        button_container = QWidget()
        button_layout = QVBoxLayout()

        # 创建一个按钮用于发送到 ALICE
        send_to_alice_button = QPushButton("Send to ALICE")
        send_to_alice_button.clicked.connect(self.send_to_alice)
        button_layout.addWidget(send_to_alice_button)

        # 创建一个按钮用于清空所有文本框
        send_to_bob_button = QPushButton("Send to BOB")
        send_to_bob_button.clicked.connect(self.send_to_bob)
        button_layout.addWidget(send_to_bob_button)

        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear)
        button_layout.addWidget(clear_button)

        return_button = QPushButton("返回主页")
        return_button.clicked.connect(self.close_window)
        button_layout.addWidget(return_button)

        button_container.setLayout(button_layout)
        layout.addWidget(button_container)

        # 创建 ALICE 的聊天容器
        alice_container = QWidget()
        alice_layout = QVBoxLayout()
        alice_title_label = QLabel("ALICE")
        alice_layout.addWidget(alice_title_label)

        alice_send_plain_text = QTextEdit()
        alice_layout.addWidget(alice_send_plain_text)

        alice_send_encrypted_text = QTextEdit()
        alice_send_encrypted_text.setReadOnly(True)
        alice_layout.addWidget(alice_send_encrypted_text)

        alice_receive_plain_text = QTextEdit()
        alice_receive_plain_text.setReadOnly(True)
        alice_layout.addWidget(alice_receive_plain_text)

        alice_receive_decrypted_text = QTextEdit()
        alice_receive_decrypted_text.setReadOnly(True)
        alice_layout.addWidget(alice_receive_decrypted_text)

        alice_container.setLayout(alice_layout)
        layout.addWidget(alice_container)

        central_widget.setLayout(layout)
        self.setWindowTitle('Chat Window')
        self.show()

        # 初始化 bobmc 和 alicemc 变量
        self.bobmc = {
            "send_plain_text": bob_send_plain_text,
            "send_encrypted_text": bob_send_encrypted_text,
            "receive_plain_text": bob_receive_plain_text,
            "receive_decrypted_text": bob_receive_decrypted_text
        }

        self.alicemc = {
            "send_plain_text": alice_send_plain_text,
            "send_encrypted_text": alice_send_encrypted_text,
            "receive_plain_text": alice_receive_plain_text,
            "receive_decrypted_text": alice_receive_decrypted_text
        }

    def send_to_alice(self):
        # 获取 BOB 发送的消息
        plaintext = self.bobmc["send_plain_text"].toPlainText()
        if not plaintext:
            QMessageBox.critical(self, "错误", "输入为空")
            return

        # 加密消息
        ciphertext = self.encrypt_text("alice", plaintext)

        # 在 BOB 的界面上显示加密后的消息
        self.bobmc["send_encrypted_text"].setPlainText(ciphertext)

        # 在 ALICE 的界面上显示收到的消息
        self.alicemc["receive_plain_text"].setPlainText(ciphertext)
        
  
        # 在 ALICE 的界面上解密并显示消息
        decrypted_text = self.decrypt_text("alice", ciphertext)
        self.alicemc["receive_decrypted_text"].setPlainText(decrypted_text)

    def send_to_bob(self):
        # 获取 ALICE 发送的消息
        plaintext = self.alicemc["send_plain_text"].toPlainText()
        if not plaintext:
            QMessageBox.critical(self, "错误", "输入为空")
            return

        # 加密消息
        ciphertext = self.encrypt_text("bob", plaintext)

        # 在 ALICE 的界面上显示加密后的消息
        self.alicemc["send_encrypted_text"].setPlainText(ciphertext)

        # 在 BOB 的界面上显示收到的消息
        self.bobmc["receive_plain_text"].setPlainText(ciphertext)

        # 在 BOB 的界面上解密并显示消息
        decrypted_text = self.decrypt_text("bob", ciphertext)

        self.bobmc["receive_decrypted_text"].setPlainText(decrypted_text)

    def encrypt_text(self, name, plaintext):
        plaintext = plaintext
        if plaintext == "":
            QMessageBox.critical(self, "错误", "输入为空")
            return

        plaintext_bytes = plaintext.encode('utf-8')
        if len(plaintext_bytes) > 190:
            QMessageBox.critical(self, "错误", "输入过长")
            return
        
        user_folder = f"{name.lower()}_keys"
        public_key_file = os.path.join(user_folder, "public_key.pem")

        if not os.path.exists(public_key_file):
            QMessageBox.critical(self, "错误", f"{name}的公钥文件不存在")
            return

        with open(public_key_file, "rb") as key_file:
            if key_file is None:
                QMessageBox.critical(self, "错误", f"{name}的公钥错误")
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
        return ciphertext.hex()

    def decrypt_text(self, name, ciphertext):
        if ciphertext == "":
            QMessageBox.critical(self, "错误", "没有解密的文本")
            return
        user_folder = f"{name.lower()}_keys"
        private_key_file = os.path.join(user_folder, "private_key.pem")

        if not os.path.exists(private_key_file):
            QMessageBox.critical(self, "错误", f"{name}的私钥文件不存在")
            return


        name = name

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
        
        ciphertext_hex = ciphertext
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
        return self.decrypted_text

    def clear(self):
        self.bobmc["send_plain_text"].clear()
        self.bobmc["send_encrypted_text"].clear()
        self.bobmc["receive_plain_text"].clear()
        self.bobmc["receive_decrypted_text"].clear()

        self.alicemc["send_plain_text"].clear()
        self.alicemc["send_encrypted_text"].clear()
        self.alicemc["receive_plain_text"].clear()
        self.alicemc["receive_decrypted_text"].clear()
    
    def close_window(self):
        self.close()  # 关闭子窗口
        MainWindow.setCentralWidget(MainWindow.central_widget)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    chat_window = ChatWindow()
    chat_window.show()
    sys.exit(app.exec_())
