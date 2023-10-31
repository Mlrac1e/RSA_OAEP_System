
import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton,QMessageBox
from PySide6.QtCore import Qt
from EncryptionWindow import RSAOAEPEncryptionApp
from DecryptionWindow import RSAOAEPDecryptionAPP


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("主页")
        self.setFixedSize(1280, 960)  # 设置窗口大小为1280x960c

        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, stop: 0 #FF6EFF, stop: 0.5 #6E91FF, stop: 1 #B76EFF);
            }

            QLabel {
                font-size: 24px;
                color: #333333;
                padding: 20px;
                background-color: #ffffff;
                border-radius: 25px;
            }

            QPushButton {
                font-size: 18px;
                color: #ffffff;
                background-color: #007bff;
                padding: 10px 20px;
                border-radius: 25px;
            }
            QPushButton:pressed {
                background-color: #0056b3;
            }

            QPushButton:hover {
                background-color: #0056b3;
            }
        """)

        self.title_label = QLabel("RSA-OAEP的实现", self)
        self.title_label.setGeometry(400, 200, 480, 100)  # 设置标题的位置和大小
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.button1 = QPushButton("消息加密", self)
        self.button1.setGeometry(400, 400, 200, 50)  # 设置按钮1的位置和大小
        self.button1.clicked.connect(self.open_RSAOAEPEncryptionApp)  # 连接按钮的点击事件到槽函数

        self.button2 = QPushButton("消息解密", self)
        self.button2.setGeometry(680, 400, 200, 50)  # 设置按钮2的位置和大小
        self.button2.clicked.connect(self.open_RSAOAEPDecryptionApp)  # 连接按钮的点击事件到槽函数

        self.button3 = QPushButton("退出", self)
        self.button3.setGeometry(1000, 800, 200, 50)
        self.button3.clicked.connect(self.close)


    def open_RSAOAEPEncryptionApp(self):
        encryption_app = RSAOAEPEncryptionApp()  
        MainWindow.close(self)
        encryption_app.show()
        encryption_app.exec()
       

    
    def open_RSAOAEPDecryptionApp(self):
        decryption_app = RSAOAEPDecryptionAPP()
        MainWindow.close(self)
        decryption_app.show()
        decryption_app.exec()
        
    """
    def closeEvent(self, event):
        reply = QMessageBox.question(self, "退出", "你确定要退出吗？", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()
    """
    
    
    


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()
