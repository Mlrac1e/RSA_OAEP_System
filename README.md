# RSA_OAEP_System
 基于pyQt6的RSA-OAEP加密系统以及本地加解密通信模拟
## 功能
 生成RSA公私钥对
    加密消息\
    使用口令解密消息\
    模拟BOB和ALICE的通信\
    (BOB使用BOB公钥加密，Alice使用BOB的私钥解密；Alice使用Alice公钥加密，BOB使用Alice的私钥解密)


## 文件结构
```
├── README.md
├── __pycache__
├── main.py
├── DecryptionWindow.py
├── EncryptionWindow.py
├── requirements.txt
├── chat.py
```

## 环境配置
安装python环境
```
    conda create -n RSA_OAEP python=3.9 
```
激活python环境
```
    conda activate RSA_OAEP 
```
安装程序环境
```
    pip install -r requirements.txt 
```


  