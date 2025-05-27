# Hướng dẫn Thiết lập Dự án Flask API và PostgreSQL 

Tài liệu này cung cấp hướng dẫn chi tiết về cách thiết lập cơ sở dữ liệu PostgreSQL, cấu hình proxy, tạo khóa SSL/TLS và JWT Secret Key cho dự án.
Clone source code ứng dụng Android và API backend ở nhánh Viramind

---

## 1. Thiết lập Database PostgreSQL

Dưới đây là các câu lệnh SQL để tạo bảng `users` và `apk_files` trong cơ sở dữ liệu PostgreSQL.

**Bảng `users`:** Lưu trữ thông tin người dùng bao gồm tên người dùng, email và mật khẩu đã hash.

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100),
    password VARCHAR(255) NOT NULL, -- Store hashed password
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Bảng `apk_files`:** Lưu trữ thông tin về các tệp APK đã tải lên, bao gồm tên tệp, đường dẫn và liên kết với người dùng đã tải lên.

```sql
CREATE TABLE apk_files (
    id SERIAL PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## 2. Thiết lập Proxy để Kết nối từ Android Virtual Device (ADV) đến Flask

Khi chạy Flask server trên máy host và cần kết nối từ một Android Virtual Device (ADV), cần thiết lập port proxy.

* **Mở Proxy:**
    Lệnh này sẽ chuyển tiếp các yêu cầu đến cổng `5000` trên máy host (nghe trên `0.0.0.0`) đến địa chỉ IP cụ thể của máy host (ví dụ: `192.168.231.165`) trên cổng `5000`.

    ```bash
    netsh interface portproxy add v4tov4 listenport=5000 connectaddress=192.168.231.165 connectport=5000
    ```
    **Lưu ý:** Thay `192.168.231.165` bằng **địa chỉ IP thực của máy tính host** mà Flask server đang chạy.

* **Đóng Proxy:**
    Nếu muốn xóa thiết lập proxy này, sử dụng lệnh:

    ```bash
    netsh interface portproxy delete v4tov4 listenport=5000 listenaddress=*
    ```

---

## 3. Tạo Khóa và Chứng chỉ SSL/TLS

Để bật HTTPS cho Flask server, cần tạo khóa riêng (private key) và chứng chỉ (certificate).

1.  **Tạo Khóa Riêng (Private Key):**
    Lệnh này tạo một khóa RSA 2048-bit và lưu vào file `server.key`.

    ```bash
    openssl genrsa -out server.key 2048
    ```

2.  **Tạo Chứng chỉ Tự Ký (Self-Signed Certificate):**
    Lệnh này tạo một chứng chỉ X.509 tự ký có giá trị 365 ngày và lưu vào file `server.crt`.
    * `CN=10.0.2.2`: Đây là địa chỉ IP đặc biệt mà Android Emulator sử dụng để tham chiếu đến `localhost` (máy host).
    * `IP:192.168.231.165`: **Cần thay `<your-IP>` bằng địa chỉ IP thực của máy tính host**  để các thiết bị khác trên mạng cũng có thể kết nối.

    ```bash
    openssl req -x509 -new -nodes -key server.key -sha256 -days 365 -out server.crt \
    -subj "/C=VN/ST=HCM/L=HCM/O=MyOrg/OU=MyUnit/CN=10.0.2.2" \
    -addext "subjectAltName=IP:10.0.2.2,IP:192.168.231.165"
    ```

    **Lưu ý:** Đặt `server.key` và `server.crt` vào thư mục `certs` trong dự án (hoặc cấu hình đường dẫn phù hợp trong `app.py`). Sau đó copy `server.crt` vào thư mục raw của Ứng dụng Android

---

## 4. Tạo Khóa JWT (JSON Web Token)
Để bảo mật các API endpoints bằng JWT, cần một khóa bí mật (secret key) mạnh. Dưới đây là cách tạo một khóa ngẫu nhiên bằng Python:

```python
import os
import binascii
import base64

# Tạo 32 byte ngẫu nhiên (tương đương 256 bit)
secure_random_bytes = os.urandom(32)

# Chuyển đổi thành chuỗi hex
jwt_secret_key_hex = binascii.hexlify(secure_random_bytes).decode('utf-8')
print("Your JWT Secret Key (Hex):", jwt_secret_key_hex)

# Hoặc chuyển đổi thành chuỗi Base64 (thường được ưu tiên hơn cho JWT)
jwt_secret_key_base64 = base64.urlsafe_b64encode(secure_random_bytes).decode('utf-8').rstrip('=')
print("Your JWT Secret Key (Base64):", jwt_secret_key_base64)
```
**Cách sử dụng:**
Chọn một trong hai định dạng (Hex hoặc Base64) và lưu khóa này vào biến môi trường (environment variable) trong file `.env` của dự án, ví dụ:
```
JWT_SECRET_KEY=your_generated_base64_or_hex_key_here
```
Sau đó, tải nó vào ứng dụng Flask của mình bằng `dotenv`.
## 5. Cài đặt Dependencies
Để chạy dự án này, cần cài đặt các thư viện Python cần thiết.
1. **Tạo môi trường ảo (Khuyến nghị):**
 ```bash
    python3 -m venv .venv
 ```
2. **Kích hoạt môi trường ảo (Trên Kali Linux):**
```
source .venv/bin/activate
```
3. **Sau đó, để cài đặt tất cả các thư viện từ file requirements.txt:**
```
pip install -r requirements.txt
```
