
# 🔐 Bảo vệ Thông Tin Nhạy Cảm trong Cơ Sở Dữ Liệu (Triple DES + AES)

## 📌 Giới thiệu
Dự án này xây dựng một hệ thống web bảo mật bằng Python và Flask, cho phép người dùng nhập, lưu trữ và truy xuất thông tin cá nhân (CCCD, BHXH, tài khoản ngân hàng) dưới dạng **mã hóa** bằng hai thuật toán:
- 🔒 Triple DES (3DES) – dùng cho CCCD
- 🔐 AES-256 – dùng cho BHXH và tài khoản ngân hàng

Hệ thống đảm bảo **chỉ người có quyền** mới có thể xem thông tin thật, và mọi dữ liệu được mã hóa an toàn khi lưu vào file JSON.

## 🧠 Công nghệ sử dụng

| Thành phần      | Mô tả |
|----------------|------|
| **Python 3.10+** | Ngôn ngữ lập trình chính |
| **Flask**       | Web framework |
| **PyCryptodome** | Thư viện mã hóa AES, Triple DES |
| **JSON**        | Mô phỏng cơ sở dữ liệu |
| **.env**        | Lưu key mã hóa và mật khẩu admin |
| **Logging**     | Ghi log hệ thống và hoạt động |

## 🎯 Tính năng chính

- ✅ Nhập thông tin người dùng (Họ tên, CCCD, BHXH, tài khoản ngân hàng)
- ✅ Mã hóa thông tin trước khi lưu
- ✅ Đăng nhập người dùng bằng CCCD
- ✅ Đăng nhập quản trị viên (admin) bằng mật khẩu
- ✅ Xem, sửa, xóa thông tin người dùng (chỉ admin)
- ✅ Ghi log mọi hoạt động truy cập
- ✅ Giao diện dễ sử dụng, mở trình duyệt tự động khi chạy server

## 🔐 Bảo mật

- ✅ Sử dụng mã hóa đối xứng (AES-256, Triple DES) + IV ngẫu nhiên
- ✅ Không lưu dữ liệu thô (plaintext)
- ✅ Xác thực quyền truy cập (admin và user)
- ✅ Giới hạn đăng nhập sai (chống brute-force)
- ✅ Ghi log chi tiết: IP, thời gian, hành vi

## 🧪 Thử nghiệm

| Thuật toán | Mã hóa 1000 lần | Giải mã 1000 lần |
|------------|-----------------|------------------|
| Triple DES | ~2.45 giây      | ~2.20 giây       |
| AES-256    | ~1.10 giây      | ~1.00 giây       |

- Hệ thống hoạt động ổn định với hàng trăm đến hàng nghìn bản ghi.
- Dữ liệu mã hóa thành công và giải mã chính xác.

## 📂 Cấu trúc thư mục

```
📁 project_root/
├── app.py                 # File chính chạy Flask app
├── users.json             # Lưu dữ liệu người dùng (đã mã hóa)
├── .env                   # Lưu key mã hóa và mật khẩu admin
├── system.log             # Ghi log hệ thống
├── templates/             # Giao diện HTML
│   ├── input.html
│   ├── view.html
│   └── ...
```

## 🚀 Chạy ứng dụng

### 1. Cài thư viện:
```bash
pip install -r requirements.txt
```

> File `requirements.txt` gồm:
```
flask
pycryptodome
python-dotenv
```

### 2. Tạo file `.env`:
```env
KEY1=your_triple_des_key
KEY2=your_aes_key
ADMIN_PASSWORD=your_admin_password
```

### 3. Chạy server:
```bash
python app.py
```

Trình duyệt sẽ tự mở trang: [http://127.0.0.1:5000](http://127.0.0.1:5000)

## 🔧 Đề xuất nâng cấp

- 🔐 Tích hợp xác thực đa yếu tố (2FA)
- 🧠 Sử dụng cơ sở dữ liệu thật (MySQL/PostgreSQL) thay JSON
- 🔒 Quản lý khóa bằng Vault/Secret Manager
- 📊 Thêm tính năng phân trang, tìm kiếm, thống kê

## 📚 Tài liệu tham khảo

- [PyCryptodome](https://www.pycryptodome.org/)
- [Flask Docs](https://flask.palletsprojects.com/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Let's Encrypt](https://letsencrypt.org/)
