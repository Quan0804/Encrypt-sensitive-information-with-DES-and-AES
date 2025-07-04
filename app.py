from flask import Flask, render_template, request, redirect, url_for, flash, session
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import webbrowser
import threading
import binascii
from functools import wraps
import json

# Load biến môi trường
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', get_random_bytes(32).hex())

# Logging
logging.basicConfig(filename='system.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load keys từ .env
key1_hex = os.getenv("TRIPLE_DES_KEY")
key2 = os.getenv("AES_KEY")
admin_password = os.getenv("ADMIN_PASSWORD")

# Kiểm tra key
if not key1_hex or not key2 or not admin_password:
    raise ValueError("⚠️ Thiếu khóa TRIPLE_DES_KEY, AES_KEY hoặc ADMIN_PASSWORD trong file .env.")

try:
    key1 = binascii.unhexlify(key1_hex)
except Exception:
    raise ValueError("TRIPLE_DES_KEY phải là chuỗi hex hợp lệ (32 hoặc 48 ký tự hex). Ví dụ: 0123456789abcdef0123456789abcdef0123456789abcdef")

if len(key1) not in [16, 24]:
    raise ValueError("TRIPLE_DES_KEY phải là hex có độ dài 32 hoặc 48 ký tự (tương ứng 16 hoặc 24 bytes). Ví dụ: 0123456789abcdef0123456789abcdef0123456789abcdef")

key2 = key2.encode()

users_db = []
login_attempts = {}

def save_users():
    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users_db, f, ensure_ascii=False, indent=2)

def load_users():
    global users_db
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            users_db = json.load(f)
    except FileNotFoundError:
        users_db = []

load_users()

# ====== Security Decorators ======
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Vui lòng đăng nhập trước!', 'danger')
            return redirect(url_for('view_users'))
        return f(*args, **kwargs)
    return decorated_function

def check_login_attempts():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_attempt'] = datetime.now().timestamp()
    
    # Reset attempts after 30 minutes
    if datetime.now().timestamp() - session['last_attempt'] > 1800:
        session['login_attempts'] = 0
    
    if session['login_attempts'] >= 5:
        flash('Quá nhiều lần đăng nhập sai. Vui lòng thử lại sau 30 phút.', 'danger')
        return False
    return True


# --- YÊU CẦU BẢO MẬT ---

def triple_des_encrypt(data, key):
    # Mã hóa dữ liệu (CCCD) bằng Triple DES trước khi lưu
    try:
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded_data = pad(data.encode(), DES3.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(iv + encrypted_data).decode('utf-8')
    except Exception as e:
        logging.error(f"Lỗi mã hóa Triple DES: {str(e)}")
        raise

def triple_des_decrypt(encrypted_data, key):
    # Giải mã dữ liệu CCCD đã mã hóa bằng Triple DES
    try:
        raw_data = base64.b64decode(encrypted_data)
        iv = raw_data[:8]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(raw_data[8:]), DES3.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logging.error(f"Lỗi giải mã Triple DES: {str(e)}")
        raise

def aes_encrypt(data, key):
    # Mã hóa dữ liệu (BHXH, tài khoản) bằng AES-256 trước khi lưu
    try:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(iv + encrypted_data).decode('utf-8')
    except Exception as e:
        logging.error(f"Lỗi mã hóa AES: {str(e)}")
        raise

def aes_decrypt(encrypted_data, key):
    # Giải mã dữ liệu BHXH, tài khoản đã mã hóa bằng AES-256
    try:
        raw_data = base64.b64decode(encrypted_data)
        iv = raw_data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(raw_data[16:]), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logging.error(f"Lỗi giải mã AES: {str(e)}")
        raise

# ====== ROUTES ======
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/input', methods=['GET', 'POST'])
def input_user():
    if request.method == 'POST':
        try:
            name = request.form['name']
            cmnd = request.form['cmnd']
            social_insurance = request.form['social_insurance']
            bank_account = request.form['bank_account']
            bank_name = request.form['bank_name']

            # --- YÊU CẦU BẢO MẬT: Không lưu dữ liệu thô, chỉ lưu dữ liệu đã mã hóa ---
            # Mã hóa CCCD bằng Triple DES
            cmnd_encrypted = triple_des_encrypt(cmnd, key1)
            # Mã hóa BHXH và tài khoản bằng AES-256
            social_insurance_encrypted = aes_encrypt(social_insurance, key2)
            bank_account_encrypted = aes_encrypt(bank_account, key2)

            user = {
                "name": name,
                # Lưu mã hóa, không lưu thô
                "cmnd_encrypted": cmnd_encrypted,
                # Lưu mã hóa
                "social_insurance_encrypted": social_insurance_encrypted,
                # Lưu mã hóa
                "bank_account_encrypted": bank_account_encrypted,
                "bank_name": bank_name,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            users_db.append(user)
            save_users()  # Lưu vào file users.json (dạng file, không phải CSDL)
            logging.info(f"Người dùng {name} đã được thêm.")
            flash('Thông tin đã được lưu (mã hóa)!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            logging.error(f"Lỗi khi thêm người dùng: {str(e)}")
            flash('Có lỗi xảy ra khi xử lý thông tin!', 'danger')
            return redirect(url_for('input_user'))
    return render_template('input.html')

@app.route('/view', methods=['GET', 'POST'])
def view_users():
    detail_user = None
    detail_error = None
    detail_name = None
    # Bước 1: Xác thực admin toàn trang
    if not session.get('admin_logged_in'):
        if request.method == 'POST' and 'admin_password' in request.form and 'detail_name' not in request.form:
            admin_password_input = request.form.get('admin_password')
            if admin_password_input != admin_password:
                flash('Sai mật khẩu!', 'danger')
                return render_template('view.html', users=None)
            session['admin_logged_in'] = True
        else:
            return render_template('view.html', users=None)
    # Bước 2: Đã xác thực admin, xử lý xem chi tiết từng user hoặc ẩn lại
    if request.method == 'POST' and 'detail_name' in request.form:
        detail_name = request.form['detail_name']
        if 'hide_detail' in request.form:
            detail_user = None  # Không lưu trạng thái giải mã, lần sau phải nhập lại mật khẩu
        else:
            admin_password_input = request.form.get('admin_password')
            user = next((u for u in users_db if u["name"] == detail_name), None)
            if not user:
                flash('Không tìm thấy người dùng.', 'danger')
                return render_template('view.html', users=None)
            if admin_password_input is not None:
                if admin_password_input != admin_password:
                    detail_error = 'Sai mật khẩu!'
                else:
                    try:
                        cmnd = triple_des_decrypt(user["cmnd_encrypted"], key1)
                        social_insurance = aes_decrypt(user["social_insurance_encrypted"], key2)
                        bank_account = aes_decrypt(user["bank_account_encrypted"], key2)
                        detail_user = {
                            "name": user["name"],
                            "cmnd": cmnd,
                            "social_insurance": social_insurance,
                            "bank_account": bank_account,
                            "bank_name": user["bank_name"],
                            "created_at": user["created_at"]
                        }
                    except Exception as e:
                        detail_error = 'Có lỗi khi giải mã thông tin!'
    users = []
    for user in users_db:
        users.append({
            "name": user["name"],
            "cmnd": user["cmnd_encrypted"],
            "social_insurance": user["social_insurance_encrypted"],
            "bank_account": user["bank_account_encrypted"],
            "bank_name": user["bank_name"],
            "created_at": user["created_at"]
        })
    return render_template('view.html', users=users, detail_user=detail_user, detail_error=detail_error, detail_name=detail_name)

@app.route('/edit/<name>', methods=['GET', 'POST'])
@admin_required
def edit_user(name):
    if request.method == 'POST':
        try:
            for user in users_db:
                if user["name"] == name:
                    old_data = user.copy()
                    user["name"] = request.form['name']
                    user["cmnd_encrypted"] = triple_des_encrypt(request.form['cmnd'], key1)
                    user["social_insurance_encrypted"] = aes_encrypt(request.form['social_insurance'], key2)
                    user["bank_account_encrypted"] = aes_encrypt(request.form['bank_account'], key2)
                    user["bank_name"] = request.form['bank_name']
                    save_users()
                    # Log chi tiết giá trị cũ/mới
                    logging.info(f"[ADMIN] Sửa thông tin: {old_data['name']} -> {user['name']} lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Cũ: {old_data} | Mới: {user}")
                    flash('Sửa thành công!', 'success')
                    return redirect(url_for('view_users'))
            flash('Không tìm thấy người dùng.', 'danger')
            return redirect(url_for('view_users'))
        except Exception as e:
            logging.error(f"Lỗi khi sửa thông tin: {str(e)}")
            flash('Có lỗi xảy ra khi xử lý thông tin!', 'danger')
            return redirect(url_for('view_users'))

    try:
        for user in users_db:
            if user["name"] == name:
                return render_template('edit.html', user={
                    "name": user["name"],
                    "cmnd": triple_des_decrypt(user["cmnd_encrypted"], key1),
                    "social_insurance": aes_decrypt(user["social_insurance_encrypted"], key2),
                    "bank_account": aes_decrypt(user["bank_account_encrypted"], key2),
                    "bank_name": user["bank_name"]
                })
        flash('Không tìm thấy người dùng.', 'danger')
        return redirect(url_for('view_users'))
    except Exception as e:
        logging.error(f"Lỗi khi xem thông tin để sửa: {str(e)}")
        flash('Có lỗi xảy ra khi xử lý thông tin!', 'danger')
        return redirect(url_for('view_users'))

@app.route('/delete/<name>', methods=['POST'])
@admin_required
def delete_user(name):
    try:
        for user in users_db:
            if user["name"] == name:
                old_data = user.copy()
                users_db.remove(user)
                save_users()
                # Log chi tiết khi xóa
                logging.info(f"[ADMIN] Xoá thông tin: {old_data['name']} lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Đã xóa: {old_data}")
                flash('Đã xóa thông tin!', 'success')
                return redirect(url_for('view_users'))
        flash('Không tìm thấy người dùng.', 'danger')
        return redirect(url_for('view_users'))
    except Exception as e:
        logging.error(f"Lỗi khi xóa thông tin: {str(e)}")
        flash('Có lỗi xảy ra khi xử lý thông tin!', 'danger')
        return redirect(url_for('view_users'))

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    flash('Đã đăng xuất!', 'success')
    return redirect(url_for('view_users'))

@app.route('/detail/<name>', methods=['GET', 'POST'])
def detail_user(name):
    user = next((u for u in users_db if u["name"] == name), None)
    if not user:
        flash('Không tìm thấy người dùng.', 'danger')
        return redirect(url_for('view_users'))
    if request.method == 'POST':
        admin_password_input = request.form['admin_password']
        if admin_password_input != admin_password:
            flash('Sai mật khẩu!', 'danger')
            return redirect(url_for('detail_user', name=name))
        # Giải mã thông tin
        try:
            cmnd = triple_des_decrypt(user["cmnd_encrypted"], key1)
            social_insurance = aes_decrypt(user["social_insurance_encrypted"], key2)
            bank_account = aes_decrypt(user["bank_account_encrypted"], key2)
            return render_template('detail.html', user={
                "name": user["name"],
                "cmnd": cmnd,
                "social_insurance": social_insurance,
                "bank_account": bank_account,
                "bank_name": user["bank_name"],
                "created_at": user["created_at"]
            })
        except Exception as e:
            flash('Có lỗi khi giải mã thông tin!', 'danger')
            return redirect(url_for('view_users'))
    return render_template('admin_password.html', user=user)

@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    if not session.get('user_logged_in'):
        flash('Vui lòng đăng nhập trước!', 'danger')
        return redirect(url_for('home'))
    
    user = next((u for u in users_db if u["name"] == session.get('user_name')), None)
    if not user:
        flash('Không tìm thấy thông tin người dùng!', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            cmnd = triple_des_decrypt(user["cmnd_encrypted"], key1)
            social_insurance = aes_decrypt(user["social_insurance_encrypted"], key2)
            bank_account = aes_decrypt(user["bank_account_encrypted"], key2)
            return render_template('user_profile.html', user={
                "name": user["name"],
                "cmnd": cmnd,
                "social_insurance": social_insurance,
                "bank_account": bank_account,
                "bank_name": user["bank_name"],
                "created_at": user["created_at"]
            })
        except Exception as e:
            flash('Có lỗi khi giải mã thông tin!', 'danger')
            return redirect(url_for('user_profile'))
    
    return render_template('user_profile.html', user=user)

@app.route('/user/edit', methods=['GET', 'POST'])
def user_edit():
    if not session.get('user_logged_in'):
        flash('Vui lòng đăng nhập trước!', 'danger')
        return redirect(url_for('home'))
    
    user = next((u for u in users_db if u["name"] == session.get('user_name')), None)
    if not user:
        flash('Không tìm thấy thông tin người dùng!', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Validate input
            cmnd = request.form['cmnd']
            social_insurance = request.form['social_insurance']
            bank_account = request.form['bank_account']
            
            if not (cmnd.isdigit() and 1 <= len(cmnd) <= 12):
                flash('Số CCCD/CMND phải là số và tối đa 12 số!', 'danger')
                return redirect(url_for('user_edit'))
            if not (social_insurance.isdigit() and len(social_insurance) == 10):
                flash('Mã số BHXH phải là số và đúng 10 số!', 'danger')
                return redirect(url_for('user_edit'))
            if not (bank_account.isdigit() and 1 <= len(bank_account) <= 32):
                flash('Số tài khoản ngân hàng phải là số và từ 1 đến 32 số!', 'danger')
                return redirect(url_for('user_edit'))
            
            # Update user information
            user["cmnd_encrypted"] = triple_des_encrypt(cmnd, key1)
            user["social_insurance_encrypted"] = aes_encrypt(social_insurance, key2)
            user["bank_account_encrypted"] = aes_encrypt(bank_account, key2)
            user["bank_name"] = request.form['bank_name']
            
            save_users()
            flash('Cập nhật thông tin thành công!', 'success')
            return redirect(url_for('user_profile'))
        except Exception as e:
            flash('Có lỗi xảy ra khi cập nhật thông tin!', 'danger')
            return redirect(url_for('user_edit'))
    
    try:
        return render_template('user_edit.html', user={
            "name": user["name"],
            "cmnd": triple_des_decrypt(user["cmnd_encrypted"], key1),
            "social_insurance": aes_decrypt(user["social_insurance_encrypted"], key2),
            "bank_account": aes_decrypt(user["bank_account_encrypted"], key2),
            "bank_name": user["bank_name"]
        })
    except Exception as e:
        flash('Có lỗi khi xem thông tin!', 'danger')
        return redirect(url_for('user_profile'))

@app.route('/user/delete', methods=['POST'])
def user_delete():
    if not session.get('user_logged_in'):
        flash('Vui lòng đăng nhập trước!', 'danger')
        return redirect(url_for('home'))
    
    try:
        user = next((u for u in users_db if u["name"] == session.get('user_name')), None)
        if user:
            users_db.remove(user)
            save_users()
            session.pop('user_logged_in', None)
            session.pop('user_name', None)
            flash('Đã xóa tài khoản thành công!', 'success')
            return redirect(url_for('home'))
        flash('Không tìm thấy thông tin người dùng!', 'danger')
        return redirect(url_for('home'))
    except Exception as e:
        flash('Có lỗi xảy ra khi xóa tài khoản!', 'danger')
        return redirect(url_for('user_profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        cmnd = request.form.get('cmnd')
        
        # Tìm user trong database
        user = next((u for u in users_db if u["name"] == name), None)
        
        if user:
            try:
                # Giải mã CMND để so sánh
                decrypted_cmnd = triple_des_decrypt(user["cmnd_encrypted"], key1)
                if decrypted_cmnd == cmnd:
                    session['user_logged_in'] = True
                    session['user_name'] = name
                    flash('Đăng nhập thành công!', 'success')
                    return redirect(url_for('user_profile'))
                else:
                    flash('Số CCCD/CMND không đúng!', 'danger')
            except Exception as e:
                flash('Có lỗi xảy ra khi đăng nhập!', 'danger')
        else:
            flash('Không tìm thấy tên người dùng!', 'danger')
    
    return render_template('login.html')

@app.route('/user/logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_name', None)
    flash('Đã đăng xuất!', 'success')
    return redirect(url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('admin_password')
        if password == admin_password:
            session['admin_logged_in'] = True
            flash('Đăng nhập admin thành công!', 'success')
            return redirect(url_for('view_users'))
        else:
            flash('Sai mật khẩu admin!', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logs')
@admin_required
def admin_logs():
    logs = []
    try:
        with open('system.log', 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                logs.append(line.strip())
    except Exception as e:
        logs = [f'Lỗi khi đọc log: {str(e)}']
    return render_template('admin_logs.html', logs=logs)

# ====== Auto Open Web Browser ======
def open_browser():
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == '__main__':
    threading.Timer(1, open_browser).start()
    app.run(debug=True)
