from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
import time
import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import requests
import secrets

# Nạp file .env từ thư mục hiện tại
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "Khoa_Bi_Mat_Cua_Nhom_1_PTIT")

# --- CẤU HÌNH SMTP GMAIL ---
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
raw_pass = os.environ.get("SMTP_PASS")
SMTP_PASS = raw_pass.replace(" ", "").strip() if raw_pass else None

print(f"[DEBUG KHỞI ĐỘNG] SMTP_USER = {SMTP_USER} | SMTP_PASS_LEN = {len(SMTP_PASS) if SMTP_PASS else 0}")

# --- CẤU HÌNH eSMS ---
ESMS_API_KEY = os.environ.get("ESMS_API_KEY")
ESMS_SECRET_KEY = os.environ.get("ESMS_SECRET_KEY")
ESMS_BRANDNAME = os.environ.get("ESMS_BRANDNAME", "PTIT2FA_N1")
ESMS_SMS_TYPE = os.environ.get("ESMS_SMS_TYPE", "2")
ESMS_TEMPLATE = os.environ.get("ESMS_TEMPLATE", "{OTP} la ma xac minh dang ky PTIT2FA_N1 cua ban")
ESMS_API_URL = "https://rest.esms.vn/MainService.svc/json/SendMultipleMessage_V4_post_json/"

def esms_ready():
    return all([ESMS_API_KEY, ESMS_SECRET_KEY, ESMS_BRANDNAME, ESMS_TEMPLATE])

def normalize_phone(phone):
    phone = (phone or "").strip().replace(" ", "").replace("-", "")
    if phone.startswith("+84"):
        return "0" + phone[3:]
    if phone.startswith("84"):
        return "0" + phone[2:]
    return phone

def send_sms_otp(phone, otp_code):
    if not esms_ready():
        raise RuntimeError("Chưa cấu hình eSMS trong file .env")

    payload = {
        "ApiKey": ESMS_API_KEY,
        "SecretKey": ESMS_SECRET_KEY,
        "Phone": normalize_phone(phone),
        "Content": ESMS_TEMPLATE.replace("{OTP}", otp_code),
        "Brandname": ESMS_BRANDNAME,
        "SmsType": ESMS_SMS_TYPE,
        "IsUnicode": "0"
    }

    response = requests.post(ESMS_API_URL, json=payload, timeout=15)
    response.raise_for_status()
    result = response.json()
    
    if str(result.get("CodeResult")) != "100":
        raise RuntimeError(f"eSMS từ chối gửi: CodeResult={result.get('CodeResult')} - {result.get('ErrorMessage', result)}")
    return result

def send_email_otp(to_email, otp_code):
    if not SMTP_USER or not SMTP_PASS:
        print("[LỖI CẤU HÌNH] Chưa có SMTP_USER hoặc SMTP_PASS trong file .env")
        return False

    msg = MIMEText(f"Mã xác thực (OTP) của bạn là: {otp_code}\nMã có hiệu lực trong 30 (s).")
    msg['Subject'] = "Mã xác thực 2FA"
    msg['From'] = SMTP_USER
    msg['To'] = to_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
            print(f"[SMTP OK] Đã gửi mã [{otp_code}] tới email: {to_email}")
        return True
    except Exception as e:
        print(f"[LỖI KẾT NỐI/GỬI EMAIL] {e}")
        return False

# --- CẤU HÌNH DATABASE ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(100), unique=True, nullable=False) 
    password = db.Column(db.String(200), nullable=False)
    auth_method = db.Column(db.String(20), nullable=False) 
    totp_secret = db.Column(db.String(32), nullable=True) 
    is_verified = db.Column(db.Boolean, default=False) 
    locked_until = db.Column(db.Float, default=0.0) 
    failed_attempts = db.Column(db.Integer, default=0) 
    last_otp_used = db.Column(db.String(10), nullable=True) # Bảo vệ Replay Attack cho App

# Đổi tên bảng thành OtpChallenge dùng chung cho cả Email và SMS
class OtpChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contact = db.Column(db.String(100), unique=True, nullable=False)
    otp_hash = db.Column(db.String(200), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    last_sent_at = db.Column(db.Float, default=0.0)

def create_and_send_oob_otp(contact, method):
    """Sinh OTP ngẫu nhiên dùng chung cho Email và SMS"""
    otp_code = f"{secrets.randbelow(1_000_000):06d}"
    now = time.time()

    challenge = OtpChallenge.query.filter_by(contact=contact).first()
    
    # 1. Cơ chế Cooldown 30s cho Nút Gửi Lại
    if challenge and now - challenge.last_sent_at < 30:
        wait = 30 - int(now - challenge.last_sent_at)
        raise RuntimeError(f"Vui lòng chờ {wait} giây trước khi gửi lại mã.")

    # 2. Xử lý gửi qua Email hoặc SMS
    if method == 'email':
        sent = send_email_otp(contact, otp_code)
        if not sent:
            raise RuntimeError("Lỗi hệ thống khi gửi Email. Vui lòng kiểm tra cấu hình SMTP.")
    elif method == 'sms':
        send_sms_otp(contact, otp_code)

    if not challenge:
        challenge = OtpChallenge(contact=contact, otp_hash="", expires_at=0)
        db.session.add(challenge)

    # 3. Cơ chế vô hiệu hóa mã cũ: Ghi đè mã băm mới nhất
    challenge.otp_hash = generate_password_hash(otp_code)
    challenge.expires_at = now + 30  # Mã chỉ sống 5 phút
    challenge.last_sent_at = now
    db.session.commit()
    print(f"[OTP OK] Đã yêu cầu gửi OTP tới {contact} qua {method.upper()}")

def check_oob_otp(contact, code):
    """Kiểm tra mã OTP cho luồng Email và SMS"""
    challenge = OtpChallenge.query.filter_by(contact=contact).first()
    if not challenge:
        return False, "Không có OTP nào đang chờ xác thực."
        
    if time.time() > challenge.expires_at:
        db.session.delete(challenge)
        db.session.commit()
        return False, "Mã xác thực đã hết hạn. Vui lòng gửi lại mã."
        
    if not check_password_hash(challenge.otp_hash, code):
        return False, "Mã xác thực không đúng."

    # Xóa ngay sau khi dùng thành công (Tính tiêu thụ 1 lần)
    db.session.delete(challenge)
    db.session.commit()
    return True, "OK"

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

# =================================================================
# LUỒNG 1: ĐĂNG KÝ (START)
# =================================================================
@app.route('/api/auth/start', methods=['POST'])
def api_auth_start():
    try:
        data = request.get_json(force=True, silent=True) 
        if not data:
            return jsonify({"ok": False, "message": "Dữ liệu không hợp lệ."}), 400
             
        contact = (data.get('contact') or '').strip()
        password = data.get('password')
        method = data.get('method')
        name = data.get('name')
        
        existing_user = User.query.filter_by(contact=contact).first()
        if existing_user:
            if existing_user.is_verified:
                return jsonify({"ok": False, "message": "Tài khoản này đã đăng ký!"}), 400
            else:
                db.session.delete(existing_user)
                db.session.commit()

        hashed_pw = generate_password_hash(password)
        new_user = User(name=name, contact=contact, password=hashed_pw, auth_method=method)
        session['current_user'] = contact

        if method == 'app':
            secret_key = pyotp.random_base32()
            new_user.totp_secret = secret_key
            db.session.add(new_user)
            db.session.commit()
            
            totp = pyotp.TOTP(secret_key)
            uri = totp.provisioning_uri(name=contact, issuer_name="Nhom1_Security_PTIT")
            qr_img = qrcode.make(uri)
            buffered = BytesIO()
            qr_img.save(buffered, format="PNG")
            qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
            
            return jsonify({
                "ok": True,
                "qr": f"data:image/png;base64,{qr_base64}",
                "message": "Quét mã QR bằng Google Authenticator."
            })
            
        elif method in ['email', 'sms']:
            db.session.add(new_user)
            db.session.commit()
            try:
                create_and_send_oob_otp(contact, method)
            except Exception as e:
                db.session.delete(new_user)
                db.session.commit()
                return jsonify({"ok": False, "message": str(e)}), 500

            return jsonify({"ok": True, "message": f"Đã gửi mã xác thực qua {method.upper()}."})
            
    except Exception as e:
        print(f"[LỖI SERVER START] {e}")
        return jsonify({"ok": False, "message": "Lỗi hệ thống."}), 500

# =================================================================
# LUỒNG 2: XÁC THỰC MÃ 6 SỐ (VERIFY)
# =================================================================
@app.route('/api/auth/verify', methods=['POST'])
def api_auth_verify():
    try:
        data = request.get_json(force=True, silent=True) or {}
        user_otp = str(data.get('otp', '')).strip()
        contact = session.get('current_user')
        
        user = User.query.filter_by(contact=contact).first()
        if not user:
            return jsonify({"ok": False, "message": "Không tìm thấy dữ liệu xác thực!"}), 400
            
        if user.locked_until > time.time():
            rem = int((user.locked_until - time.time()) / 60) + 1
            return jsonify({"ok": False, "message": f"Tài khoản đang bị khóa. Thử lại sau {rem} phút."}), 403

        is_valid = False
        if user.auth_method == 'app':
            # Chặn đứng Replay Attack cho Google Auth
            if user.last_otp_used == user_otp:
                return jsonify({"ok": False, "message": "Mã OTP này đã được sử dụng. Vui lòng chờ mã mới!"}), 403
                
            totp = pyotp.TOTP(user.totp_secret, interval=30)
            is_valid = totp.verify(user_otp, valid_window=1)
            
            if is_valid:
                user.last_otp_used = user_otp # Lưu vết mã vừa xài
                
        elif user.auth_method in ['email', 'sms']:
            try:
                is_valid, msg = check_oob_otp(contact, user_otp)
                if not is_valid and "hết hạn" in msg:
                    return jsonify({"ok": False, "message": msg}), 400
            except Exception as e:
                print(f"[VERIFY ERROR] {e}")
                is_valid = False

        if is_valid:
            user.failed_attempts = 0
            user.is_verified = True
            db.session.commit()
            print(f"[SERVER LOG] ✅ Xác thực thành công cho: {contact}")
            return jsonify({"ok": True, "message": "Xác thực thành công!"})
        else:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = time.time() + 900
                db.session.commit()
                return jsonify({"ok": False, "message": "Nhập sai 5 lần. Khóa tài khoản 15 phút."}), 403
            
            db.session.commit()
            return jsonify({"ok": False, "message": f"Mã sai. Còn {5 - user.failed_attempts} lần thử."}), 400

    except Exception as e:
        print(f"[LỖI VERIFY] {e}")
        return jsonify({"ok": False, "message": "Lỗi xác thực."}), 500

# =================================================================
# LUỒNG 3: ĐĂNG NHẬP (LOGIN)
# =================================================================
@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data = request.get_json(force=True, silent=True) or {}
    contact = (data.get('contact') or '').strip()
    password = data.get('password')
    
    user = User.query.filter_by(contact=contact).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"ok": False, "message": "Tài khoản hoặc mật khẩu không đúng!"}), 400

    if not user.is_verified:
        return jsonify({"ok": False, "message": "Tài khoản chưa hoàn tất xác thực. Vui lòng đăng ký lại!"}), 403
        
    session['current_user'] = contact    
    
    if user.auth_method in ['email', 'sms']:
        try:
            create_and_send_oob_otp(contact, user.auth_method)
        except Exception as e:
            return jsonify({"ok": False, "message": str(e)}), 500
    
    return jsonify({
        "ok": True,
        "method": user.auth_method,
        "message": "Mật khẩu đúng. Vui lòng nhập mã xác thực 2 lớp (2FA) để vào hệ thống."
    })

# =================================================================
# LUỒNG 4: GỬI LẠI MÃ (RESEND)
# =================================================================
@app.route('/api/auth/resend', methods=['POST'])
def api_auth_resend():
    try:
        contact = session.get('current_user')
        if not contact:
            return jsonify({"ok": False, "message": "Phiên làm việc đã hết hạn. Vui lòng thử lại từ đầu."}), 401

        user = User.query.filter_by(contact=contact).first()
        if not user:
            return jsonify({"ok": False, "message": "Không tìm thấy dữ liệu tài khoản!"}), 400

        if user.locked_until > time.time():
            rem = int((user.locked_until - time.time()) / 60) + 1
            return jsonify({"ok": False, "message": f"Tài khoản đang bị khóa. Thử lại sau {rem} phút."}), 403

        if user.auth_method == 'app':
            return jsonify({"ok": False, "message": "Google Authenticator tự sinh mã, không cần gửi lại."}), 400
            
        elif user.auth_method in ['email', 'sms']:
            try:
                create_and_send_oob_otp(contact, user.auth_method)
                return jsonify({"ok": True, "message": f"Đã gửi lại mã xác thực qua {user.auth_method.upper()}."})
            except Exception as e:
                return jsonify({"ok": False, "message": str(e)}), 400

    except Exception as e:
        print(f"[LỖI RESEND] {e}")
        return jsonify({"ok": False, "message": "Lỗi hệ thống xử lý gửi lại mã."}), 500

if __name__ == '__main__':
    print("="*60)
    print("🚀 HỆ THỐNG XÁC THỰC 2FA ĐANG CHẠY...")
    print("👉 Mở trình duyệt và truy cập: http://127.0.0.1:5000")
    print("="*60)
    app.run(debug=True, port=5000)