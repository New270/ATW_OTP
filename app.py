from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
import time

app = Flask(__name__)
app.secret_key = 'Khoa_Bi_Mat_Cua_Nhom_1_PTIT'

# Cấu hình Database SQLite (Lưu file trực tiếp trên ổ cứng)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- TẠO BẢNG DATABASE ---
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

# Tạo file users.db nếu chưa có
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    """Render giao diện web do Tùng thiết kế"""
    return render_template('index.html')

# =================================================================
# LUỒNG 1: ĐĂNG KÝ (TẠO TÀI KHOẢN VÀ THIẾT LẬP 2FA)
# =================================================================
@app.route('/api/auth/start', methods=['POST'])
def api_auth_start():
    try:
        data = request.get_json(force=True, silent=True) 
        if not data:
             return jsonify({"ok": False, "message": "Dữ liệu không hợp lệ."}), 400
             
        contact = data.get('contact')
        password = data.get('password')
        method = data.get('method')
        name = data.get('name')
        
        # Kiểm tra xem tài khoản đã tồn tại trong DB chưa
        existing_user = User.query.filter_by(contact=contact).first()
        if existing_user:
            return jsonify({"ok": False, "message": "Tài khoản (Email/SĐT) này đã được đăng ký!"}), 400

        # Lưu người dùng mới vào Database thật
        hashed_pw = generate_password_hash(password)
        new_user = User(name=name, contact=contact, password=hashed_pw, auth_method=method)
        
        session['current_user'] = contact
        print(f"\n[SERVER LOG] Đang tạo tài khoản mới: {contact} - Phương thức: {method.upper()}")

        if method == 'app':
            secret_key = pyotp.random_base32()
            new_user.totp_secret = secret_key
            
            db.session.add(new_user)
            db.session.commit()
            
            # Tạo mã QR
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
            return jsonify({"ok": True, "message": f"Đã gửi mã qua {method.upper()}"})
            
    except Exception as e:
        print(f"[LỖI SERVER] {e}")
        return jsonify({"ok": False, "message": "Lỗi hệ thống."}), 500


# =================================================================
# LUỒNG 2: XÁC THỰC MÃ 6 SỐ (Dùng chung cho cả Đăng ký & Đăng nhập)
# =================================================================
@app.route('/api/auth/verify', methods=['POST'])
def api_auth_verify():
    try:
        data = request.get_json()
        user_otp = data.get('otp')
        contact = session.get('current_user')
        
        user = User.query.filter_by(contact=contact).first()
        if not user:
            return jsonify({"ok": False, "message": "Không tìm thấy dữ liệu xác thực!"}), 400
            
        # Kiểm tra khóa tài khoản
        if user.locked_until > time.time():
            rem = int((user.locked_until - time.time()) / 60)
            return jsonify({"ok": False, "message": f"Tài khoản đang bị khóa. Thử lại sau {rem} phút."}), 403

        # Xử lý riêng cho TOTP
        if user.auth_method == 'app':
            totp = pyotp.TOTP(user.totp_secret)
            is_valid = totp.verify(user_otp, valid_window=1)
            
            if is_valid:
                user.failed_attempts = 0
                user.is_verified = True # Đánh dấu tài khoản đã kích hoạt thành công
                db.session.commit()
                print(f"[SERVER LOG] ✅ XÁC THỰC THÀNH CÔNG CHO: {contact}")
                return jsonify({"ok": True, "message": "Xác thực thành công!"})
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = time.time() + 900 # Khóa 15 phút
                    db.session.commit()
                    return jsonify({"ok": False, "message": "Nhập sai 5 lần. Khóa tài khoản 15 phút."}), 403
                
                db.session.commit()
                return jsonify({"ok": False, "message": f"Mã sai. Còn {5 - user.failed_attempts} lần thử."}), 400

    except Exception as e:
        return jsonify({"ok": False, "message": "Lỗi xác thực."}), 500


# =================================================================
# LUỒNG 3: ĐĂNG NHẬP (API MỚI - Gửi cho Tùng để ghép giao diện)
# =================================================================
@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    """
    Khi Tùng làm trang Đăng nhập, Tùng sẽ gửi Username và Password vào API này.
    Nếu đúng, API sẽ trả về yêu cầu nhập mã 6 số (chuyển sang màn hình Verify).
    """
    data = request.get_json(force=True, silent=True)
    contact = data.get('contact')
    password = data.get('password')
    
    user = User.query.filter_by(contact=contact).first()
    
    # Kiểm tra tài khoản và mật khẩu
    if not user or not check_password_hash(user.password, password):
        return jsonify({"ok": False, "message": "Tài khoản hoặc mật khẩu không đúng!"}), 400
        
    # Nếu pass đúng, lưu session và yêu cầu nhập mã 2FA
    session['current_user'] = contact
    
    return jsonify({
        "ok": True,
        "method": user.auth_method,
        "message": "Mật khẩu đúng. Vui lòng nhập mã xác thực 2 lớp (2FA) để vào hệ thống."
    })

if __name__ == '__main__':
    print("="*60)
    print("🚀 HỆ THỐNG XÁC THỰC 2FA (TOTP) ĐANG CHẠY...")
    print("👉 Mở trình duyệt và truy cập: http://127.0.0.1:5000")
    print("="*60)
    app.run(debug=True, port=5000)