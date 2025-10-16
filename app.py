import os
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import jwt

# -------------------------
# إعدادات التطبيق
# -------------------------
app = Flask(__name__)
# غيّر هذا المفتاح إلى قيمة قوية بخط الإنتاج
app.secret_key = 'CHANGE_THIS_SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# مكان رفع الصور (مجلد داخل static)
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

# -------------------------
# نموذج المستخدم
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    national_id = db.Column(db.String(50), unique=True)
    birth_date = db.Column(db.Date)
    nationality = db.Column(db.String(50))
    gender = db.Column(db.String(10))
    qualification = db.Column(db.String(50))
    birth_city = db.Column(db.String(50))
    birth_country = db.Column(db.String(50))
    marital_status = db.Column(db.String(20))
    blood_type = db.Column(db.String(10))
    phone_number = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(150), unique=True)
    profile_image = db.Column(db.String(200))
    fingerprint_image = db.Column(db.String(200))
    password_hash = db.Column(db.String(256))
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_code = db.Column(db.String(10), nullable=True)

with app.app_context():
    db.create_all()

# -------------------------
# مساعدة: توليد رابط للصورة يمكن للـ site2 الوصول إليه
# -------------------------
def profile_url_for(filename):
    # filename should be base filename inside static/uploads
    return url_for('static', filename=f'uploads/{filename}', _external=True)

# -------------------------
# التحقق من تسجيل الدخول (داخل الـ SSO نفسه)
# -------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            current_user = User.query.get(data.get('user_id'))
            if not current_user:
                flash("المستخدم غير موجود")
                return redirect(url_for('login'))
        except jwt.ExpiredSignatureError:
            flash("انتهت صلاحية الجلسة، الرجاء تسجيل الدخول مجددًا.")
            return redirect(url_for('login'))
        except Exception:
            flash("هناك خطأ في التوكن، الرجاء تسجيل الدخول.")
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated

# -------------------------
# وظيفة إرسال البريد (SMTP)
# -------------------------
def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = "azlal.gov@gmail.com"
    msg['To'] = to_email
    msg.set_content(body)
    # ملاحظة: إعدادات SMTP كما أعطيت سابقًا (استخدم app password)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login('azlal.gov@gmail.com', 'mhhuliujcrqkzccg')
        smtp.send_message(msg)

# -------------------------
# الصفحة الرئيسية -> تحويل إلى login
# -------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# -------------------------
# تسجيل مستخدم جديد
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # جمع الحقول من النموذج
        full_name = request.form.get('full_name', '').strip()
        national_id = request.form.get('national_id', '').strip()
        birth_date = request.form.get('birth_date', '').strip()
        nationality = request.form.get('nationality', '').strip()
        gender = request.form.get('gender', '').strip()
        qualification = request.form.get('qualification', '').strip()
        birth_city = request.form.get('birth_city', '').strip()
        birth_country = request.form.get('birth_country', '').strip()
        marital_status = request.form.get('marital_status', '').strip()
        blood_type = request.form.get('blood_type', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        email = request.form.get('email', '').strip()

        # تأكد من عدم تكرار الهوية أو الجوال أو البريد
        existing = User.query.filter(
            (User.national_id == national_id) |
            (User.email == email) |
            (User.phone_number == phone_number)
        ).first()
        if existing:
            flash("رقم الهوية أو الجوال أو البريد الإلكتروني مستخدم مسبقًا.")
            return redirect(url_for('register'))

        # معالجة الملفات (إن وُجدت)
        profile_file = request.files.get('profile_image')
        fingerprint_file = request.files.get('fingerprint_image')

        profile_filename = None
        fingerprint_filename = None

        if profile_file and profile_file.filename:
            ext = profile_file.filename.rsplit('.', 1)[-1].lower()
            profile_filename = secure_filename(f"{national_id}p.{ext}")
            profile_file.save(os.path.join(UPLOAD_FOLDER, profile_filename))

        if fingerprint_file and fingerprint_file.filename:
            ext = fingerprint_file.filename.rsplit('.', 1)[-1].lower()
            fingerprint_filename = secure_filename(f"{national_id}h.{ext}")
            fingerprint_file.save(os.path.join(UPLOAD_FOLDER, fingerprint_filename))

        # إرسال رمز تحقق إلى البريد
        verification_code = str(random.randint(100000, 999999))
        try:
            send_email(email, "رمز التحقق", f"رمز التحقق الخاص بك: {verification_code}")
        except Exception as e:
            # لا نوقف التسجيل لو فشل الإرسال، نكتفي بتنبيه (أو بإمكانك رفض التسجيل)
            flash("تعذر إرسال رمز التحقق عبر البريد. تأكد من إعداد SMTP.")
            # يمكنك اختيار إعادة التوجيه أو السماح بالمضي — هنا نواصل الحفظ.

        # حفظ المستخدم (بدون كلمة مرور حتى يتم إنشاءها لاحقًا)
        user = User(
            full_name=full_name,
            national_id=national_id,
            birth_date=datetime.strptime(birth_date, "%Y-%m-%d") if birth_date else None,
            nationality=nationality,
            gender=gender,
            qualification=qualification,
            birth_city=birth_city,
            birth_country=birth_country,
            marital_status=marital_status,
            blood_type=blood_type,
            phone_number=phone_number,
            email=email,
            profile_image=profile_filename,         # نخزن اسم الملف فقط
            fingerprint_image=fingerprint_filename, # نخزن اسم الملف فقط
            verification_code=verification_code,
            email_verified=False
        )
        db.session.add(user)
        db.session.commit()

        # نحفظ id المستخدم في الجلسة للخطوات التالية
        session['user_id'] = user.id
        return redirect(url_for('verify_email'))

    return render_template('register_step1.html')

# -------------------------
# التحقق من البريد (رمز التحقق)
# -------------------------
@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('register'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if user and code == user.verification_code:
            user.email_verified = True
            user.verification_code = None
            db.session.commit()
            return redirect(url_for('create_password'))
        else:
            flash("رمز التحقق غير صحيح!")
    return render_template('verify_email.html', email=(user.email if user else ''))

# -------------------------
# إنشاء كلمة المرور بعد التحقق
# -------------------------
@app.route('/create_password', methods=['GET', 'POST'])
def create_password():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('register'))
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('register'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        birth_input = request.form.get('birth_date', '')
        if password != confirm:
            flash("كلمتا المرور غير متطابقتان!")
        elif birth_input != (user.birth_date.strftime("%Y-%m-%d") if user.birth_date else ''):
            flash("تاريخ الميلاد غير صحيح!")
        else:
            user.password_hash = generate_password_hash(password)
            db.session.commit()
            flash("تم إنشاء كلمة المرور بنجاح! الآن سجل دخول.")
            return redirect(url_for('login'))
    return render_template('create_password.html')

# -------------------------
# صفحة تسجيل الدخول (تدعم redirect_url لربط المواقع الأخرى)
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # قد يأتي redirect_url كـ query param من الموقع الآخر
    redirect_url = request.args.get('redirect_url') or request.args.get('next')

    if request.method == 'POST':
        # لو النموذج أرسَل redirect_url في حقل مخفي فقرأه
        redirect_url = redirect_url or request.form.get('redirect_url')

        national_id = request.form.get('national_id', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(national_id=national_id).first()

        if not user:
            flash("رقم الهوية أو كلمة المرور غير صحيحة.")
            return render_template('login.html', redirect_url=redirect_url)

        if not user.password_hash:
            flash("هذا الحساب لم يكمل إنشاء كلمة المرور بعد.")
            return render_template('login.html', redirect_url=redirect_url)

        if check_password_hash(user.password_hash, password):
            # توليد التوكن
            payload = {
                'user_id': user.id,
                'national_id': user.national_id,
                'exp': datetime.utcnow() + timedelta(hours=3)
            }
            token = jwt.encode(payload, app.secret_key, algorithm='HS256')

            # إذا هناك redirect_url نعيد التوجيه مع التوكن (للمواقع الثانية)
            if redirect_url:
                # في بيئة الإنتاج يجب التحقق أن redirect_url مسموح به (قائمة white-list)
                return redirect(f"{redirect_url}?token={token}")

            # خلاف ذلك نسجل الجلسة داخل SSO ونذهب للوحة تحكم
            session['token'] = token
            return redirect(url_for('dashboard'))
        else:
            flash("رقم الهوية أو كلمة المرور غير صحيحة.")
            return render_template('login.html', redirect_url=redirect_url)

    # GET: نعرض صفحة الدخول، ونمرر redirect_url للاستخدام كحقل مخفي إن وُجد
    return render_template('login.html', redirect_url=redirect_url)

# -------------------------
# لوحة تحكم المستخدم داخل SSO
# -------------------------
@app.route('/dashboard')
@token_required
def dashboard(current_user):
    # current_user هو كائن User
    return render_template('dashboard.html', user=current_user)

# -------------------------
# عرض وتعديل المعلومات (داخل SSO)
# -------------------------
@app.route('/view_info')
@token_required
def view_info(current_user):
    return render_template('view_info.html', user=current_user)

@app.route('/edit_info', methods=['GET', 'POST'])
@token_required
def edit_info(current_user):
    if request.method == 'POST':
        current_user.nationality = request.form.get('nationality', current_user.nationality)
        current_user.qualification = request.form.get('qualification', current_user.qualification)
        current_user.marital_status = request.form.get('marital_status', current_user.marital_status)
        current_user.phone_number = request.form.get('phone_number', current_user.phone_number)
        db.session.commit()
        flash("تم تحديث المعلومات بنجاح!")
        return redirect(url_for('dashboard'))
    return render_template('edit_info.html', user=current_user)

# -------------------------
# API - تسجيل الدخول الموحد (للمواقع الثانية) - بديل مباشر
# -------------------------
@app.route('/api/sso-login', methods=['POST'])
def api_sso_login():
    """المواقع الخارجية يمكنها طلب توكن عبر إرسال الهوية وكلمة المرور"""
    data = request.get_json() or {}
    national_id = data.get('national_id')
    password = data.get('password')
    if not national_id or not password:
        return jsonify({'error': 'national_id and password required'}), 400

    user = User.query.filter_by(national_id=national_id).first()
    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=3)
    }, app.secret_key, algorithm='HS256')

    return jsonify({'token': token})

# -------------------------
# API - جلب بيانات المستخدم عبر التوكن (للمواقع الأخرى)
# -------------------------
@app.route('/api/get_user', methods=['POST'])
def api_get_user():
    data = request.get_json() or {}
    token = data.get('token')
    if not token:
        return jsonify({'error': 'Token required'}), 400
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user = User.query.get(payload.get('user_id'))
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # بناء رابط الصورة الكامل إن وُجد
        profile_filename = user.profile_image or ''
        profile_url = profile_url_for(profile_filename) if profile_filename else ''

        return jsonify({
            'full_name': user.full_name,
            'national_id': user.national_id,
            'email': user.email,
            'phone_number': user.phone_number,
            'qualification': user.qualification,
            'birth_date': user.birth_date.strftime("%Y-%m-%d") if user.birth_date else '',
            'nationality': user.nationality,
            'profile_image': profile_url
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401
    

# -------------------------
# تسجيل الخروج
# -------------------------
@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))

# -------------------------
# تشغيل التطبيق
# -------------------------
if __name__ == '__main__':
    # شغّل SSO على البورت الافتراضي 5000
    app.run(debug=True)
