import os
import secrets
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

# تنظیمات برنامه
app = Flask(__name__)
CORS(app)  # فعال کردن CORS برای ارتباط با frontend

# تنظیمات دیتابیس
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ایجاد پوشه آپلود
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# مدل کاربر
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# مدل آیتم منو
class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Integer, nullable=False)  # قیمت به ریال
    discount = db.Column(db.Integer, default=0)    # تخفیف به درصد
    status = db.Column(db.String(20), default='available')  # available/unavailable
    badge = db.Column(db.String(50), default='')
    image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ایجاد جداول در دیتابیس
with app.app_context():
    db.create_all()
    
    # ایجاد کاربر پیش‌فرض اگر وجود نداشته باشد
    if not User.query.filter_by(username='matin').first():
        user = User(
            username='matin',
            password_hash=generate_password_hash('1025')
        )
        db.session.add(user)
        db.session.commit()

# Decorator برای احراز هویت با JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # دریافت توکن از هدر
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'توکن نامعتبر است'}), 401
        
        if not token:
            return jsonify({'error': 'توکن احراز هویت لازم است'}), 401
        
        try:
            # دیکد کردن توکن
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'error': 'توکن نامعتبر یا منقضی شده است'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# بررسی مجاز بودن فرمت فایل
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Endpoint ریشه
@app.route('/')
def index():
    return jsonify({
        'message': 'API کافه تاپ تنور',
        'version': '1.0.0',
        'endpoints': {
            'menu_items': '/api/menu-items',
            'login': '/api/login',
            'upload': '/api/upload'
        }
    })

# Endpoint لاگین و دریافت توکن
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'نام کاربری و رمز عبور الزامی است'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'error': 'نام کاربری یا رمز عبور اشتباه است'}), 401
        
        # ایجاد توکن JWT
        token = jwt.encode({
            'username': user.username,
            'exp': datetime.utcnow().timestamp() + 24 * 3600  # 24 ساعت اعتبار
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'با موفقیت وارد شدید',
            'token': token,
            'user': {
                'username': user.username,
                'created_at': user.created_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# دریافت همه آیتم‌های منو
@app.route('/api/menu-items', methods=['GET'])
def get_menu_items():
    try:
        # پارامترهای جستجو و فیلتر
        category = request.args.get('category')
        search = request.args.get('search')
        
        query = MenuItem.query
        
        if category:
            query = query.filter_by(category=category)
        
        if search:
            query = query.filter(
                (MenuItem.name.ilike(f'%{search}%')) | 
                (MenuItem.description.ilike(f'%{search}%'))
            )
        
        items = query.order_by(MenuItem.created_at.desc()).all()
        
        result = []
        for item in items:
            result.append({
                'id': item.id,
                'name': item.name,
                'description': item.description,
                'category': item.category,
                'price': item.price,
                'discount': item.discount,
                'status': item.status,
                'badge': item.badge,
                'image': item.image_url or f'/api/images/{item.category}',
                'created_at': item.created_at.isoformat(),
                'updated_at': item.updated_at.isoformat()
            })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# دریافت یک آیتم خاص
@app.route('/api/menu-items/<int:item_id>', methods=['GET'])
def get_menu_item(item_id):
    try:
        item = MenuItem.query.get_or_404(item_id)
        
        return jsonify({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'category': item.category,
            'price': item.price,
            'discount': item.discount,
            'status': item.status,
            'badge': item.badge,
            'image': item.image_url or f'/api/images/{item.category}',
            'created_at': item.created_at.isoformat(),
            'updated_at': item.updated_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ایجاد آیتم جدید (نیاز به احراز هویت)
@app.route('/api/menu-items', methods=['POST'])
@token_required
def create_menu_item(current_user):
    try:
        data = request.get_json()
        
        if not data or not data.get('name') or not data.get('category') or not data.get('price'):
            return jsonify({'error': 'نام، دسته‌بندی و قیمت الزامی هستند'}), 400
        
        # ایجاد آیتم جدید
        item = MenuItem(
            name=data['name'],
            description=data.get('description', ''),
            category=data['category'],
            price=int(data['price']),
            discount=int(data.get('discount', 0)),
            status=data.get('status', 'available'),
            badge=data.get('badge', ''),
            image_url=data.get('image', '')
        )
        
        db.session.add(item)
        db.session.commit()
        
        return jsonify({
            'message': 'آیتم با موفقیت ایجاد شد',
            'item': {
                'id': item.id,
                'name': item.name,
                'category': item.category,
                'price': item.price,
                'created_at': item.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# به‌روزرسانی آیتم (نیاز به احراز هویت)
@app.route('/api/menu-items/<int:item_id>', methods=['PUT'])
@token_required
def update_menu_item(current_user, item_id):
    try:
        item = MenuItem.query.get_or_404(item_id)
        data = request.get_json()
        
        if 'name' in data:
            item.name = data['name']
        if 'description' in data:
            item.description = data['description']
        if 'category' in data:
            item.category = data['category']
        if 'price' in data:
            item.price = int(data['price'])
        if 'discount' in data:
            item.discount = int(data['discount'])
        if 'status' in data:
            item.status = data['status']
        if 'badge' in data:
            item.badge = data['badge']
        if 'image' in data:
            item.image_url = data['image']
        
        item.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'آیتم با موفقیت به‌روزرسانی شد',
            'item': {
                'id': item.id,
                'name': item.name,
                'updated_at': item.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# حذف آیتم (نیاز به احراز هویت)
@app.route('/api/menu-items/<int:item_id>', methods=['DELETE'])
@token_required
def delete_menu_item(current_user, item_id):
    try:
        item = MenuItem.query.get_or_404(item_id)
        
        # حذف عکس مرتبط اگر وجود دارد
        if item.image_url and item.image_url.startswith('/api/images/'):
            filename = item.image_url.split('/')[-1]
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(item)
        db.session.commit()
        
        return jsonify({'message': 'آیتم با موفقیت حذف شد'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# آپلود عکس
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_image(current_user):
    try:
        # بررسی وجود فایل
        if 'image' not in request.files:
            return jsonify({'error': 'هیچ فایلی ارسال نشده است'}), 400
        
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({'error': 'نام فایل خالی است'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'فرمت فایل مجاز نیست'}), 400
        
        # تولید نام امن و یکتا برای فایل
        filename = secure_filename(file.filename)
        unique_filename = f"{secrets.token_hex(8)}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # ذخیره فایل
        file.save(filepath)
        
        # آدرس کامل فایل
        image_url = f'/api/images/{unique_filename}'
        
        return jsonify({
            'message': 'عکس با موفقیت آپلود شد',
            'image_url': image_url,
            'filename': unique_filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# سرو فایل‌های عکس
@app.route('/api/images/<filename>')
def serve_image(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except:
        # اگر فایل یافت نشد، یک تصویر پیش‌فرض برگردانید
        return send_from_directory('static', 'default.jpg', mimetype='image/jpeg')

# هندلر برای خطاهای 404
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'منبع یافت نشد'}), 404

# هندلر برای خطاهای 500
@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'خطای داخلی سرور'}), 500

# اجرای برنامه
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)