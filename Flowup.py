import os
import sqlite3
import uuid
import hashlib
import logging
import base64
import re
import json
import mimetypes
import secrets
import time
import warnings
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, redirect, url_for, session, g, flash, send_from_directory, jsonify, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Suppress rate limiting warning for development
warnings.filterwarnings("ignore", category=UserWarning, module="flask_limiter")

# ============================================================
# CREATE APP
# ============================================================
app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=100 * 1024 * 1024
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
STATIC_FOLDER = os.path.join(BASE_DIR, 'static')
ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp'
}

ALLOWED_MIME_TYPES = {
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/webp': ['.webp'],
    'video/mp4': ['.mp4', '.m4v'],
    'video/webm': ['.webm'],
    'video/quicktime': ['.mov'],
    'video/x-msvideo': ['.avi'],
    'video/x-flv': ['.flv'],
    'video/x-ms-wmv': ['.wmv'],
    'video/mp4v-es': ['.mp4'],
    'video/mpeg': ['.mpeg', '.mpg'],
    'video/ogg': ['.ogv', '.ogg'],
    'video/3gpp': ['.3gp']
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================
# RATE LIMITING
# ============================================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ============================================================
# SECURITY HEADERS
# ============================================================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ============================================================
# DEFAULT IMAGES
# ============================================================
def create_default_svg(path, content):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(content)

DEFAULT_PIC_PATH = os.path.join(STATIC_FOLDER, 'default.svg')
create_default_svg(DEFAULT_PIC_PATH, '''<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
    <circle cx="100" cy="100" r="100" fill="#d868ff"/>
    <circle cx="100" cy="70" r="35" fill="white" opacity="0.8"/>
    <circle cx="100" cy="160" r="50" fill="white" opacity="0.6"/>
</svg>''')

DEFAULT_POST_PATH = os.path.join(STATIC_FOLDER, 'default_post.svg')
create_default_svg(DEFAULT_POST_PATH, '''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400" viewBox="0 0 400 400">
    <rect width="400" height="400" fill="#1a1a2e"/>
    <circle cx="200" cy="180" r="60" fill="#d868ff" opacity="0.3"/>
    <rect x="120" y="260" width="160" height="30" rx="15" fill="#d868ff" opacity="0.2"/>
    <rect x="150" y="300" width="100" height="20" rx="10" fill="#d868ff" opacity="0.15"/>
    <text x="200" y="200" text-anchor="middle" fill="#d868ff" font-size="40" font-family="Arial">📸</text>
    <text x="200" y="350" text-anchor="middle" fill="#888" font-size="16" font-family="Arial">No image available</text>
</svg>''')

DATABASE = os.path.join(BASE_DIR, 'instagram.db')

# ============================================================
# DATABASE
# ============================================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT,
                bio TEXT,
                profile_pic TEXT DEFAULT 'default.svg',
                online_status TEXT DEFAULT 'offline',
                last_seen TIMESTAMP,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                media_url TEXT NOT NULL,
                media_type TEXT NOT NULL,
                caption TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, post_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                parent_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (parent_id) REFERENCES comments (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER NOT NULL,
                followed_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (follower_id, followed_id),
                FOREIGN KEY (follower_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (followed_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                media_url TEXT NOT NULL,
                caption TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                media_url TEXT NOT NULL,
                media_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT (datetime('now', '+24 hours')),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS story_views (
                user_id INTEGER NOT NULL,
                story_id INTEGER NOT NULL,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, story_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (story_id) REFERENCES stories (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reel_likes (
                user_id INTEGER NOT NULL,
                reel_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, reel_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (reel_id) REFERENCES reels (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS typing_status (
                user_id INTEGER PRIMARY KEY,
                is_typing INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                from_user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                read INTEGER DEFAULT 0,
                link TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_posts (
                user_id INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, post_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_reels (
                user_id INTEGER NOT NULL,
                reel_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, reel_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (reel_id) REFERENCES reels (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                target_id INTEGER,
                target_type TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                username TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_followed ON follows(followed_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_stories_user_id ON stories(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_stories_created ON stories(created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reels_user_id ON reels(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reels_created ON reels(created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(user_id, read)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_user ON user_activity(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_created ON user_activity(created_at DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_saved_posts_user ON saved_posts(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_saved_reels_user ON saved_reels(user_id)')

        db.commit()
        print("✅ Database initialized successfully!")

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(e):
    flash('File ni kubwa sana. Maximum size ni 100MB.', 'danger')
    return redirect(request.url or url_for('upload'))

@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    flash('Page not found.', 'danger')
    return redirect(url_for('feed'))

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Server error: {e}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    flash('Something went wrong. Please try again.', 'danger')
    return redirect(url_for('feed'))

@app.errorhandler(429)
def ratelimit_error(e):
    flash('Too many requests. Please wait and try again.', 'warning')
    return redirect(request.url or url_for('feed'))

# ============================================================
# SECURITY HELPERS
# ============================================================
def generate_csrf_token():
    stored = session.get('_csrf_token')
    if stored and isinstance(stored, dict):
        if stored.get('expires', 0) > int(time.time()):
            return stored['value']
    token = {
        'value': secrets.token_urlsafe(32),
        'created_at': int(time.time()),
        'expires': int(time.time()) + 3600
    }
    session['_csrf_token'] = token
    return token['value']

def validate_csrf_token(token):
    stored = session.get('_csrf_token')
    if not stored or not isinstance(stored, dict):
        return False
    if stored.get('expires', 0) < int(time.time()):
        session.pop('_csrf_token', None)
        return False
    return token == stored.get('value')

def validate_api_csrf():
    token = request.headers.get('X-CSRFToken')
    if not token:
        return False
    return validate_csrf_token(token)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Tafadhali ingia kwanza.', 'warning')
            return redirect(url_for('login'))
        try:
            user = get_user(session['user_id'])
            if not user:
                session.clear()
                flash('Account not found. Please login again.', 'warning')
                return redirect(url_for('login'))
        except:
            session.clear()
            flash('Session error. Please login again.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# FILE VALIDATION
# ============================================================
def validate_file_content(file):
    try:
        import magic
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        file_bytes = file.read(2048)
        file.seek(0)
        mime = magic.from_buffer(file_bytes, mime=True)
        
        if mime not in ALLOWED_MIME_TYPES:
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext in ['mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp']:
                mime = 'video/mp4'
            elif ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                mime = 'image/jpeg'
            else:
                return False, f"File type '{mime}' not allowed"
        
        max_file_size = 100 * 1024 * 1024
        max_image_size = 20 * 1024 * 1024
        
        if mime.startswith('image/') and size > max_image_size:
            return False, f"Image too large. Maximum {max_image_size // (1024*1024)}MB"
        elif mime.startswith('video/') and size > max_file_size:
            return False, f"Video too large. Maximum {max_file_size // (1024*1024)}MB"
        
        if mime.startswith('image/'):
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(file_bytes))
                img.verify()
                file.seek(0)
                img = Image.open(file)
                if img.width < 10 or img.height < 10:
                    return False, "Image too small (minimum 10x10 pixels)"
                if img.width > 8000 or img.height > 8000:
                    return False, "Image too large (maximum 8000x8000 pixels)"
                file.seek(0)
            except Exception as e:
                return False, f"Invalid image file: {str(e)}"
        
        return True, "OK"
    except ImportError:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        video_extensions = ['mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp', 'mpeg', 'mpg']
        image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']
        if ext in video_extensions or ext in image_extensions:
            return True, "OK"
        return False, f"File type '.{ext}' not allowed"
    except Exception as e:
        logger.error(f"File validation error: {e}")
        return False, "Error validating file"

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    valid_extensions = set()
    for mime_exts in ALLOWED_MIME_TYPES.values():
        valid_extensions.update(mime_exts)
    valid_extensions = {ext.lstrip('.') for ext in valid_extensions}
    valid_extensions.update(['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'])
    return ext in valid_extensions

def detect_media_type(filename):
    video_extensions = {'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp', 'mpeg', 'mpg'}
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext in video_extensions:
        return 'video'
    return 'image'

def save_uploaded_file(file, prefix=''):
    try:
        if '.' not in file.filename:
            return None, None, None
        ext = file.filename.rsplit('.', 1)[1].lower()
        allowed_extensions = {'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'}
        if ext not in allowed_extensions:
            return None, None, None
        
        unique_id = str(uuid.uuid4())
        filename = f"{prefix}{unique_id}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return None, None, None
        
        video_exts = {'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp'}
        media_type = 'video' if ext in video_exts else 'image'
        
        if media_type == 'video':
            try:
                thumbnail = create_video_thumbnail(filepath, filename)
                if thumbnail:
                    thumb_old = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail)
                    thumb_new = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_thumb.jpg")
                    if os.path.exists(thumb_old):
                        os.rename(thumb_old, thumb_new)
            except Exception as e:
                print(f"⚠️ Thumbnail error: {e}")
        
        if media_type == 'image':
            try:
                from PIL import Image
                with Image.open(filepath) as img:
                    if img.mode in ('RGBA', 'LA', 'P'):
                        img = img.convert('RGB')
                    max_size = 2000
                    if max(img.size) > max_size:
                        img.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)
                    img.save(filepath, 'JPEG', quality=85, optimize=True)
            except Exception as e:
                print(f"⚠️ Image processing error: {e}")
        
        return filename, filepath, media_type
    except Exception as e:
        print(f"❌ Error saving file: {e}")
        return None, None, None

def create_video_thumbnail(video_path, video_filename):
    try:
        import subprocess
        base_name = os.path.splitext(video_filename)[0]
        thumb_filename = f"{base_name}_thumb.jpg"
        thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename)
        cmd = ['ffmpeg', '-i', video_path, '-ss', '00:00:01', '-vframes', '1', '-vf', 'scale=640:-1', '-q:v', '2', thumb_path, '-y']
        subprocess.run(cmd, capture_output=True, timeout=30)
        if os.path.exists(thumb_path) and os.path.getsize(thumb_path) > 0:
            return thumb_filename
        return create_thumbnail_with_pil(video_path, video_filename)
    except Exception as e:
        return create_thumbnail_with_pil(video_path, video_filename)

def create_thumbnail_with_pil(video_path, video_filename):
    try:
        from PIL import Image
        base_name = os.path.splitext(video_filename)[0]
        thumb_filename = f"{base_name}_thumb.jpg"
        thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], thumb_filename)
        img = Image.new('RGB', (640, 360), color=(26, 26, 46))
        img.save(thumb_path, 'JPEG', quality=85)
        return thumb_filename
    except Exception as e:
        return None

def save_media_from_data(media_data, post_type):
    media_url = None
    media_type = None
    try:
        if not media_data:
            return None, None
        if media_data.startswith('data:image'):
            header, encoded = media_data.split(',', 1)
            media_file = base64.b64decode(encoded)
            unique_id = str(uuid.uuid4())
            filename = f"{post_type}_{unique_id}.jpg"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                from PIL import Image
                import io
                image = Image.open(io.BytesIO(media_file))
                if image.mode in ('RGBA', 'LA', 'P'):
                    image = image.convert('RGB')
                max_size = 2000
                if max(image.size) > max_size:
                    image.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)
                image.save(filepath, 'JPEG', quality=85, optimize=True)
            except Exception as e:
                with open(filepath, 'wb') as f:
                    f.write(media_file)
            media_url = f'static/uploads/{filename}'
            media_type = 'image'
        elif media_data.startswith('data:video'):
            header, encoded = media_data.split(',', 1)
            media_file = base64.b64decode(encoded)
            unique_id = str(uuid.uuid4())
            filename = f"{post_type}_{unique_id}.mp4"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(filepath, 'wb') as f:
                f.write(media_file)
            create_video_thumbnail(filepath, filename)
            media_url = f'static/uploads/{filename}'
            media_type = 'video'
    except Exception as e:
        logger.error(f"Failed to save media from data: {e}")
        return None, None
    return media_url, media_type

# ============================================================
# VALIDATION HELPERS
# ============================================================
def validate_username(username):
    if not username or len(username) < 3 or len(username) > 30:
        return False, "Username must be 3-30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscore"
    return True, "OK"

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "OK"

def validate_caption(text):
    if len(text) > 2200:
        return False, "Caption too long (maximum 2200 characters)"
    return True, "OK"

def validate_comment(text):
    if len(text) > 500:
        return False, "Comment too long (maximum 500 characters)"
    if len(text) < 1:
        return False, "Comment cannot be empty"
    return True, "OK"

def validate_bio(text):
    if len(text) > 150:
        return False, "Bio too long (maximum 150 characters)"
    return True, "OK"

# ============================================================
# LOGGING HELPERS
# ============================================================
def log_activity(user_id, activity_type, target_id=None, target_type=None, metadata=None):
    try:
        db = get_db()
        db.execute('''
            INSERT INTO user_activity (user_id, activity_type, target_id, target_type, metadata)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, activity_type, target_id, target_type, json.dumps(metadata) if metadata else None))
        db.commit()
    except Exception as e:
        logger.error(f"Error logging activity: {e}")

def get_user_activity(user_id, limit=50):
    db = get_db()
    activities = db.execute('''
        SELECT * FROM user_activity
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    ''', (user_id, limit)).fetchall()
    result = []
    for act in activities:
        meta = json.loads(act['metadata']) if act['metadata'] else {}
        result.append({
            'id': act['id'],
            'type': act['activity_type'],
            'target_id': act['target_id'],
            'target_type': act['target_type'],
            'metadata': meta,
            'created_at': act['created_at']
        })
    return result

def log_security_event(event_type, details, user_id=None):
    logger.info(f"Security Event: {event_type} - User: {user_id} - Details: {details}")
    try:
        db = get_db()
        db.execute('''
            INSERT INTO audit_log (user_id, action, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, event_type, details, request.remote_addr, request.headers.get('User-Agent', '')))
        db.commit()
    except Exception as e:
        logger.error(f"Error logging security event: {e}")

def check_login_attempts(ip_address, username=None):
    db = get_db()
    cutoff = datetime.now() - timedelta(minutes=15)
    attempts = db.execute('''
        SELECT COUNT(*) FROM login_attempts
        WHERE ip_address = ? AND attempt_time > ?
    ''', (ip_address, cutoff)).fetchone()[0]
    if attempts >= 10:
        return False, "Too many login attempts. Please try again later."
    if username:
        attempts = db.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE username = ? AND attempt_time > ?
        ''', (username, cutoff)).fetchone()[0]
        if attempts >= 5:
            return False, "Too many failed attempts for this username. Please try again later."
    return True, "OK"

def log_login_attempt(ip_address, username, success):
    db = get_db()
    db.execute('''
        INSERT INTO login_attempts (ip_address, username, success)
        VALUES (?, ?, ?)
    ''', (ip_address, username, 1 if success else 0))
    db.commit()

# ============================================================
# DATABASE HELPERS
# ============================================================
def get_user(user_id):
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cur.fetchone()

def get_user_by_username(username):
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
    return cur.fetchone()

def get_feed_posts(user_id, page=1, per_page=10):
    offset = (page - 1) * per_page
    db = get_db()
    sql = '''
        SELECT
            p.id,
            p.user_id,
            p.media_url,
            p.media_type,
            p.caption,
            p.created_at,
            u.username,
            u.full_name,
            u.profile_pic,
            COALESCE(lc.like_count, 0) AS like_count,
            COALESCE(cc.comment_count, 0) AS comment_count,
            CASE WHEN l.user_id IS NOT NULL THEN 1 ELSE 0 END AS liked_by_user,
            CASE WHEN p.user_id = ? THEN 1 ELSE 0 END AS is_owner
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS like_count
            FROM likes
            GROUP BY post_id
        ) lc ON p.id = lc.post_id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS comment_count
            FROM comments
            GROUP BY post_id
        ) cc ON p.id = cc.post_id
        LEFT JOIN likes l ON l.post_id = p.id AND l.user_id = ?
        WHERE p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)
           OR p.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
    '''
    cur = db.execute(sql, (user_id, user_id, user_id, user_id, per_page, offset))
    return cur.fetchall()

def get_total_feed_posts(user_id):
    db = get_db()
    cur = db.execute('''
        SELECT COUNT(*) FROM posts p
        WHERE p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)
           OR p.user_id = ?
    ''', (user_id, user_id))
    return cur.fetchone()[0]

def get_comments_with_replies(post_id, page=1, per_page=20):
    offset = (page - 1) * per_page
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM comments WHERE post_id = ?', (post_id,)).fetchone()[0]
    cur = db.execute('''
        SELECT c.*, u.username, u.full_name, u.profile_pic
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.parent_id NULLS FIRST, c.created_at ASC
        LIMIT ? OFFSET ?
    ''', (post_id, per_page, offset))
    comments = cur.fetchall()
    return {'total': total, 'comments': [dict(row) for row in comments]}

def search_users(query):
    db = get_db()
    cur = db.execute('''
        SELECT id, username, full_name, profile_pic
        FROM users
        WHERE username LIKE ? OR full_name LIKE ?
        LIMIT 20
    ''', (f'%{query}%', f'%{query}%'))
    return cur.fetchall()

def get_user_posts(user_id, current_user_id, page=1, per_page=9):
    offset = (page - 1) * per_page
    db = get_db()
    sql = '''
        SELECT
            p.id,
            p.user_id,
            p.media_url,
            p.media_type,
            p.caption,
            p.created_at,
            u.username,
            u.full_name,
            u.profile_pic,
            COALESCE(lc.like_count, 0) AS like_count,
            COALESCE(cc.comment_count, 0) AS comment_count,
            CASE WHEN l.user_id IS NOT NULL THEN 1 ELSE 0 END AS liked_by_user,
            CASE WHEN p.user_id = ? THEN 1 ELSE 0 END AS is_owner
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS like_count
            FROM likes
            GROUP BY post_id
        ) lc ON p.id = lc.post_id
        LEFT JOIN (
            SELECT post_id, COUNT(*) AS comment_count
            FROM comments
            GROUP BY post_id
        ) cc ON p.id = cc.post_id
        LEFT JOIN likes l ON l.post_id = p.id AND l.user_id = ?
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
    '''
    cur = db.execute(sql, (current_user_id, current_user_id, user_id, per_page, offset))
    return cur.fetchall()

def count_followers(user_id):
    db = get_db()
    cur = db.execute('SELECT COUNT(*) FROM follows WHERE followed_id = ?', (user_id,))
    return cur.fetchone()[0]

def count_following(user_id):
    db = get_db()
    cur = db.execute('SELECT COUNT(*) FROM follows WHERE follower_id = ?', (user_id,))
    return cur.fetchone()[0]

def count_user_posts(user_id):
    db = get_db()
    cur = db.execute('SELECT COUNT(*) FROM posts WHERE user_id = ?', (user_id,))
    return cur.fetchone()[0]

def count_user_reels(user_id):
    db = get_db()
    cur = db.execute('SELECT COUNT(*) FROM reels WHERE user_id = ?', (user_id,))
    return cur.fetchone()[0]

def check_is_following(follower_id, followed_id):
    db = get_db()
    cur = db.execute('SELECT * FROM follows WHERE follower_id = ? AND followed_id = ?', (follower_id, followed_id))
    return cur.fetchone() is not None

def get_stories_grouped_by_user(user_id):
    db = get_db()
    sql = '''
        SELECT
            u.id as user_id,
            u.username,
            u.full_name,
            u.profile_pic,
            s.id as story_id,
            s.media_url,
            s.media_type,
            s.created_at,
            s.expires_at,
            CASE
                WHEN sv.user_id IS NOT NULL THEN 1
                ELSE 0
            END as is_viewed
        FROM users u
        JOIN stories s ON u.id = s.user_id
        LEFT JOIN story_views sv ON s.id = sv.story_id AND sv.user_id = ?
        WHERE (
            u.id IN (SELECT followed_id FROM follows WHERE follower_id = ?)
            OR u.id = ?
        )
        AND s.expires_at > datetime('now')
        ORDER BY
            is_viewed ASC,
            s.created_at DESC
    '''
    cur = db.execute(sql, (user_id, user_id, user_id))
    rows = cur.fetchall()
    grouped = {}
    for row in rows:
        uid = row['user_id']
        if uid not in grouped:
            grouped[uid] = {
                'user_id': uid,
                'username': row['username'],
                'full_name': row['full_name'],
                'profile_pic': row['profile_pic'] or 'default.svg',
                'has_unviewed': not row['is_viewed'],
                'stories': []
            }
        grouped[uid]['stories'].append({
            'id': row['story_id'],
            'media_url': row['media_url'],
            'media_type': row['media_type'],
            'created_at': row['created_at'],
            'expires_at': row['expires_at'],
            'is_viewed': row['is_viewed']
        })
    sorted_stories = sorted(grouped.values(), key=lambda x: (not x['has_unviewed'], -len(x['stories'])))
    return sorted_stories

def get_user_stories_grouped(user_id, viewer_id):
    db = get_db()
    sql = '''
        SELECT
            u.id as user_id,
            u.username,
            u.full_name,
            u.profile_pic,
            s.id as story_id,
            s.media_url,
            s.media_type,
            s.created_at,
            s.expires_at,
            CASE
                WHEN sv.user_id IS NOT NULL THEN 1
                ELSE 0
            END as is_viewed
        FROM users u
        JOIN stories s ON u.id = s.user_id
        LEFT JOIN story_views sv ON s.id = sv.story_id AND sv.user_id = ?
        WHERE u.id = ?
        AND s.expires_at > datetime('now')
        ORDER BY s.created_at DESC
    '''
    cur = db.execute(sql, (viewer_id, user_id))
    rows = cur.fetchall()
    if not rows:
        return None
    result = {
        'user_id': rows[0]['user_id'],
        'username': rows[0]['username'],
        'full_name': rows[0]['full_name'],
        'profile_pic': rows[0]['profile_pic'] or 'default.svg',
        'stories': []
    }
    for row in rows:
        result['stories'].append({
            'id': row['story_id'],
            'media_url': row['media_url'],
            'media_type': row['media_type'],
            'created_at': row['created_at'],
            'expires_at': row['expires_at'],
            'is_viewed': row['is_viewed']
        })
    return result

def view_story(user_id, story_id):
    db = get_db()
    try:
        with db:
            db.execute('''
                INSERT OR IGNORE INTO story_views (user_id, story_id)
                VALUES (?, ?)
            ''', (user_id, story_id))
        return True
    except Exception as e:
        logger.error(f"Error viewing story: {e}")
        return False

def get_reels(user_id, page=1, per_page=10):
    offset = (page - 1) * per_page
    db = get_db()
    sql = '''
        SELECT r.*, u.username, u.full_name, u.profile_pic,
               COALESCE(rl.like_count, 0) AS like_count,
               CASE WHEN rl2.user_id IS NOT NULL THEN 1 ELSE 0 END AS liked_by_user,
               CASE WHEN r.user_id = ? THEN 1 ELSE 0 END AS is_owner,
               CASE WHEN EXISTS (SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = r.user_id) THEN 1 ELSE 0 END AS is_following
        FROM reels r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN (
            SELECT reel_id, COUNT(*) AS like_count
            FROM reel_likes
            GROUP BY reel_id
        ) rl ON r.id = rl.reel_id
        LEFT JOIN reel_likes rl2 ON rl2.reel_id = r.id AND rl2.user_id = ?
        ORDER BY r.created_at DESC
        LIMIT ? OFFSET ?
    '''
    cur = db.execute(sql, (user_id, user_id, user_id, per_page, offset))
    return cur.fetchall()

def get_total_reels():
    db = get_db()
    cur = db.execute('SELECT COUNT(*) FROM reels')
    return cur.fetchone()[0]

def get_user_reels(user_id, current_user_id, page=1, per_page=9):
    offset = (page - 1) * per_page
    db = get_db()
    sql = '''
        SELECT r.*, u.username, u.full_name, u.profile_pic,
               COALESCE(rl.like_count, 0) AS like_count,
               CASE WHEN rl2.user_id IS NOT NULL THEN 1 ELSE 0 END AS liked_by_user,
               CASE WHEN r.user_id = ? THEN 1 ELSE 0 END AS is_owner
        FROM reels r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN (
            SELECT reel_id, COUNT(*) AS like_count
            FROM reel_likes
            GROUP BY reel_id
        ) rl ON r.id = rl.reel_id
        LEFT JOIN reel_likes rl2 ON rl2.reel_id = r.id AND rl2.user_id = ?
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
        LIMIT ? OFFSET ?
    '''
    cur = db.execute(sql, (current_user_id, current_user_id, user_id, per_page, offset))
    return cur.fetchall()

# ============================================================
# ROUTES - AUTH
# ============================================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            error = 'Please fill in all fields.'
            return render_template_string(LOGIN_TEMPLATE, error=error, flashes=get_flashed_messages(with_categories=True))
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True
            generate_csrf_token()
            db.execute('UPDATE users SET online_status = "online", last_seen = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            db.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('feed'))
        else:
            error = 'Invalid username or password.'
    return render_template_string(LOGIN_TEMPLATE, error=error, flashes=get_flashed_messages(with_categories=True))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        valid, msg = validate_username(username)
        if not valid:
            error = msg
        elif password != confirm_password:
            error = 'Passwords do not match.'
        else:
            valid, msg = validate_password(password)
            if not valid:
                error = msg
            else:
                db = get_db()
                existing = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if existing:
                    error = 'Username already taken.'
                else:
                    hashed = generate_password_hash(password)
                    db.execute('INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)',
                               (username, hashed, full_name))
                    db.commit()
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('login'))
    return render_template_string(REGISTER_TEMPLATE, error=error, flashes=get_flashed_messages(with_categories=True))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        try:
            db = get_db()
            db.execute('UPDATE users SET online_status = "offline", last_seen = CURRENT_TIMESTAMP WHERE id = ?', (session['user_id'],))
            db.commit()
            log_activity(session['user_id'], 'logout')
            log_security_event('LOGOUT', f'User logged out', session['user_id'])
        except:
            pass
        session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/logout_all')
def logout_all():
    session.clear()
    flash('Logged out of all accounts.', 'info')
    return redirect(url_for('login'))

# ============================================================
# ROUTES - MAIN
# ============================================================
@app.route('/feed')
@login_required
def feed():
    try:
        user = get_user(session['user_id'])
        if not user:
            session.clear()
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('login'))
        
        page = request.args.get('page', 1, type=int)
        per_page = 10
        posts = get_feed_posts(session['user_id'], page, per_page)
        total_posts = get_total_feed_posts(session['user_id'])
        total_pages = (total_posts + per_page - 1) // per_page if total_posts > 0 else 1
        
        db = get_db()
        db.execute('UPDATE users SET online_status = "online", last_seen = CURRENT_TIMESTAMP WHERE id = ?', (session['user_id'],))
        db.commit()
        
        stories_data = get_stories_grouped_by_user(session['user_id'])
        
        has_unviewed_story = False
        stories = db.execute('''
            SELECT s.id FROM stories s
            LEFT JOIN story_views sv ON s.id = sv.story_id AND sv.user_id = ?
            WHERE s.user_id = ? AND sv.user_id IS NULL AND s.expires_at > datetime('now')
        ''', (session['user_id'], session['user_id'])).fetchone()
        if stories:
            has_unviewed_story = True
        
        unread_count = db.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND read = 0', (session['user_id'],)).fetchone()[0]
        unread_count += db.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read = 0', (session['user_id'],)).fetchone()[0]
        
        other_accounts = db.execute('''
            SELECT id, username, full_name, profile_pic 
            FROM users 
            WHERE id != ? 
            ORDER BY created_at DESC
            LIMIT 10
        ''', (session['user_id'],)).fetchall()
        
        return render_template_string(FEED_TEMPLATE, 
                                      posts=posts, 
                                      current_user=user,
                                      other_accounts=other_accounts,
                                      stories=stories_data,
                                      has_unviewed_story=has_unviewed_story,
                                      page=page, 
                                      total_pages=total_pages,
                                      total_unread=unread_count,
                                      flashes=get_flashed_messages(with_categories=True))
    except Exception as e:
        print(f"❌ Feed error: {e}")
        import traceback
        traceback.print_exc()
        session.clear()
        flash('Session error. Please login again.', 'danger')
        return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            flash('Invalid CSRF token. Please refresh and try again.', 'danger')
            return redirect(request.url)
        
        post_type = request.form.get('post_type', 'post')
        caption = request.form.get('caption', '').strip()
        media_data = request.form.get('media_data', '')
        file = request.files.get('media')
        
        media_url = None
        media_type = None
        
        try:
            if file and file.filename != '':
                filename, filepath, media_type = save_uploaded_file(file, f'{post_type}_')
                if not filename:
                    flash('Error saving file. Please try again.', 'danger')
                    return redirect(request.url)
                media_url = f'static/uploads/{filename}'
                if not media_type:
                    media_type = detect_media_type(filename)
            elif media_data:
                media_url, media_type = save_media_from_data(media_data, post_type)
                if not media_url:
                    flash('Failed to process image/video from camera.', 'danger')
                    return redirect(request.url)
            else:
                flash('Tafadhali chagua picha au video.', 'warning')
                return redirect(request.url)
            
            if not media_url:
                flash('Error processing media. Please try again.', 'danger')
                return redirect(request.url)
            
            if not media_type:
                media_type = detect_media_type(media_url)
            
            db = get_db()
            if post_type == 'story':
                db.execute('''
                    INSERT INTO stories (user_id, media_url, media_type)
                    VALUES (?, ?, ?)
                ''', (session['user_id'], media_url, media_type))
                db.commit()
                log_activity(session['user_id'], 'story', metadata={'media_type': media_type})
                flash('Story imepakiwa!', 'success')
                return redirect(url_for('feed'))
            elif post_type == 'reel':
                if media_type != 'video':
                    flash('Reel inahitaji video.', 'danger')
                    return redirect(request.url)
                cursor = db.execute('''
                    INSERT INTO reels (user_id, media_url, caption)
                    VALUES (?, ?, ?)
                ''', (session['user_id'], media_url, caption))
                reel_id = cursor.lastrowid
                db.commit()
                log_activity(session['user_id'], 'reel', reel_id, 'reel', {'caption': caption[:50]})
                flash('Reel imepakiwa!', 'success')
                return redirect(url_for('explore'))
            else:
                cursor = db.execute('''
                    INSERT INTO posts (user_id, media_url, media_type, caption)
                    VALUES (?, ?, ?, ?)
                ''', (session['user_id'], media_url, media_type, caption))
                post_id = cursor.lastrowid
                db.commit()
                log_activity(session['user_id'], 'post', post_id, 'post', {'media_type': media_type, 'caption': caption[:50]})
                flash('Post imepakiwa!', 'success')
                return redirect(url_for('feed'))
        except Exception as e:
            db.rollback()
            logger.error(f"Database error during insert: {e}")
            flash('Error saving to database. Please try again.', 'danger')
            return redirect(request.url)
    
    return render_template_string(UPLOAD_TEMPLATE, flashes=get_flashed_messages(with_categories=True))

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = get_user_by_username(username)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('feed'))
    current_user = get_user(session['user_id'])
    is_following = False
    is_mutual = False
    if current_user and current_user['id'] != user['id']:
        is_following = check_is_following(current_user['id'], user['id'])
        is_mutual = is_following and check_is_following(user['id'], current_user['id'])
    post_page = request.args.get('post_page', 1, type=int)
    reel_page = request.args.get('reel_page', 1, type=int)
    per_page = 9
    posts = get_user_posts(user['id'], current_user['id'], post_page, per_page)
    total_posts = count_user_posts(user['id'])
    total_post_pages = (total_posts + per_page - 1) // per_page if total_posts > 0 else 1
    reels = get_user_reels(user['id'], current_user['id'], reel_page, per_page)
    total_reels = count_user_reels(user['id'])
    total_reel_pages = (total_reels + per_page - 1) // per_page if total_reels > 0 else 1
    follow_action = 'Unfollow' if is_following else 'Follow'
    follow_url = url_for('follow_user', user_id=user['id'])
    followers_count = count_followers(user['id'])
    following_count = count_following(user['id'])
    return render_template_string(PROFILE_TEMPLATE,
                                  user=user, current_user=current_user,
                                  posts=posts, reels=reels,
                                  post_page=post_page, reel_page=reel_page,
                                  total_posts=total_posts, total_reels=total_reels,
                                  total_post_pages=total_post_pages, total_reel_pages=total_reel_pages,
                                  follow_action=follow_action, follow_url=follow_url,
                                  followers_count=followers_count, following_count=following_count,
                                  is_mutual=is_mutual,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = get_user(session['user_id'])
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not validate_csrf_token(csrf_token):
            flash('Invalid CSRF token', 'danger')
            return redirect(request.url)
        full_name = request.form.get('full_name', '').strip()
        bio = request.form.get('bio', '').strip()
        if len(bio) > 150:
            flash('Bio too long (maximum 150 characters)', 'danger')
            return redirect(request.url)
        db = get_db()
        file = request.files.get('profile_pic')
        if file and file.filename != '':
            ALLOWED_DP_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
            if '.' not in file.filename:
                flash('Invalid file name. Please use a valid image file.', 'danger')
                return redirect(request.url)
            ext = file.filename.rsplit('.', 1)[1].lower()
            if ext not in ALLOWED_DP_EXTENSIONS:
                flash(f'File type ".{ext}" not allowed. Please use JPG, PNG, GIF, or WebP.', 'danger')
                return redirect(request.url)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            if file_size > 5 * 1024 * 1024:
                flash('File too large! Maximum size is 5MB.', 'danger')
                return redirect(request.url)
            try:
                from PIL import Image
                import io
                file_bytes = file.read()
                file.seek(0)
                img = Image.open(io.BytesIO(file_bytes))
                img.verify()
                file.seek(0)
                unique_id = str(uuid.uuid4())
                filename = f"dp_{unique_id}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img = Image.open(file)
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                width, height = img.size
                size = min(width, height)
                left = (width - size) // 2
                top = (height - size) // 2
                img = img.crop((left, top, left + size, top + size))
                img = img.resize((300, 300), Image.Resampling.LANCZOS)
                if ext.lower() in ['jpg', 'jpeg']:
                    img.save(filepath, 'JPEG', quality=90, optimize=True)
                else:
                    img.save(filepath, optimize=True)
                old_pic = user['profile_pic']
                if old_pic and old_pic != 'default.svg':
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_pic)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                db.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (filename, user['id']))
            except Exception as e:
                flash(f'Error processing image: {str(e)}', 'danger')
                return redirect(request.url)
        db.execute('UPDATE users SET full_name = ?, bio = ? WHERE id = ?', (full_name, bio, user['id']))
        db.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile', username=user['username']))
    profile_pic = user['profile_pic'] or 'default.svg'
    return render_template_string(EDIT_PROFILE_TEMPLATE, user=user, profile_pic=profile_pic,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/settings')
@login_required
def settings():
    current_user = get_user(session['user_id'])
    return render_template_string(SETTINGS_TEMPLATE, 
                                  current_user=current_user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/account_center')
@login_required
def account_center():
    db = get_db()
    current_user = get_user(session['user_id'])
    other_accounts = db.execute('''
        SELECT id, username, full_name, profile_pic 
        FROM users 
        WHERE id != ? 
        ORDER BY created_at DESC
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    return render_template_string(ACCOUNT_CENTER_TEMPLATE, 
                                  current_user=current_user,
                                  other_accounts=other_accounts,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/about')
@login_required
def about():
    current_user = get_user(session['user_id'])
    return render_template_string(ABOUT_TEMPLATE, 
                                  current_user=current_user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    user_id = session['user_id']
    current_user = get_user(user_id)
    
    db.execute('UPDATE notifications SET read = 1 WHERE user_id = ?', (user_id,))
    db.commit()
    
    notifs = db.execute('''
        SELECT n.*, u.username, u.full_name, u.profile_pic
        FROM notifications n
        JOIN users u ON n.from_user_id = u.id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
        LIMIT 50
    ''', (user_id,)).fetchall()
    
    return render_template_string(NOTIFICATIONS_TEMPLATE, 
                                  notifs=notifs,
                                  current_user=current_user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/search')
@login_required
def search_page():
    current_user = get_user(session['user_id'])
    return render_template_string(SEARCH_TEMPLATE, 
                                  current_user=current_user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/history')
@login_required
def history():
    user = get_user(session['user_id'])
    activities = get_user_activity(session['user_id'])
    
    db = get_db()
    saved_posts = db.execute('''
        SELECT sp.*, p.media_url, p.media_type, p.caption, p.created_at as post_created_at,
               u.username, u.full_name, u.profile_pic,
               (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS like_count,
               (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comment_count
        FROM saved_posts sp
        JOIN posts p ON sp.post_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE sp.user_id = ?
        ORDER BY sp.created_at DESC
        LIMIT 50
    ''', (session['user_id'],)).fetchall()
    
    saved_reels = db.execute('''
        SELECT sr.*, r.media_url, r.caption, r.created_at as reel_created_at,
               u.username, u.full_name, u.profile_pic,
               (SELECT COUNT(*) FROM reel_likes WHERE reel_id = r.id) AS like_count
        FROM saved_reels sr
        JOIN reels r ON sr.reel_id = r.id
        JOIN users u ON r.user_id = u.id
        WHERE sr.user_id = ?
        ORDER BY sr.created_at DESC
        LIMIT 50
    ''', (session['user_id'],)).fetchall()
    
    return render_template_string(HISTORY_TEMPLATE, 
                                  user=user, 
                                  activities=activities,
                                  saved_posts=saved_posts,
                                  saved_reels=saved_reels,
                                  current_user=user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    db = get_db()
    current_user = get_user(session['user_id'])
    post = db.execute('''
        SELECT p.*, u.username, u.full_name, u.profile_pic,
               (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS like_count,
               (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comment_count,
               EXISTS (SELECT 1 FROM likes WHERE user_id = ? AND post_id = p.id) AS liked_by_user,
               (p.user_id = ?) AS is_owner
        FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?
    ''', (session['user_id'], session['user_id'], post_id)).fetchone()
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))
    return render_template_string(POST_VIEW_TEMPLATE, post=post, current_user=current_user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/reel/<int:reel_id>')
@login_required
def view_reel(reel_id):
    db = get_db()
    current_user = get_user(session['user_id'])
    all_reels = db.execute('''
        SELECT r.*, u.username, u.full_name, u.profile_pic, u.id as user_id,
               (SELECT COUNT(*) FROM reel_likes WHERE reel_id = r.id) AS like_count,
               EXISTS (SELECT 1 FROM reel_likes WHERE user_id = ? AND reel_id = r.id) AS liked_by_user,
               EXISTS (SELECT 1 FROM saved_reels WHERE user_id = ? AND reel_id = r.id) AS saved_by_user,
               (r.user_id = ?) AS is_owner,
               EXISTS (SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = r.user_id) AS is_following
        FROM reels r 
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id'])).fetchall()
    if not all_reels:
        flash('No reels found.', 'warning')
        return redirect(url_for('explore'))
    reel_exists = any(r['id'] == reel_id for r in all_reels)
    if not reel_exists:
        flash('Reel not found.', 'danger')
        return redirect(url_for('explore'))
    return render_template_string(REEL_VIEW_TEMPLATE, 
                                  reels=all_reels,
                                  current_user=current_user,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/explore')
@login_required
def explore():
    user = get_user(session['user_id'])
    page = request.args.get('page', 1, type=int)
    per_page = 10
    reels = get_reels(session['user_id'], page, per_page)
    total_reels = get_total_reels()
    total_pages = (total_reels + per_page - 1) // per_page if total_reels > 0 else 1
    return render_template_string(REELS_TEMPLATE, reels=reels, current_user=user,
                                  page=page, total_pages=total_pages,
                                  flashes=get_flashed_messages(with_categories=True))

@app.route('/follow/<int:user_id>')
@login_required
def follow_user(user_id):
    current_user_id = session['user_id']
    if current_user_id == user_id:
        flash('You cannot follow yourself.', 'warning')
        return redirect(request.referrer or url_for('feed'))
    db = get_db()
    cur = db.execute('SELECT * FROM follows WHERE follower_id = ? AND followed_id = ?', (current_user_id, user_id))
    if cur.fetchone():
        db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?', (current_user_id, user_id))
        db.commit()
        log_activity(current_user_id, 'unfollow', user_id, 'user')
        flash('Unfollowed.', 'info')
    else:
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)', (current_user_id, user_id))
        db.commit()
        user = get_user(current_user_id)
        db.execute('''
            INSERT INTO notifications (user_id, from_user_id, type, message, link)
            VALUES (?, ?, 'follow', ?, ?)
        ''', (user_id, current_user_id, f'{user["username"]} started following you', f'/profile/{user["username"]}'))
        db.commit()
        log_activity(current_user_id, 'follow', user_id, 'user')
        flash('Followed!', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/chat/<int:user_id>')
@login_required
def chat_with_user(user_id):
    other_user = get_user(user_id)
    if not other_user:
        flash('User not found', 'danger')
        return redirect(url_for('notifications'))
    db = get_db()
    messages = db.execute('''
        SELECT * FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
    ''', (session['user_id'], user_id, user_id, session['user_id'])).fetchall()
    db.execute('UPDATE messages SET read = 1 WHERE sender_id = ? AND receiver_id = ? AND read = 0',
               (user_id, session['user_id']))
    db.commit()
    return render_template_string(CHAT_TEMPLATE, messages=messages, other_user=other_user,
                                  current_user=get_user(session['user_id']),
                                  flashes=get_flashed_messages(with_categories=True))

# ============================================================
# STATIC FILES
# ============================================================
@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        if '..' in filename or filename.startswith('/'):
            return "Invalid filename", 400
        allowed_types = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'webm', 'mov', 'avi', 'mkv', 'svg']
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        if ext not in allowed_types:
            return "File type not allowed", 403
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(filepath):
            return send_from_directory(STATIC_FOLDER, 'default.svg')
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return send_from_directory(STATIC_FOLDER, 'default.svg')

# ============================================================
# API ROUTES
# ============================================================
@app.route('/api/like/<int:post_id>', methods=['POST'])
@login_required
def api_like(post_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    user_id = session['user_id']
    db = get_db()
    cur = db.execute('SELECT * FROM likes WHERE user_id = ? AND post_id = ?', (user_id, post_id))
    if cur.fetchone():
        db.execute('DELETE FROM likes WHERE user_id = ? AND post_id = ?', (user_id, post_id))
        liked = False
    else:
        db.execute('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', (user_id, post_id))
        liked = True
    post = db.execute('SELECT user_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post and post['user_id'] != user_id:
        user = get_user(user_id)
        db.execute('''
            INSERT INTO notifications (user_id, from_user_id, type, message, link)
            VALUES (?, ?, 'like', ?, ?)
        ''', (post['user_id'], user_id, f'{user["username"]} liked your post', f'/post/{post_id}'))
        db.commit()
    cur = db.execute('SELECT COUNT(*) FROM likes WHERE post_id = ?', (post_id,))
    like_count = cur.fetchone()[0]
    if liked:
        log_activity(user_id, 'like', post_id, 'post')
    return jsonify({'success': True, 'liked': liked, 'like_count': like_count})

@app.route('/api/comments/<int:post_id>')
@login_required
def api_comments(post_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    data = get_comments_with_replies(post_id, page, per_page)
    result = []
    for c in data['comments']:
        result.append({
            'id': c['id'], 'user_id': c['user_id'], 'username': c['username'],
            'text': c['text'], 'profile_pic': c['profile_pic'],
            'created_at': c['created_at'], 'parent_id': c['parent_id'],
            'can_delete': c['user_id'] == session['user_id']
        })
    return jsonify({'comments': result, 'total': data['total']})

@app.route('/api/comment', methods=['POST'])
@login_required
def api_comment():
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    data = request.get_json()
    post_id = data.get('post_id')
    text = data.get('text', '').strip()
    reply_to = data.get('reply_to')
    if not post_id or not text:
        return jsonify({'success': False, 'error': 'Missing fields'}), 400
    valid, msg = validate_comment(text)
    if not valid:
        return jsonify({'success': False, 'error': msg}), 400
    db = get_db()
    db.execute('INSERT INTO comments (user_id, post_id, text, parent_id) VALUES (?, ?, ?, ?)',
               (session['user_id'], post_id, text, reply_to))
    db.commit()
    post = db.execute('SELECT user_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post and post['user_id'] != session['user_id']:
        user = get_user(session['user_id'])
        db.execute('''
            INSERT INTO notifications (user_id, from_user_id, type, message, link)
            VALUES (?, ?, 'comment', ?, ?)
        ''', (post['user_id'], session['user_id'], f'{user["username"]} commented: {text[:50]}', f'/post/{post_id}'))
        db.commit()
    log_activity(session['user_id'], 'comment', post_id, 'post', {'comment_text': text[:50]})
    return jsonify({'success': True})

@app.route('/api/comment/<int:comment_id>', methods=['DELETE'])
@login_required
def api_delete_comment(comment_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    db = get_db()
    comment = db.execute('SELECT user_id FROM comments WHERE id = ?', (comment_id,)).fetchone()
    if not comment:
        return jsonify({'success': False, 'error': 'Comment not found'}), 404
    if comment['user_id'] != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/post/<int:post_id>', methods=['DELETE'])
@login_required
def api_delete_post(post_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    db = get_db()
    post = db.execute('SELECT user_id, media_url FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not post:
        return jsonify({'success': False, 'error': 'Post not found'}), 404
    if post['user_id'] != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    media_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(post['media_url']))
    if os.path.exists(media_path):
        os.remove(media_path)
    db.execute('DELETE FROM likes WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/reel/like/<int:reel_id>', methods=['POST'])
@login_required
def api_reel_like(reel_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    user_id = session['user_id']
    db = get_db()
    cur = db.execute('SELECT * FROM reel_likes WHERE user_id = ? AND reel_id = ?', (user_id, reel_id))
    if cur.fetchone():
        db.execute('DELETE FROM reel_likes WHERE user_id = ? AND reel_id = ?', (user_id, reel_id))
        liked = False
    else:
        db.execute('INSERT INTO reel_likes (user_id, reel_id) VALUES (?, ?)', (user_id, reel_id))
        liked = True
    db.commit()
    cur = db.execute('SELECT COUNT(*) FROM reel_likes WHERE reel_id = ?', (reel_id,))
    like_count = cur.fetchone()[0]
    return jsonify({'success': True, 'liked': liked, 'like_count': like_count})

@app.route('/api/reel/save/<int:reel_id>', methods=['POST'])
@login_required
def api_reel_save(reel_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    user_id = session['user_id']
    db = get_db()
    reel = db.execute('SELECT id FROM reels WHERE id = ?', (reel_id,)).fetchone()
    if not reel:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404
    cur = db.execute('SELECT * FROM saved_reels WHERE user_id = ? AND reel_id = ?', (user_id, reel_id))
    if cur.fetchone():
        db.execute('DELETE FROM saved_reels WHERE user_id = ? AND reel_id = ?', (user_id, reel_id))
        saved = False
    else:
        db.execute('INSERT INTO saved_reels (user_id, reel_id) VALUES (?, ?)', (user_id, reel_id))
        saved = True
        log_activity(user_id, 'save_reel', reel_id, 'reel')
    db.commit()
    return jsonify({'success': True, 'saved': saved})

@app.route('/api/reel/<int:reel_id>', methods=['DELETE'])
@login_required
def api_delete_reel(reel_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    db = get_db()
    reel = db.execute('SELECT user_id, media_url FROM reels WHERE id = ?', (reel_id,)).fetchone()
    if not reel:
        return jsonify({'success': False, 'error': 'Reel not found'}), 404
    if reel['user_id'] != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    media_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(reel['media_url']))
    if os.path.exists(media_path):
        os.remove(media_path)
    db.execute('DELETE FROM reel_likes WHERE reel_id = ?', (reel_id,))
    db.execute('DELETE FROM saved_reels WHERE reel_id = ?', (reel_id,))
    db.execute('DELETE FROM reels WHERE id = ?', (reel_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/stories/feed')
@login_required
def api_stories_feed():
    stories = get_stories_grouped_by_user(session['user_id'])
    return jsonify(stories)

@app.route('/api/stories/user/<int:user_id>')
@login_required
def api_stories_user(user_id):
    stories = get_user_stories_grouped(user_id, session['user_id'])
    if not stories:
        return jsonify({'error': 'No stories found'}), 404
    return jsonify(stories)

@app.route('/api/story/view', methods=['POST'])
@login_required
def api_view_story():
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    data = request.get_json()
    story_id = data.get('story_id')
    if not story_id:
        return jsonify({'error': 'Story ID required'}), 400
    if view_story(session['user_id'], story_id):
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to view story'}), 500

@app.route('/api/stories/upload', methods=['POST'])
@login_required
def api_upload_story():
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    if 'media' not in request.files:
        return jsonify({'error': 'No media file'}), 400
    file = request.files['media']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    valid, msg = validate_file_content(file)
    if not valid:
        return jsonify({'error': msg}), 400
    filename, filepath, media_type = save_uploaded_file(file, 'story_')
    if not filename:
        return jsonify({'error': 'Error saving file'}), 500
    media_url = f'static/uploads/{filename}'
    db = get_db()
    db.execute('''
        INSERT INTO stories (user_id, media_url, media_type)
        VALUES (?, ?, ?)
    ''', (session['user_id'], media_url, media_type))
    db.commit()
    return jsonify({'success': True, 'media_url': media_url, 'media_type': media_type})

@app.route('/api/search')
@login_required
def api_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    results = search_users(query)
    users = []
    seen = set()
    for row in results:
        if row['username'] not in seen:
            seen.add(row['username'])
            users.append({
                'id': row['id'], 'username': row['username'],
                'full_name': row['full_name'], 'profile_pic': row['profile_pic']})
    return jsonify(users)

@app.route('/api/save/<int:post_id>', methods=['POST'])
@login_required
def api_save_post(post_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    user_id = session['user_id']
    db = get_db()
    cur = db.execute('SELECT * FROM saved_posts WHERE user_id = ? AND post_id = ?', (user_id, post_id))
    if cur.fetchone():
        db.execute('DELETE FROM saved_posts WHERE user_id = ? AND post_id = ?', (user_id, post_id))
        saved = False
    else:
        db.execute('INSERT INTO saved_posts (user_id, post_id) VALUES (?, ?)', (user_id, post_id))
        saved = True
        log_activity(user_id, 'save', post_id, 'post')
    db.commit()
    return jsonify({'success': True, 'saved': saved})

@app.route('/api/report/<int:post_id>', methods=['POST'])
@login_required
def api_report_post(post_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    log_security_event('POST_REPORTED', f'Post {post_id} reported by user {session["user_id"]}', session['user_id'])
    return jsonify({'success': True})

@app.route('/api/follow/<int:user_id>', methods=['POST'])
@login_required
def api_follow(user_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    current_user_id = session['user_id']
    if current_user_id == user_id:
        return jsonify({'error': 'You cannot follow yourself'}), 400
    db = get_db()
    cur = db.execute('SELECT * FROM follows WHERE follower_id = ? AND followed_id = ?', (current_user_id, user_id))
    if cur.fetchone():
        db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?', (current_user_id, user_id))
        db.commit()
        log_activity(current_user_id, 'unfollow', user_id, 'user')
        return jsonify({'success': True, 'following': False})
    else:
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)', (current_user_id, user_id))
        db.commit()
        user = get_user(current_user_id)
        db.execute('''
            INSERT INTO notifications (user_id, from_user_id, type, message, link)
            VALUES (?, ?, 'follow', ?, ?)
        ''', (user_id, current_user_id, f'{user["username"]} started following you', f'/profile/{user["username"]}'))
        db.commit()
        log_activity(current_user_id, 'follow', user_id, 'user')
        return jsonify({'success': True, 'following': True})

@app.route('/api/switch_account/<int:user_id>', methods=['POST'])
@login_required
def api_switch_account(user_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.execute('UPDATE users SET online_status = "offline", last_seen = CURRENT_TIMESTAMP WHERE id = ?', (session['user_id'],))
    session['user_id'] = user['id']
    session.permanent = True
    db.execute('UPDATE users SET online_status = "online", last_seen = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
    db.commit()
    log_activity(user['id'], 'switch_account')
    log_security_event('ACCOUNT_SWITCH', f'Switched to account {user["username"]}', user['id'])
    return jsonify({'success': True, 'username': user['username'], 'redirect': '/feed'})

@app.route('/api/chat/send', methods=['POST'])
@login_required
def api_send_message():
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message = data.get('message', '').strip()
    if not receiver_id or not message:
        return jsonify({'success': False, 'error': 'Missing fields'}), 400
    if len(message) > 1000:
        return jsonify({'success': False, 'error': 'Message too long'}), 400
    db = get_db()
    db.execute('INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
               (session['user_id'], receiver_id, message))
    db.commit()
    sender = get_user(session['user_id'])
    db.execute('''
        INSERT INTO notifications (user_id, from_user_id, type, message, link)
        VALUES (?, ?, 'message', ?, ?)
    ''', (receiver_id, session['user_id'], f'New message from {sender["username"]}: {message[:50]}', f'/chat/{session["user_id"]}'))
    db.commit()
    log_activity(session['user_id'], 'message', receiver_id, 'user')
    return jsonify({'success': True})

@app.route('/api/chat/messages/<int:user_id>')
@login_required
def api_get_chat_messages(user_id):
    last_id = request.args.get('last_id', 0, type=int)
    db = get_db()
    messages = db.execute('''
        SELECT * FROM messages
        WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        AND id > ? ORDER BY created_at ASC
    ''', (session['user_id'], user_id, user_id, session['user_id'], last_id)).fetchall()
    return jsonify({'messages': [dict(row) for row in messages]})

@app.route('/api/chat/clear/<int:user_id>', methods=['DELETE'])
@login_required
def api_clear_chat(user_id):
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    db = get_db()
    db.execute('''
        DELETE FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ''', (session['user_id'], user_id, user_id, session['user_id']))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/messages/read/<int:user_id>', methods=['POST'])
@login_required
def api_mark_messages_read(user_id):
    db = get_db()
    db.execute('UPDATE messages SET read = 1 WHERE sender_id = ? AND receiver_id = ? AND read = 0',
               (user_id, session['user_id']))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/typing', methods=['POST'])
@login_required
def api_typing():
    if not validate_api_csrf():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    is_typing = data.get('is_typing', False)
    db = get_db()
    db.execute('''
        INSERT OR REPLACE INTO typing_status (user_id, is_typing, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (session['user_id'], 1 if is_typing else 0))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/typing/<int:user_id>')
@login_required
def api_get_typing(user_id):
    db = get_db()
    cur = db.execute('''
        SELECT is_typing FROM typing_status
        WHERE user_id = ? AND updated_at > datetime('now', '-5 seconds')
    ''', (user_id,))
    result = cur.fetchone()
    return jsonify({'is_typing': result['is_typing'] == 1 if result else False})

@app.route('/api/user/status/<int:user_id>')
@login_required
def api_user_status(user_id):
    db = get_db()
    cur = db.execute('SELECT online_status FROM users WHERE id = ?', (user_id,))
    result = cur.fetchone()
    status = result['online_status'] if result else 'offline'
    return jsonify({'status': status})

# ============================================================
# CONTEXT PROCESSOR
# ============================================================
@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf_token}

# ============================================================
# TEMPLATES - (All templates go here - compressed for space)
# ============================================================
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlowUp – Login</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:Arial,sans-serif}
        body{background:radial-gradient(circle at 0% 0%,#ffb6c9 0%,#f5f7fb 40%,#e6f0ff 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
        .main{width:100%;max-width:380px;background:#ffffff;border-radius:25px;padding:35px 28px;box-shadow:0 8px 30px rgba(255,107,157,0.25)}
        .logo{text-align:center;margin-bottom:35px}
        .logo-text{font-size:28px;font-weight:700;color:#1f2937;letter-spacing:2px}
        .logo-text span{background:linear-gradient(45deg,#ff73d2,#d868ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .option-btn{display:flex;gap:30px;border-bottom:1px solid #e5e7eb;margin-bottom:25px}
        .login-btn,.sign-btn{border:none;background:none;padding:12px 0;font-size:15px;cursor:pointer;color:#6b7280}
        .active{color:#2196f3;border-bottom:3px solid #2196f3}
        .input-group{margin-bottom:18px}
        .input-group label{display:block;margin-bottom:8px;font-size:14px;color:#374151;font-weight:600}
        .input-group input{width:100%;height:50px;padding:0 15px;border:1px solid #d1d5db;border-radius:8px;outline:none;font-size:15px}
        .input-group input:focus{border-color:#ff6b9d;box-shadow:0 0 0 3px rgba(255,107,157,0.15)}
        .loginButton{width:100%;height:50px;border:none;border-radius:8px;background:linear-gradient(135deg,#2196f3,#7A00FF);color:white;font-size:16px;font-weight:600;cursor:pointer}
        .loginButton:hover{opacity:0.9;transform:scale(1.02)}
        .text{text-align:center;margin-top:25px;color:#6b7280}
        .text a{color:#2196f3;text-decoration:none;font-weight:600}
        .text a:hover{color:#ff6b9d;text-decoration:underline}
        .error-msg{background:#fee2e2;color:#dc2626;padding:10px 14px;border-radius:8px;margin-bottom:15px;font-size:14px;text-align:center}
        .flash-messages{margin-bottom:15px}
        .flash-message{padding:10px 14px;border-radius:8px;margin-bottom:8px;font-size:14px;text-align:center}
        .flash-message.success{background:#d4edda;color:#155724}
        .flash-message.danger{background:#f8d7da;color:#721c24}
        .flash-message.warning{background:#fff3cd;color:#856404}
        @media(max-width:400px){.main{padding:25px 18px}}
    </style>
</head>
<body>
    <div class="main">
        <div class="logo">
            <svg width="80" height="80" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="55" fill="url(#g)"/>
                <path d="M22 75 C35 55, 45 55, 58 75 C71 95, 85 95, 98 75" fill="none" stroke="white" stroke-width="7" stroke-linecap="round"/>
                <path d="M58 35 L85 35 L85 62" fill="none" stroke="white" stroke-width="6" stroke-linecap="round"/>
                <path d="M85 35 L50 70" fill="none" stroke="white" stroke-width="6" stroke-linecap="round"/>
                <defs><linearGradient id="g"><stop offset="0%" stop-color="#2196F3"/><stop offset="100%" stop-color="#7A00FF"/></linearGradient></defs>
            </svg>
            <span class="logo-text"><span>FlowUp</span></span>
        </div>
        <div class="option-btn">
            <button class="login-btn active" onclick="window.location.href='/login'">Sign In</button>
            <button class="sign-btn" onclick="window.location.href='/register'">Sign Up</button>
        </div>
        <div class="flash-messages">
            {% for category, message in flashes %}
            <div class="flash-message {{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter username" required />
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password" required />
            </div>
            <button type="submit" class="loginButton">Login</button>
        </form>
        <div class="text">Don't have an account? <a href="/register">Sign Up</a></div>
    </div>
</body>
</html>
'''
REGISTER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlowUp – Sign Up</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:Arial,sans-serif}
        body{background:radial-gradient(circle at 0% 0%,#ffb6c9 0%,#f5f7fb 40%,#e6f0ff 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
        .main{width:100%;max-width:380px;background:#ffffff;border-radius:25px;padding:35px 28px;box-shadow:0 8px 30px rgba(255,107,157,0.25)}
        .logo{text-align:center;margin-bottom:35px}
        .logo-text{font-size:28px;font-weight:700;color:#1f2937;letter-spacing:2px}
        .logo-text span{background:linear-gradient(45deg,#ff73d2,#d868ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .option-btn{display:flex;gap:30px;border-bottom:1px solid #e5e7eb;margin-bottom:25px}
        .login-btn,.sign-btn{border:none;background:none;padding:12px 0;font-size:15px;cursor:pointer;color:#6b7280}
        .active{color:#2196f3;border-bottom:3px solid #2196f3}
        .input-group{margin-bottom:18px}
        .input-group label{display:block;margin-bottom:8px;font-size:14px;color:#374151;font-weight:600}
        .input-group input{width:100%;height:50px;padding:0 15px;border:1px solid #d1d5db;border-radius:8px;outline:none;font-size:15px}
        .input-group input:focus{border-color:#ff6b9d;box-shadow:0 0 0 3px rgba(255,107,157,0.15)}
        .loginButton{width:100%;height:50px;border:none;border-radius:8px;background:linear-gradient(135deg,#2196f3,#7A00FF);color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:5px}
        .loginButton:hover{opacity:0.9;transform:scale(1.02)}
        .text{text-align:center;margin-top:25px;color:#6b7280}
        .text a{color:#2196f3;text-decoration:none;font-weight:600}
        .text a:hover{color:#ff6b9d;text-decoration:underline}
        .error-msg{background:#fee2e2;color:#dc2626;padding:10px 14px;border-radius:8px;margin-bottom:15px;font-size:14px;text-align:center}
        .flash-messages{margin-bottom:15px}
        .flash-message{padding:10px 14px;border-radius:8px;margin-bottom:8px;font-size:14px;text-align:center}
        .flash-message.success{background:#d4edda;color:#155724}
        .flash-message.danger{background:#f8d7da;color:#721c24}
        .flash-message.warning{background:#fff3cd;color:#856404}
        @media(max-width:400px){.main{padding:25px 18px}}
    </style>
</head>
<body>
    <div class="main">
        <div class="logo">
            <svg width="80" height="80" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="55" fill="url(#g)"/>
                <path d="M22 75 C35 55, 45 55, 58 75 C71 95, 85 95, 98 75" fill="none" stroke="white" stroke-width="7" stroke-linecap="round"/>
                <path d="M58 35 L85 35 L85 62" fill="none" stroke="white" stroke-width="6" stroke-linecap="round"/>
                <path d="M85 35 L50 70" fill="none" stroke="white" stroke-width="6" stroke-linecap="round"/>
                <defs><linearGradient id="g"><stop offset="0%" stop-color="#2196F3"/><stop offset="100%" stop-color="#7A00FF"/></linearGradient></defs>
            </svg>
            <span class="logo-text"><span>FlowUp</span></span>
        </div>
        <div class="option-btn">
            <button class="login-btn" onclick="window.location.href='/login'">Sign In</button>
            <button class="sign-btn active" onclick="window.location.href='/register'">Sign Up</button>
        </div>
        <div class="flash-messages">
            {% for category, message in flashes %}
            <div class="flash-message {{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="input-group">
                <label>Full Name</label>
                <input type="text" name="full_name" placeholder="Enter your name" />
            </div>
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Choose a username" required />
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Create password" required />
            </div>
            <div class="input-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" placeholder="Confirm password" required />
            </div>
            <button type="submit" class="loginButton">Join Now</button>
        </form>
        <div class="text">Already have an account? <a href="/login">Login</a></div>
    </div>
</body>
</html>
'''
EDIT_PROFILE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Profile - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
        body{max-width:430px;margin:auto;padding:20px;background:#fafafa;min-height:100vh}
        .header{background:white;padding:14px 20px;border-bottom:1px solid #f0f0f0;margin:-20px -20px 20px -20px;display:flex;align-items:center;gap:15px}
        .header h2{font-size:22px;flex:1}
        .header a{color:#262626;font-size:22px;text-decoration:none}
        .card{background:white;padding:30px;border-radius:16px;box-shadow:0 2px 10px rgba(0,0,0,0.08)}
        .form-group{margin-bottom:20px}
        label{display:block;font-weight:600;margin-bottom:8px;color:#262626;font-size:14px}
        input[type="file"]{width:100%;padding:12px;border:2px dashed #ddd;border-radius:12px;cursor:pointer;background:#fafafa}
        input[type="file"]:hover{border-color:#d868ff;background:#f5f5f5}
        input[type="text"],textarea{width:100%;padding:12px;border:1px solid #ddd;border-radius:12px;font-family:inherit;font-size:14px;background:#fff}
        textarea{min-height:80px;resize:vertical}
        input[type="text"]:focus,textarea:focus{outline:none;border-color:#d868ff;box-shadow:0 0 0 3px rgba(216,104,255,0.1)}
        .dp-section{display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:15px;background:#f8f8f8;border-radius:12px}
        .dp-section .current-dp{width:80px;height:80px;border-radius:50%;object-fit:cover;border:3px solid #d868ff;background:#f0f0f0}
        .dp-section .current-dp.error{background:#f0f0f0;padding:15px;object-fit:contain}
        .btn{background:linear-gradient(135deg,#d868ff,#ff73d2);color:white;border:none;padding:12px 40px;border-radius:25px;font-size:16px;cursor:pointer;width:100%;font-weight:600;transition:all 0.3s}
        .btn:hover{opacity:0.9;transform:scale(1.02)}
        .btn:active{transform:scale(0.95)}
        .flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}
        .flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center;animation:slideDown 0.3s ease}
        .flash-message.success{background:#28a745}
        .flash-message.danger{background:#dc3545}
        .flash-message.warning{background:#ffc107;color:#333}
        @keyframes slideDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
        .file-info{font-size:12px;color:#888;margin-top:4px}
        .file-info i{margin-right:4px}
        .preview-container{margin-top:10px;display:none}
        .preview-container img{max-width:100px;max-height:100px;border-radius:8px;border:2px solid #d868ff}
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="header">
        <a href="{{ url_for('profile', username=user.username) }}"><i class="fa-solid fa-arrow-left"></i></a>
        <h2>Edit Profile</h2>
    </div>
    <div class="card">
        <form method="POST" enctype="multipart/form-data" id="editProfileForm">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            
            <div class="dp-section">
                <img src="/static/uploads/{{ profile_pic }}" 
                     alt="Profile" 
                     class="current-dp" 
                     id="profilePreview"
                     onerror="this.src='/static/default.svg'; this.classList.add('error')">
                <div>
                    <h4>Profile Photo</h4>
                    <p style="color:#888;font-size:12px;">Click below to change</p>
                </div>
            </div>
            
            <div class="form-group">
                <label>Change Profile Photo</label>
                <input type="file" name="profile_pic" id="profilePicInput" accept="image/png,image/jpeg,image/jpg,image/gif,image/webp">
                <div class="file-info" id="fileInfo">
                    <i class="fa-regular fa-circle-info"></i> Supported: JPG, PNG, GIF, WebP (Max: 5MB)
                </div>
                <div class="preview-container" id="previewContainer">
                    <img id="imagePreview" src="#" alt="Preview">
                </div>
            </div>
            
            <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="full_name" value="{{ user.full_name|e or '' }}" placeholder="Enter your full name">
            </div>
            
            <div class="form-group">
                <label>Bio</label>
                <textarea name="bio" placeholder="Tell us about yourself..." maxlength="150">{{ user.bio|e or '' }}</textarea>
                <div style="text-align:right;font-size:12px;color:#888;margin-top:4px;">
                    <span id="bioCount">0</span>/150
                </div>
            </div>
            
            <button type="submit" class="btn" id="submitBtn">
                <i class="fa-regular fa-floppy-disk"></i> Save Changes
            </button>
        </form>
    </div>
    
    <script>
        var bioTextarea = document.querySelector('textarea[name="bio"]');
        var bioCount = document.getElementById('bioCount');
        if (bioTextarea && bioCount) {
            bioCount.textContent = bioTextarea.value.length;
            bioTextarea.addEventListener('input', function() {
                bioCount.textContent = this.value.length;
                if (this.value.length > 150) {
                    this.style.borderColor = '#dc3545';
                    bioCount.style.color = '#dc3545';
                } else {
                    this.style.borderColor = '';
                    bioCount.style.color = '#888';
                }
            });
        }
        
        var profilePicInput = document.getElementById('profilePicInput');
        var previewContainer = document.getElementById('previewContainer');
        var imagePreview = document.getElementById('imagePreview');
        if (profilePicInput) {
            profilePicInput.addEventListener('change', function(e) {
                var file = this.files[0];
                if (file) {
                    var reader = new FileReader();
                    reader.onload = function(e) {
                        previewContainer.style.display = 'block';
                        imagePreview.src = e.target.result;
                    };
                    reader.readAsDataURL(file);
                    var fileInfo = document.getElementById('fileInfo');
                    var sizeMB = (file.size / (1024 * 1024)).toFixed(2);
                    fileInfo.innerHTML = '<i class="fa-regular fa-check-circle" style="color:#28a745;"></i> Selected: ' + 
                                         file.name + ' (' + sizeMB + ' MB)';
                    if (file.size > 5 * 1024 * 1024) {
                        fileInfo.innerHTML = '<i class="fa-regular fa-circle-exclamation" style="color:#dc3545;"></i> ' +
                                             'File too large! Maximum 5MB.';
                        fileInfo.style.color = '#dc3545';
                        profilePicInput.value = '';
                        previewContainer.style.display = 'none';
                    } else {
                        fileInfo.style.color = '#28a745';
                    }
                } else {
                    previewContainer.style.display = 'none';
                    document.getElementById('fileInfo').innerHTML = '<i class="fa-regular fa-circle-info"></i> Supported: JPG, PNG, GIF, WebP (Max: 5MB)';
                    document.getElementById('fileInfo').style.color = '#888';
                }
            });
        }
        
        document.getElementById('editProfileForm').addEventListener('submit', function() {
            var btn = document.getElementById('submitBtn');
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
            btn.disabled = true;
        });
        
        setTimeout(function() {
            document.querySelectorAll('.flash-message').forEach(function(el) {
                el.style.transition = 'opacity 0.5s';
                el.style.opacity = '0';
                setTimeout(function() { el.remove(); }, 500);
            });
        }, 4000);
    </script>
</body>
</html>
'''
NOTIFICATIONS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
        body{max-width:430px;margin:auto;background:#000;min-height:100vh;color:#fff}
        .header{background:#000;padding:14px 20px;border-bottom:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;gap:15px}
        .header h2{font-size:22px;flex:1;color:#fff}
        .header a{color:#fff;font-size:22px;text-decoration:none}
        .notif-item{display:flex;align-items:center;gap:12px;padding:12px 16px;background:rgba(255,255,255,0.03);border-bottom:1px solid rgba(255,255,255,0.04);text-decoration:none;color:#fff}
        .notif-item:hover{background:rgba(255,255,255,0.06)}
        .notif-item img{width:40px;height:40px;border-radius:50%;object-fit:cover}
        .notif-item .content{flex:1}
        .notif-item .content .text{font-size:14px}
        .notif-item .content .text strong{color:#fff}
        .notif-item .content .time{font-size:12px;color:rgba(255,255,255,0.3);margin-top:2px}
        .empty{text-align:center;padding:60px 20px;color:rgba(255,255,255,0.3)}
        .empty i{font-size:48px;display:block;margin-bottom:16px;color:rgba(255,255,255,0.1)}
        .flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}
        .flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center}
        .flash-message.success{background:#28a745}
        .flash-message.danger{background:#dc3545}
        .flash-message.warning{background:#ffc107;color:#333}
        .bottom-nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:430px;height:65px;background:linear-gradient(45deg,#ff73d2,#d868ff);display:flex;justify-content:space-around;align-items:center;border-radius:25px 25px 0 0;padding:0 12px;z-index:50}
        .bottom-nav a{display:flex;align-items:center;justify-content:center;text-decoration:none;color:white;opacity:0.85;font-size:24px;transition:opacity 0.2s}
        .bottom-nav a.active{opacity:1}
        .bottom-nav a:hover{opacity:1}
        .plus-btn{width:58px;height:58px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;margin-top:-28px;text-decoration:none;box-shadow:0 4px 15px rgba(0,0,0,0.3)}
        .plus-btn:hover{transform:scale(1.1)}
        .plus-btn i{color:#000;font-size:30px}
        .bottom-spacer{height:65px}
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="header">
        <a href="/feed"><i class="fa-solid fa-arrow-left"></i></a>
        <h2>Notifications</h2>
    </div>
    {% if notifs %}
        {% for n in notifs %}
        <a href="{{ n.link or '#' }}" class="notif-item">
            <img src="/static/uploads/{{ n.profile_pic }}" onerror="this.src='/static/default.svg'">
            <div class="content">
                <div class="text"><strong>{{ n.username|e }}</strong> {{ n.message|e }}</div>
                <div class="time">{{ n.created_at }}</div>
            </div>
        </a>
        {% endfor %}
    {% else %}
        <div class="empty"><i class="fa-regular fa-bell-slash"></i><p>No notifications yet</p></div>
    {% endif %}
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}" class="active"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=current_user.username) }}"><i class="fa-regular fa-user"></i></a>
    </div>
    <script>
        setTimeout(function(){document.querySelectorAll('.flash-message').forEach(function(el){el.style.opacity='0';setTimeout(function(){el.remove()},500)})},4000);
    </script>
</body>
</html>
'''
SEARCH_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
        body{background:#000;max-width:430px;margin:auto;min-height:100vh;color:#fff}
        .search-header{background:#000;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:10}
        .search-header a{color:#fff;font-size:22px;text-decoration:none}
        .search-input-wrapper{flex:1;display:flex;align-items:center;background:rgba(255,255,255,0.08);border-radius:12px;padding:0 12px}
        .search-input-wrapper i{color:rgba(255,255,255,0.3);font-size:16px;margin-right:8px}
        .search-input-wrapper input{flex:1;border:none;background:transparent;padding:10px 0;font-size:16px;outline:none;color:#fff}
        .search-input-wrapper input::placeholder{color:rgba(255,255,255,0.3)}
        .results-container{padding:0 16px;margin-top:8px}
        .user-result{display:flex;align-items:center;gap:14px;padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
        .user-result img{width:50px;height:50px;border-radius:50%;object-fit:cover}
        .user-result .info{flex:1}
        .user-result .info .name{font-weight:600;font-size:15px;color:#fff}
        .user-result .info .username{font-size:13px;color:rgba(255,255,255,0.4)}
        .user-result a{background:#d868ff;color:white;border:none;padding:6px 16px;border-radius:20px;text-decoration:none;font-size:13px;font-weight:600}
        .no-results{text-align:center;padding:40px 20px;color:rgba(255,255,255,0.3)}
        .empty-state{text-align:center;padding:60px 20px;color:rgba(255,255,255,0.3)}
        .empty-state i{font-size:64px;display:block;margin-bottom:16px;color:rgba(255,255,255,0.05)}
        .flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}
        .flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center}
        .flash-message.success{background:#28a745}
        .flash-message.danger{background:#dc3545}
        .flash-message.warning{background:#ffc107;color:#333}
        .bottom-nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:430px;height:65px;background:linear-gradient(45deg,#ff73d2,#d868ff);display:flex;justify-content:space-around;align-items:center;border-radius:25px 25px 0 0;padding:0 12px;z-index:50}
        .bottom-nav a{display:flex;align-items:center;justify-content:center;text-decoration:none;color:white;opacity:0.85;font-size:24px}
        .bottom-nav a.active{opacity:1}
        .bottom-nav a:hover{opacity:1}
        .plus-btn{width:58px;height:58px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;margin-top:-28px;text-decoration:none;box-shadow:0 4px 15px rgba(0,0,0,0.3)}
        .plus-btn:hover{transform:scale(1.1)}
        .plus-btn i{color:#000;font-size:30px}
        .bottom-spacer{height:65px}
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    <div class="search-header">
        <a href="/feed"><i class="fa-solid fa-arrow-left"></i></a>
        <div class="search-input-wrapper">
            <i class="fa-solid fa-magnifying-glass"></i>
            <input type="text" id="searchInput" placeholder="Search users...">
        </div>
    </div>
    <div class="results-container" id="resultsContainer">
        <div class="empty-state">
            <i class="fa-regular fa-magnifying-glass"></i>
            <h3>Search for users</h3>
            <p style="color:rgba(255,255,255,0.2);">Find people to follow</p>
        </div>
        <div id="searchResults"></div>
    </div>
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=current_user.username) }}"><i class="fa-regular fa-user"></i></a>
    </div>
    <script>
        var searchInput=document.getElementById('searchInput'),searchResults=document.getElementById('searchResults'),emptyState=document.querySelector('.empty-state');
        var debounceTimer;
        function getCsrfToken(){return document.getElementById('csrf_token').value}
        searchInput.addEventListener('input',function(){var q=this.value.trim();if(q.length>0){emptyState.style.display='none'}else{emptyState.style.display='block';searchResults.innerHTML='';return}clearTimeout(debounceTimer);debounceTimer=setTimeout(function(){performSearch(q)},300)});
        function performSearch(q){if(q.length===0)return;searchResults.innerHTML='<div style="text-align:center;padding:20px;color:rgba(255,255,255,0.3);">Searching...</div>';fetch('/api/search?q='+encodeURIComponent(q)).then(function(r){return r.json()}).then(function(data){if(data.length===0){searchResults.innerHTML='<div class="no-results">No users found</div>'}else{var html='';data.forEach(function(u){html+='<div class="user-result"><img src="/static/uploads/'+u.profile_pic+'" alt="'+u.username+'" onerror="this.src='+"'/static/default.svg'"+'"><div class="info"><div class="name">'+(u.full_name||u.username)+'</div><div class="username">@'+u.username+'</div></div><a href="/profile/'+u.username+'">View</a></div>'});searchResults.innerHTML=html}}).catch(function(){searchResults.innerHTML='<div class="no-results">Error searching</div>'})}
        setTimeout(function(){document.querySelectorAll('.flash-message').forEach(function(el){el.style.opacity='0';setTimeout(function(){el.remove()},500)})},4000);
    </script>
</body>
</html>
'''

HISTORY_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activity History - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { max-width:430px; margin:auto; background:#000; min-height:100vh; color:#fff; }
        .header { background:#000; padding:14px 20px; border-bottom:1px solid rgba(255,255,255,0.08); display:flex; align-items:center; gap:15px; position:sticky; top:0; z-index:10; }
        .header h2 { font-size:22px; flex:1; color:#fff; }
        .header a { color:#fff; font-size:22px; text-decoration:none; }
        .filter-tabs { display:flex; gap:8px; padding:12px 16px; overflow-x:auto; background:#000; border-bottom:1px solid rgba(255,255,255,0.04); scrollbar-width:none; }
        .filter-tabs::-webkit-scrollbar { display:none; }
        .filter-tabs button { padding:6px 16px; border-radius:20px; border:1px solid rgba(255,255,255,0.08); background:rgba(255,255,255,0.03); color:rgba(255,255,255,0.5); font-size:13px; cursor:pointer; white-space:nowrap; transition:all 0.3s; }
        .filter-tabs button.active { background:#d868ff; color:white; border-color:#d868ff; }
        .filter-tabs button:hover { background:rgba(255,255,255,0.05); }
        .filter-tabs button.active:hover { background:#c858e8; }
        .history-container { padding:12px 16px; }
        .activity-item { display:flex; align-items:center; gap:14px; padding:12px 16px; background:rgba(255,255,255,0.02); border-radius:12px; margin-bottom:8px; border-bottom:1px solid rgba(255,255,255,0.04); }
        .activity-icon { width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:18px; flex-shrink:0; }
        .activity-icon.like { background:rgba(237,73,86,0.15); color:#ed4956; }
        .activity-icon.comment { background:rgba(0,188,212,0.15); color:#00bcd4; }
        .activity-icon.post { background:rgba(216,104,255,0.15); color:#d868ff; }
        .activity-icon.follow { background:rgba(76,175,80,0.15); color:#4caf50; }
        .activity-icon.login { background:rgba(33,150,243,0.15); color:#2196f3; }
        .activity-icon.save { background:rgba(255,152,0,0.15); color:#ff9800; }
        .activity-icon.story { background:rgba(233,30,99,0.15); color:#e91e63; }
        .activity-icon.reel { background:rgba(63,81,181,0.15); color:#3f51b5; }
        .activity-content { flex:1; }
        .activity-content .text { font-size:14px; color:rgba(255,255,255,0.8); }
        .activity-content .text strong { color:#fff; }
        .activity-content .time { font-size:12px; color:rgba(255,255,255,0.3); margin-top:2px; display:block; }
        .empty-state { text-align:center; padding:60px 20px; color:rgba(255,255,255,0.3); }
        .empty-state i { font-size:48px; display:block; margin-bottom:16px; color:rgba(255,255,255,0.05); }
        .saved-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:4px; margin-top:4px; display:none; }
        .saved-grid.active { display:grid; }
        .saved-item { aspect-ratio:1/1; overflow:hidden; border-radius:4px; background:#111; position:relative; cursor:pointer; }
        .saved-item img, .saved-item video { width:100%; height:100%; object-fit:cover; }
        .saved-item .overlay { position:absolute; bottom:0; left:0; right:0; padding:20px 8px 8px; background:linear-gradient(0deg,rgba(0,0,0,0.7) 0%,transparent 100%); opacity:0; transition:opacity 0.3s; }
        .saved-item:hover .overlay { opacity:1; }
        .saved-item .overlay .stats { color:#fff; font-size:11px; display:flex; gap:12px; justify-content:center; }
        .saved-item .overlay .stats i { margin-right:3px; }
        .flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}
        .flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center}
        .flash-message.success{background:#28a745}
        .flash-message.danger{background:#dc3545}
        .flash-message.warning{background:#ffc107;color:#333}
        .bottom-nav { position:fixed; bottom:0; left:50%; transform:translateX(-50%); width:100%; max-width:430px; height:65px; background:linear-gradient(45deg,#ff73d2,#d868ff); display:flex; justify-content:space-around; align-items:center; border-radius:25px 25px 0 0; padding:0 12px; z-index:50; }
        .bottom-nav a { display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; opacity:0.85; font-size:24px; transition:opacity 0.2s; }
        .bottom-nav a.active { opacity:1; }
        .bottom-nav a:hover { opacity:1; }
        .plus-btn { width:58px; height:58px; border-radius:50%; background:#fff; display:flex; align-items:center; justify-content:center; margin-top:-28px; text-decoration:none; box-shadow:0 4px 15px rgba(0,0,0,0.3); }
        .plus-btn:hover { transform:scale(1.1); }
        .plus-btn i { color:#000; font-size:30px; }
        .bottom-spacer { height:65px; }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="header">
        <a href="{{ url_for('profile', username=user.username) }}"><i class="fa-solid fa-arrow-left"></i></a>
        <h2><i class="fa-regular fa-clock"></i> Activity History</h2>
    </div>
    <div class="filter-tabs">
        <button class="active" data-filter="all" onclick="filterActivities('all', this)">All</button>
        <button data-filter="like" onclick="filterActivities('like', this)"><i class="fa-regular fa-heart"></i> Likes</button>
        <button data-filter="comment" onclick="filterActivities('comment', this)"><i class="fa-regular fa-comment"></i> Comments</button>
        <button data-filter="post" onclick="filterActivities('post', this)"><i class="fa-regular fa-image"></i> Posts</button>
        <button data-filter="follow" onclick="filterActivities('follow', this)"><i class="fa-regular fa-user-plus"></i> Follows</button>
        <button data-filter="save" onclick="filterActivities('save', this)"><i class="fa-regular fa-bookmark"></i> Saves</button>
    </div>
    <div class="history-container" id="historyContainer">
        <!-- Activities -->
        <div id="activitiesContainer">
            {% if activities %}
                {% for act in activities %}
                <div class="activity-item" data-type="{{ act.type }}">
                    <div class="activity-icon {{ act.type }}">
                        {% if act.type == 'like' %}<i class="fa-regular fa-heart"></i>
                        {% elif act.type == 'comment' %}<i class="fa-regular fa-comment"></i>
                        {% elif act.type == 'post' %}<i class="fa-regular fa-image"></i>
                        {% elif act.type == 'follow' %}<i class="fa-regular fa-user-plus"></i>
                        {% elif act.type == 'login' %}<i class="fa-regular fa-right-to-bracket"></i>
                        {% elif act.type == 'save' %}<i class="fa-regular fa-bookmark"></i>
                        {% elif act.type == 'story' %}<i class="fa-regular fa-circle-play"></i>
                        {% elif act.type == 'reel' %}<i class="fa-regular fa-video"></i>
                        {% else %}<i class="fa-regular fa-circle"></i>{% endif %}
                    </div>
                    <div class="activity-content">
                        <div class="text">
                            {% if act.type == 'like' %}You liked a <strong>post</strong>
                            {% elif act.type == 'comment' %}You commented on a <strong>post</strong>
                                {% if act.metadata and act.metadata.comment_text %}
                                    <span style="color:rgba(255,255,255,0.3);font-size:12px;display:block;">"{{ act.metadata.comment_text|e }}"</span>
                                {% endif %}
                            {% elif act.type == 'post' %}You created a <strong>post</strong>
                                {% if act.metadata and act.metadata.caption %}
                                    <span style="color:rgba(255,255,255,0.3);font-size:12px;display:block;">"{{ act.metadata.caption|e }}"</span>
                                {% endif %}
                            {% elif act.type == 'follow' %}You followed someone
                            {% elif act.type == 'login' %}You logged in
                            {% elif act.type == 'save' %}You saved a <strong>post</strong>
                            {% elif act.type == 'story' %}You posted a <strong>story</strong>
                            {% elif act.type == 'reel' %}You posted a <strong>reel</strong>
                                {% if act.metadata and act.metadata.caption %}
                                    <span style="color:rgba(255,255,255,0.3);font-size:12px;display:block;">"{{ act.metadata.caption|e }}"</span>
                                {% endif %}
                            {% else %}{{ act.type }}{% endif %}
                        </div>
                        <span class="time">{{ act.created_at }}</span>
                    </div>
                </div>
                {% endfor %}
            {% else %}
                <div class="empty-state" style="display:block;padding:60px 20px;color:rgba(255,255,255,0.3);text-align:center;grid-column:1/4;">
                    <i class="fa-regular fa-clock"></i>
                    <h3>No activity yet</h3>
                    <p style="color:rgba(255,255,255,0.2);">Your activity will appear here</p>
                </div>
            {% endif %}
        </div>
        
        <!-- Saved Posts Grid -->
        <div id="savedContainer" style="display:none;">
            <div class="saved-grid active" id="savedGrid">
                {% if saved_posts %}
                    {% for post in saved_posts %}
                    <a href="{{ url_for('view_post', post_id=post.post_id) }}" class="saved-item">
                        {% if post.media_type == 'video' %}
                            <video src="/{{ post.media_url }}" muted preload="metadata"></video>
                        {% else %}
                            <img src="/{{ post.media_url }}" loading="lazy" onerror="this.src='/static/default_post.svg'">
                        {% endif %}
                        <div class="overlay">
                            <div class="stats">
                                <span><i class="fa-regular fa-heart"></i> {{ post.like_count }}</span>
                                <span><i class="fa-regular fa-comment"></i> {{ post.comment_count }}</span>
                            </div>
                        </div>
                    </a>
                    {% endfor %}
                {% else %}
                    <div class="empty-state">
                        <i class="fa-regular fa-bookmark"></i>
                        <h3>No saved posts</h3>
                        <p style="color:rgba(255,255,255,0.2);">Save posts you love to see them here</p>
                    </div>
                {% endif %}
            </div>
            
            <!-- Saved Reels -->
            <div class="saved-grid active" style="margin-top:12px;">
                {% if saved_reels %}
                    {% for reel in saved_reels %}
                    <a href="{{ url_for('view_reel', reel_id=reel.reel_id) }}" class="saved-item">
                        <video src="/{{ reel.media_url }}" muted preload="metadata"></video>
                        <div class="overlay">
                            <div class="stats">
                                <span><i class="fa-regular fa-heart"></i> {{ reel.like_count }}</span>
                            </div>
                        </div>
                    </a>
                    {% endfor %}
                {% else %}
                    <div class="empty-state">
                        <i class="fa-regular fa-bookmark"></i>
                        <h3>No saved reels</h3>
                        <p style="color:rgba(255,255,255,0.2);">Save reels you enjoy to see them here</p>
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=user.username) }}" class="active"><i class="fa-regular fa-user"></i></a>
    </div>
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    <script>
        function getCsrfToken() { return document.getElementById('csrf_token').value; }
        function filterActivities(type, btn) {
            document.querySelectorAll('.filter-tabs button').forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
            var activitiesContainer = document.getElementById('activitiesContainer');
            var savedContainer = document.getElementById('savedContainer');
            if (type === 'save') {
                activitiesContainer.style.display = 'none';
                savedContainer.style.display = 'block';
            } else {
                activitiesContainer.style.display = 'block';
                savedContainer.style.display = 'none';
                var items = document.querySelectorAll('.activity-item');
                var visible = 0;
                items.forEach(function(item) {
                    if (type === 'all' || item.dataset.type === type) {
                        item.style.display = 'flex';
                        visible++;
                    } else {
                        item.style.display = 'none';
                    }
                });
                var emptyState = document.querySelector('#activitiesContainer .empty-state');
                if (visible === 0) {
                    if (!emptyState) {
                        var container = document.getElementById('activitiesContainer');
                        var empty = document.createElement('div');
                        empty.className = 'empty-state';
                        empty.style.display = 'block';
                        empty.style.padding = '60px 20px';
                        empty.style.textAlign = 'center';
                        empty.style.color = 'rgba(255,255,255,0.3)';
                        empty.style.gridColumn = '1/4';
                        empty.innerHTML = '<i class="fa-regular fa-filter"></i><h3 style="color:#fff;">No activity of this type</h3><p style="color:rgba(255,255,255,0.2);">Try a different filter</p>';
                        container.appendChild(empty);
                    } else {
                        emptyState.style.display = 'block';
                    }
                } else if (emptyState) {
                    emptyState.style.display = 'none';
                }
            }
        }
        document.querySelectorAll('.activity-item .time').forEach(function(el) {
            var time = new Date(el.textContent);
            var now = new Date();
            var diff = Math.floor((now - time) / 1000);
            if (diff < 60) el.textContent = 'Just now';
            else if (diff < 3600) el.textContent = Math.floor(diff / 60) + ' minutes ago';
            else if (diff < 86400) el.textContent = Math.floor(diff / 3600) + ' hours ago';
            else if (diff < 604800) el.textContent = Math.floor(diff / 86400) + ' days ago';
            else el.textContent = time.toLocaleDateString();
        });
        setTimeout(function(){document.querySelectorAll('.flash-message').forEach(function(el){el.style.opacity='0';setTimeout(function(){el.remove()},500)})},4000);
    </script>
</body>
</html>
'''

CHAT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}body{background:#000;max-width:430px;margin:auto;height:100vh;display:flex;flex-direction:column}.chat-header{background:#000;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.08);display:flex;align-items:center;gap:12px}.chat-header a{color:#fff;font-size:22px;text-decoration:none}.chat-header .user-info{display:flex;align-items:center;gap:10px;flex:1}.chat-header .user-info img{width:32px;height:32px;border-radius:50%;object-fit:cover;border:2px solid #d868ff}.chat-header .user-info .name{color:#fff;font-weight:600;font-size:16px}.chat-header .user-info .status{color:rgba(255,255,255,0.3);font-size:12px}.messages{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:8px}.message{max-width:80%;padding:10px 14px;border-radius:16px;font-size:14px;word-wrap:break-word}.message.sent{background:linear-gradient(45deg,#ff73d2,#d868ff);color:#fff;align-self:flex-end;border-bottom-right-radius:4px}.message.received{background:rgba(255,255,255,0.08);color:#fff;align-self:flex-start;border-bottom-left-radius:4px}.message .time{font-size:10px;opacity:0.5;margin-top:4px;display:block}.message .delete-btn{background:none;border:none;color:rgba(255,255,255,0.3);cursor:pointer;font-size:12px;margin-left:8px}.message .delete-btn:hover{color:#ff4444}.chat-input{display:flex;gap:10px;padding:12px 16px;background:#111;border-top:1px solid rgba(255,255,255,0.06)}.chat-input input{flex:1;padding:10px 16px;border-radius:20px;border:1px solid rgba(255,255,255,0.08);background:rgba(255,255,255,0.04);color:#fff;outline:none;font-size:14px}.chat-input input:focus{border-color:#d868ff}.chat-input input::placeholder{color:rgba(255,255,255,0.3)}.chat-input button{padding:10px 20px;border-radius:20px;border:none;background:linear-gradient(45deg,#ff73d2,#d868ff);color:#fff;font-weight:600;cursor:pointer}.chat-input button:active{transform:scale(0.95)}.typing-indicator{color:rgba(255,255,255,0.3);font-size:12px;padding:4px 16px;font-style:italic;min-height:24px}.clear-chat{background:none;border:none;color:rgba(255,255,255,0.3);font-size:14px;cursor:pointer;padding:4px 8px}.clear-chat:hover{color:#ff4444}.empty-chat{text-align:center;color:rgba(255,255,255,0.3);padding:40px 20px;flex:1;display:flex;flex-direction:column;justify-content:center}.empty-chat i{font-size:48px;color:rgba(255,255,255,0.05);margin-bottom:16px}.flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}.flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center}.flash-message.success{background:#28a745}.flash-message.danger{background:#dc3545}.flash-message.warning{background:#ffc107;color:#333}
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="chat-header">
        <a href="{{ url_for('notifications') }}"><i class="fa-solid fa-arrow-left"></i></a>
        <div class="user-info">
            <img src="/static/uploads/{{ other_user.profile_pic }}" onerror="this.src='/static/default.svg'">
            <div>
                <div class="name">{{ other_user.full_name|e or other_user.username|e }}</div>
                <div class="status" id="userStatus">offline</div>
            </div>
        </div>
        <button class="clear-chat" onclick="clearChat()"><i class="fa-solid fa-trash"></i></button>
    </div>
    <div class="messages" id="messagesContainer">
        {% if messages %}
            {% for msg in messages %}
            <div class="message {% if msg.sender_id == current_user.id %}sent{% else %}received{% endif %}" id="msg-{{ msg.id }}">
                {{ msg.message|e }}
                <span class="time">{{ msg.created_at }}</span>
                {% if msg.sender_id == current_user.id %}
                <button class="delete-btn" onclick="deleteMessage({{ msg.id }})"><i class="fa-solid fa-xmark"></i></button>
                {% endif %}
            </div>
            {% endfor %}
        {% else %}
            <div class="empty-chat">
                <i class="fa-regular fa-comment-dots"></i>
                <p>No messages yet. Say hello!</p>
            </div>
        {% endif %}
    </div>
    <div class="typing-indicator" id="typingIndicator"></div>
    <div class="chat-input">
        <input type="text" id="messageInput" placeholder="Type a message..." onkeypress="if(event.key==='Enter') sendMessage()">
        <button onclick="sendMessage()"><i class="fa-regular fa-paper-plane"></i></button>
    </div>
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    <input type="hidden" id="otherUserId" value="{{ other_user.id }}">
    <script>
        var otherUserId = parseInt(document.getElementById('otherUserId').value);
        var lastMessageId = 0;
        var typingTimeout = null;
        var isTyping = false;
        function getCsrfToken() { return document.getElementById('csrf_token').value; }
        function scrollToBottom() { var container = document.getElementById('messagesContainer'); container.scrollTop = container.scrollHeight; }
        function sendMessage() {
            var input = document.getElementById('messageInput');
            var message = input.value.trim();
            if (!message) return;
            var csrf = getCsrfToken();
            fetch('/api/chat/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
                body: JSON.stringify({ receiver_id: otherUserId, message: message })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    input.value = '';
                    loadMessages();
                } else {
                    alert('Error sending message');
                }
            });
        }
        function loadMessages() {
            fetch('/api/chat/messages/' + otherUserId + '?last_id=' + lastMessageId)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (data.messages && data.messages.length > 0) {
                        var container = document.getElementById('messagesContainer');
                        var empty = container.querySelector('.empty-chat');
                        if (empty) empty.remove();
                        data.messages.forEach(function(msg) {
                            var div = document.createElement('div');
                            div.className = 'message ' + (msg.sender_id === {{ current_user.id }} ? 'sent' : 'received');
                            div.id = 'msg-' + msg.id;
                            var deleteBtn = msg.sender_id === {{ current_user.id }} ?
                                '<button class="delete-btn" onclick="deleteMessage(' + msg.id + ')"><i class="fa-solid fa-xmark"></i></button>' : '';
                            div.innerHTML = msg.message + '<span class="time">' + msg.created_at + '</span>' + deleteBtn;
                            container.appendChild(div);
                            if (msg.id > lastMessageId) lastMessageId = msg.id;
                        });
                        scrollToBottom();
                        fetch('/api/messages/read/' + otherUserId, {
                            method: 'POST',
                            headers: { 'X-CSRFToken': getCsrfToken() }
                        });
                    }
                });
        }
        function deleteMessage(messageId) {
            if (!confirm('Delete this message?')) return;
            var csrf = getCsrfToken();
            fetch('/api/chat/clear/' + otherUserId, {
                method: 'DELETE',
                headers: { 'X-CSRFToken': csrf }
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    document.getElementById('msg-' + messageId).remove();
                }
            });
        }
        function clearChat() {
            if (!confirm('Clear all messages?')) return;
            var csrf = getCsrfToken();
            fetch('/api/chat/clear/' + otherUserId, {
                method: 'DELETE',
                headers: { 'X-CSRFToken': csrf }
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    document.getElementById('messagesContainer').innerHTML =
                        '<div class="empty-chat"><i class="fa-regular fa-comment-dots"></i><p>No messages yet. Say hello!</p></div>';
                    lastMessageId = 0;
                }
            });
        }
        var typingTimer;

function updateTyping() {

    clearTimeout(typingTimer);

    typingTimer = setTimeout(function(){

        fetch('/api/typing', {
            method:'POST',
            headers:{
                'Content-Type':'application/json'
            },
            body: JSON.stringify({
                receiver_id: otherUserId,
                is_typing: true
            })
        });

    }, 800);

}
        function checkTyping() {
            fetch('/api/typing/' + otherUserId)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var indicator = document.getElementById('typingIndicator');
                    if (data.is_typing) {
                        indicator.textContent = 'typing...';
                    } else {
                        indicator.textContent = '';
                    }
                });
        }
        function updateStatus() {
            fetch('/api/user/status/' + otherUserId)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var statusEl = document.getElementById('userStatus');
                    if (data.status === 'online') {
                        statusEl.textContent = '● Online';
                        statusEl.style.color = '#2ecc71';
                    } else {
                        statusEl.textContent = '○ Offline';
                        statusEl.style.color = 'rgba(255,255,255,0.3)';
                    }
                });
        }
        document.getElementById('messageInput').addEventListener('input', updateTyping);

setInterval(loadMessages, 5000);   // ilikuwa 2000
setInterval(checkTyping, 5000);    // ilikuwa 3000
setInterval(updateStatus, 15000);  // ilikuwa 5000

setTimeout(function() {
    loadMessages();
    updateStatus();
}, 500);

scrollToBottom();

setTimeout(function(){
    document.querySelectorAll('.flash-message').forEach(function(el){
        el.style.opacity='0';
        setTimeout(function(){
            el.remove()
        },500)
    })
},4000);
    </script>
</body>
</html>
'''
SETTINGS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Settings - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { max-width:430px; margin:auto; background:#000; min-height:100vh; color:#fff; padding-bottom:80px; }
        .header { background:#000; padding:14px 16px; border-bottom:1px solid rgba(255,255,255,0.08); display:flex; align-items:center; gap:12px; position:sticky; top:0; z-index:10; }
        .header .back-btn { color:#fff; font-size:22px; text-decoration:none; width:36px; height:36px; display:flex; align-items:center; justify-content:center; border-radius:50%; transition:background 0.2s; }
        .header .back-btn:hover { background:rgba(255,255,255,0.08); }
        .header .back-btn:active { transform:scale(0.9); }
        .header h1 { font-size:18px; font-weight:700; flex:1; color:#fff; }
        .settings-container { padding:8px 0; }
        .settings-section { margin:4px 12px; border-radius:14px; overflow:hidden; border:1px solid rgba(255,255,255,0.06); }
        .settings-item { display:flex; align-items:center; gap:14px; padding:14px 16px; background:rgba(255,255,255,0.03); border-bottom:1px solid rgba(255,255,255,0.04); cursor:pointer; transition:all 0.2s; text-decoration:none; color:#fff; }
        .settings-item:last-child { border-bottom:none; }
        .settings-item:hover { background:rgba(255,255,255,0.06); }
        .settings-item:active { transform:scale(0.98); }
        .settings-item .icon { width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:16px; flex-shrink:0; }
        .settings-item .icon.purple { background:rgba(216,104,255,0.15); color:#d868ff; }
        .settings-item .icon.blue { background:rgba(52,152,219,0.15); color:#3498db; }
        .settings-item .icon.green { background:rgba(46,204,113,0.15); color:#2ecc71; }
        .settings-item .icon.orange { background:rgba(243,156,18,0.15); color:#f39c12; }
        .settings-item .icon.red { background:rgba(231,76,60,0.15); color:#e74c3c; }
        .settings-item .icon.pink { background:rgba(232,67,147,0.15); color:#e84393; }
        .settings-item .icon.teal { background:rgba(26,188,156,0.15); color:#1abc9c; }
        .settings-item .info { flex:1; }
        .settings-item .info .title { font-size:14px; font-weight:500; color:#fff; }
        .settings-item .info .desc { font-size:12px; color:rgba(255,255,255,0.3); margin-top:1px; }
        .settings-item .arrow { color:rgba(255,255,255,0.15); font-size:14px; }
        .settings-item.logout { border-color:rgba(255,0,0,0.1); background:rgba(255,0,0,0.03); }
        .settings-item.logout:hover { background:rgba(255,0,0,0.06); }
        .settings-item.logout .info .title { color:#ed4956; }
        .settings-item.logout .icon { background:rgba(237,73,86,0.15); color:#ed4956; }
        .section-title { font-size:11px; font-weight:600; color:rgba(255,255,255,0.3); padding:12px 16px 6px; text-transform:uppercase; letter-spacing:0.5px; }
        .flash-messages { position:fixed; top:60px; left:50%; transform:translateX(-50%); z-index:999; width:90%; max-width:400px; }
        .flash-message { padding:10px 16px; border-radius:10px; margin-bottom:6px; color:#fff; font-weight:500; text-align:center; animation:slideDown 0.3s ease; }
        .flash-message.success { background:#28a745; }
        .flash-message.danger { background:#dc3545; }
        .flash-message.warning { background:#ffc107; color:#333; }
        @keyframes slideDown { from { opacity:0; transform:translateY(-20px); } to { opacity:1; transform:translateY(0); } }
        .bottom-nav { position:fixed; bottom:0; left:50%; transform:translateX(-50%); width:100%; max-width:430px; height:65px; background:linear-gradient(45deg,#ff73d2,#d868ff); display:flex; justify-content:space-around; align-items:center; border-radius:25px 25px 0 0; padding:0 12px; z-index:50; }
        .bottom-nav a { display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; opacity:0.7; font-size:24px; transition:all 0.2s; }
        .bottom-nav a.active { opacity:1; }
        .bottom-nav a:hover { opacity:1; }
        .plus-btn { width:58px; height:58px; border-radius:50%; background:#fff; display:flex; align-items:center; justify-content:center; margin-top:-28px; text-decoration:none; box-shadow:0 4px 15px rgba(0,0,0,0.3); transition:transform 0.3s ease; }
        .plus-btn:hover { transform:scale(1.1); }
        .plus-btn i { color:#000; font-size:30px; }
        .bottom-spacer { height:65px; }
        @media (max-width:430px) { .header { padding:12px 14px; } .header h1 { font-size:16px; } .settings-item { padding:12px 14px; } .settings-item .icon { width:28px; height:28px; font-size:14px; } .settings-item .info .title { font-size:13px; } }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="header">
        <a href="{{ url_for('feed') }}" class="back-btn"><i class="fa-solid fa-chevron-left"></i></a>
        <h1>Settings</h1>
    </div>
    <div class="settings-container">
        <div class="section-title">Account</div>
        <div class="settings-section">
            <a href="{{ url_for('edit_profile') }}" class="settings-item">
                <div class="icon purple"><i class="fa-regular fa-user"></i></div>
                <div class="info"><div class="title">Profile</div><div class="desc">Edit your profile information</div></div>
                <span class="arrow"><i class="fa-solid fa-chevron-right"></i></span>
            </a>
            <a href="{{ url_for('notifications') }}" class="settings-item">
                <div class="icon blue"><i class="fa-regular fa-bell"></i></div>
                <div class="info"><div class="title">Notifications</div><div class="desc">Manage notification settings</div></div>
                <span class="arrow"><i class="fa-solid fa-chevron-right"></i></span>
            </a>
            <a href="{{ url_for('history') }}" class="settings-item">
                <div class="icon orange"><i class="fa-regular fa-clock"></i></div>
                <div class="info"><div class="title">Activities</div><div class="desc">View your activity history</div></div>
                <span class="arrow"><i class="fa-solid fa-chevron-right"></i></span>
            </a>
        </div>
        <div class="section-title">Account Center</div>
        <div class="settings-section">
            <a href="{{ url_for('account_center') }}" class="settings-item">
                <div class="icon purple"><i class="fa-solid fa-circle-user"></i></div>
                <div class="info"><div class="title">Account Center</div><div class="desc">Manage your accounts</div></div>
                <span class="arrow"><i class="fa-solid fa-chevron-right"></i></span>
            </a>
        </div>
        <div class="section-title">Support</div>
        <div class="settings-section">
            <a href="{{ url_for('about') }}" class="settings-item">
                <div class="icon green"><i class="fa-regular fa-circle-info"></i></div>
                <div class="info"><div class="title">About</div><div class="desc">About FlowUp and developer</div></div>
                <span class="arrow"><i class="fa-solid fa-chevron-right"></i></span>
            </a>
        </div>
        <div class="section-title"></div>
        <div class="settings-section">
            <a href="#" class="settings-item logout" onclick="confirmLogout()">
                <div class="icon"><i class="fa-solid fa-right-from-bracket"></i></div>
                <div class="info"><div class="title">Log out</div><div class="desc">Sign out of your account</div></div>
                <span class="arrow"><i class="fa-solid fa-chevron-right"></i></span>
            </a>
        </div>
    </div>
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=current_user.username) }}" class="active"><i class="fa-regular fa-user"></i></a>
    </div>
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    <script>
        function confirmLogout() { if (confirm('Are you sure you want to log out?')) { window.location.href = '/logout'; } }
        setTimeout(function(){document.querySelectorAll('.flash-message').forEach(function(el){el.style.opacity='0';setTimeout(function(){el.remove()},500)})},4000);
    </script>
</body>
</html>
'''
ACCOUNT_CENTER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Account Center - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { max-width:430px; margin:auto; background:#000; min-height:100vh; color:#fff; }
        .header { background:#000; padding:14px 16px; border-bottom:1px solid rgba(255,255,255,0.1); display:flex; align-items:center; gap:12px; position:sticky; top:0; z-index:10; }
        .header .back-btn { color:#fff; font-size:24px; text-decoration:none; width:36px; height:36px; display:flex; align-items:center; justify-content:center; border-radius:50%; transition:background 0.2s; }
        .header .back-btn:hover { background:rgba(255,255,255,0.1); }
        .header .back-btn:active { transform:scale(0.9); }
        .header h1 { font-size:18px; font-weight:700; flex:1; color:#fff; }
        .account-section { padding:8px 0; }
        .section-title { font-size:13px; font-weight:600; color:rgba(255,255,255,0.4); padding:12px 16px 6px; text-transform:uppercase; letter-spacing:0.5px; }
        .account-card { background:rgba(255,255,255,0.05); margin:4px 12px; border-radius:14px; padding:14px 16px; display:flex; align-items:center; gap:14px; border:1px solid rgba(255,255,255,0.06); }
        .account-card .avatar { width:50px; height:50px; border-radius:50%; object-fit:cover; border:2px solid #d868ff; flex-shrink:0; background:#222; }
        .account-card .info { flex:1; min-width:0; }
        .account-card .info .name { font-weight:600; font-size:15px; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .account-card .info .username { font-size:13px; color:rgba(255,255,255,0.5); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .account-card .badge { background:#d868ff; color:#fff; font-size:10px; font-weight:700; padding:3px 12px; border-radius:12px; flex-shrink:0; letter-spacing:0.3px; }
        .account-item { background:rgba(255,255,255,0.03); margin:4px 12px; border-radius:14px; padding:12px 16px; display:flex; align-items:center; gap:14px; border:1px solid rgba(255,255,255,0.04); cursor:pointer; transition:all 0.2s; }
        .account-item:hover { background:rgba(255,255,255,0.08); }
        .account-item:active { transform:scale(0.98); }
        .account-item .avatar { width:44px; height:44px; border-radius:50%; object-fit:cover; border:2px solid rgba(255,255,255,0.1); flex-shrink:0; background:#222; }
        .account-item .info { flex:1; min-width:0; }
        .account-item .info .name { font-weight:500; font-size:14px; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .account-item .info .username { font-size:12px; color:rgba(255,255,255,0.4); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .account-item .switch-btn { background:#d868ff; color:#fff; border:none; padding:5px 16px; border-radius:16px; font-size:12px; font-weight:600; cursor:pointer; transition:all 0.2s; flex-shrink:0; }
        .account-item .switch-btn:hover { opacity:0.85; transform:scale(1.02); }
        .account-item .switch-btn:active { transform:scale(0.92); }
        .divider { height:1px; background:rgba(255,255,255,0.06); margin:12px 16px; }
        .add-account-btn { background:rgba(255,255,255,0.03); margin:4px 12px; border-radius:14px; padding:14px 16px; display:flex; align-items:center; gap:14px; border:1px dashed rgba(216,104,255,0.3); cursor:pointer; transition:all 0.3s; }
        .add-account-btn:hover { background:rgba(216,104,255,0.05); border-color:#d868ff; }
        .add-account-btn:active { transform:scale(0.98); }
        .add-account-btn i { font-size:22px; color:#d868ff; width:44px; height:44px; display:flex; align-items:center; justify-content:center; border-radius:50%; background:rgba(216,104,255,0.1); }
        .add-account-btn .info { flex:1; }
        .add-account-btn .info .title { font-weight:600; font-size:15px; color:#d868ff; }
        .add-account-btn .info .desc { font-size:12px; color:rgba(255,255,255,0.3); }
        .bottom-nav { position:fixed; bottom:0; left:50%; transform:translateX(-50%); width:100%; max-width:430px; height:65px; background:linear-gradient(45deg,#ff73d2,#d868ff); display:flex; justify-content:space-around; align-items:center; border-radius:25px 25px 0 0; padding:0 12px; z-index:50; }
        .bottom-nav a { display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; opacity:0.7; font-size:24px; transition:all 0.2s; }
        .bottom-nav a.active { opacity:1; }
        .bottom-nav a:hover { opacity:1; }
        .plus-btn { width:58px; height:58px; border-radius:50%; background:#fff; display:flex; align-items:center; justify-content:center; margin-top:-28px; text-decoration:none; box-shadow:0 4px 15px rgba(0,0,0,0.3); transition:transform 0.3s ease; }
        .plus-btn:hover { transform:scale(1.1); }
        .plus-btn i { color:#000; font-size:30px; }
        .bottom-spacer { height:65px; }
        .flash-messages { position:fixed; top:60px; left:50%; transform:translateX(-50%); z-index:999; width:90%; max-width:400px; }
        .flash-message { padding:10px 16px; border-radius:10px; margin-bottom:6px; color:#fff; font-weight:500; text-align:center; animation:slideDown 0.3s ease; }
        .flash-message.success { background:#28a745; }
        .flash-message.danger { background:#dc3545; }
        .flash-message.warning { background:#ffc107; color:#333; }
        @keyframes slideDown { from { opacity:0; transform:translateY(-20px); } to { opacity:1; transform:translateY(0); } }
        @media (max-width:430px) { .header { padding:12px 14px; } .header h1 { font-size:16px; } .account-card { padding:12px 14px; } .account-item { padding:10px 14px; } .account-card .avatar { width:44px; height:44px; } .account-item .avatar { width:38px; height:38px; } }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="header">
        <a href="{{ url_for('feed') }}" class="back-btn"><i class="fa-solid fa-chevron-left"></i></a>
        <h1>Account Center</h1>
        <a href="{{ url_for('settings') }}" style="color:#d868ff;font-size:14px;font-weight:600;text-decoration:none;padding:6px 12px;border-radius:20px;transition:all 0.2s;"><i class="fa-regular fa-gear"></i></a>
    </div>
    <div class="account-section">
        <div class="section-title">Current Account</div>
        <div class="account-card">
            <img class="avatar" src="/static/uploads/{{ current_user.profile_pic }}" onerror="this.src='/static/default.svg'">
            <div class="info">
                <div class="name">{{ current_user.full_name|e or current_user.username|e }}</div>
                <div class="username">@{{ current_user.username|e }}</div>
            </div>
            <span class="badge">Active</span>
        </div>
        {% if other_accounts %}
            <div class="section-title">Other Accounts</div>
            {% for acc in other_accounts %}
            <div class="account-item" onclick="switchAccount({{ acc.id }})">
                <img class="avatar" src="/static/uploads/{{ acc.profile_pic }}" onerror="this.src='/static/default.svg'">
                <div class="info">
                    <div class="name">{{ acc.full_name|e or acc.username|e }}</div>
                    <div class="username">@{{ acc.username|e }}</div>
                </div>
                <button class="switch-btn" id="switchBtn-{{ acc.id }}" onclick="event.stopPropagation(); switchAccount({{ acc.id }})">Switch</button>
            </div>
            {% endfor %}
        {% else %}
            <div style="padding:8px 20px; text-align:center; color:rgba(255,255,255,0.2); font-size:13px;">No other accounts linked</div>
        {% endif %}
        <div class="divider"></div>
        <div class="add-account-btn" onclick="window.location.href='/register'">
            <i class="fa-solid fa-plus"></i>
            <div class="info">
                <div class="title">Add Account</div>
                <div class="desc">Create a new account or login to existing</div>
            </div>
            <span style="color:rgba(255,255,255,0.2);font-size:16px;"><i class="fa-solid fa-chevron-right"></i></span>
        </div>
        <div class="divider"></div>
        <div class="section-title">Settings</div>
        <div style="background:rgba(255,255,255,0.03);margin:3px 12px;border-radius:14px;padding:12px 16px;display:flex;align-items:center;gap:14px;border:1px solid rgba(255,255,255,0.04);cursor:pointer;transition:all 0.2s;" onclick="window.location.href='{{ url_for('edit_profile') }}'">
            <i style="font-size:18px;width:36px;color:rgba(255,255,255,0.5);text-align:center;" class="fa-regular fa-user"></i>
            <div class="info" style="flex:1;">
                <div style="font-weight:500;font-size:14px;color:#fff;">Edit Profile</div>
                <div style="font-size:11px;color:rgba(255,255,255,0.3);">Change your profile information</div>
            </div>
            <span style="color:rgba(255,255,255,0.15);font-size:14px;"><i class="fa-solid fa-chevron-right"></i></span>
        </div>
    </div>
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=current_user.username) }}"><i class="fa-regular fa-user"></i></a>
    </div>
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    <script>
        function getCsrfToken() { return document.getElementById('csrf_token').value; }
        function switchAccount(userId) {
            var btn = document.getElementById('switchBtn-' + userId);
            var originalText = btn.textContent;
            btn.textContent = 'Switching...';
            btn.classList.add('switching');
            var csrf = getCsrfToken();
            fetch('/api/switch_account/' + userId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    window.location.href = '/feed';
                } else {
                    btn.textContent = originalText;
                    btn.classList.remove('switching');
                    alert(data.error || 'Error switching account');
                }
            })
            .catch(function(error) {
                console.error('Error:', error);
                btn.textContent = originalText;
                btn.classList.remove('switching');
                alert('Error switching account');
            });
        }
        setTimeout(function(){document.querySelectorAll('.flash-message').forEach(function(el){el.style.opacity='0';setTimeout(function(){el.remove()},500)})},4000);
    </script>
</body>
</html>
'''
ABOUT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>About - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { max-width:430px; margin:auto; background:#000; min-height:100vh; color:#fff; padding-bottom:80px; }
        .header { background:#000; padding:14px 16px; border-bottom:1px solid rgba(255,255,255,0.08); display:flex; align-items:center; gap:12px; position:sticky; top:0; z-index:10; }
        .header .back-btn { color:#fff; font-size:22px; text-decoration:none; width:36px; height:36px; display:flex; align-items:center; justify-content:center; border-radius:50%; transition:background 0.2s; }
        .header .back-btn:hover { background:rgba(255,255,255,0.08); }
        .header .back-btn:active { transform:scale(0.9); }
        .header h1 { font-size:18px; font-weight:700; flex:1; color:#fff; }
        .about-container { padding:16px; }
        .profile-card { background:rgba(255,255,255,0.03); border-radius:16px; padding:20px; border:1px solid rgba(255,255,255,0.06); text-align:center; margin-bottom:16px; }
        .profile-card .avatar { width:80px; height:80px; border-radius:50%; object-fit:cover; border:3px solid #d868ff; margin:0 auto 12px; background:#222; }
        .profile-card .name { font-size:20px; font-weight:700; color:#fff; }
        .profile-card .title { font-size:14px; color:rgba(255,255,255,0.4); margin-top:2px; }
        .profile-card .bio { font-size:13px; color:rgba(255,255,255,0.5); margin-top:8px; line-height:1.5; }
        .info-card { background:rgba(255,255,255,0.03); border-radius:14px; padding:16px; border:1px solid rgba(255,255,255,0.06); margin-bottom:12px; }
        .info-card .card-title { font-size:12px; font-weight:600; color:rgba(255,255,255,0.3); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:10px; }
        .info-item { display:flex; align-items:center; gap:12px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04); }
        .info-item:last-child { border-bottom:none; }
        .info-item .label { font-size:13px; color:rgba(255,255,255,0.3); min-width:80px; }
        .info-item .value { font-size:13px; color:#fff; flex:1; }
        .info-item .value a { color:#d868ff; text-decoration:none; }
        .info-item .value a:hover { text-decoration:underline; }
        .supporters-list { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; }
        .supporter-tag { background:rgba(216,104,255,0.1); color:#d868ff; padding:4px 14px; border-radius:20px; font-size:12px; font-weight:500; border:1px solid rgba(216,104,255,0.1); }
        .social-links { display:flex; gap:12px; margin-top:8px; flex-wrap:wrap; }
        .social-link { display:flex; align-items:center; gap:8px; padding:8px 16px; border-radius:12px; background:rgba(255,255,255,0.04); color:#fff; text-decoration:none; font-size:13px; transition:all 0.2s; border:1px solid rgba(255,255,255,0.04); }
        .social-link:hover { background:rgba(255,255,255,0.08); }
        .social-link:active { transform:scale(0.95); }
        .social-link i { font-size:16px; }
        .social-link.instagram i { color:#E4405F; }
        .social-link.facebook i { color:#1877F2; }
        .social-link.email i { color:#D44638; }
        .social-link.phone i { color:#2ecc71; }
        .app-info { text-align:center; padding:16px; color:rgba(255,255,255,0.2); font-size:12px; }
        .app-info .version { font-weight:600; color:rgba(255,255,255,0.3); }
        .bottom-nav { position:fixed; bottom:0; left:50%; transform:translateX(-50%); width:100%; max-width:430px; height:65px; background:linear-gradient(45deg,#ff73d2,#d868ff); display:flex; justify-content:space-around; align-items:center; border-radius:25px 25px 0 0; padding:0 12px; z-index:50; }
        .bottom-nav a { display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; opacity:0.7; font-size:24px; transition:all 0.2s; }
        .bottom-nav a.active { opacity:1; }
        .bottom-nav a:hover { opacity:1; }
        .plus-btn { width:58px; height:58px; border-radius:50%; background:#fff; display:flex; align-items:center; justify-content:center; margin-top:-28px; text-decoration:none; box-shadow:0 4px 15px rgba(0,0,0,0.3); transition:transform 0.3s ease; }
        .plus-btn:hover { transform:scale(1.1); }
        .plus-btn i { color:#000; font-size:30px; }
        .bottom-spacer { height:65px; }
        @media (max-width:430px) { .header { padding:12px 14px; } .header h1 { font-size:16px; } .profile-card .avatar { width:64px; height:64px; } .profile-card .name { font-size:18px; } .about-container { padding:12px; } .info-item .label { min-width:60px; font-size:12px; } .info-item .value { font-size:12px; } .social-link { padding:6px 12px; font-size:12px; } }
    </style>
</head>
<body>
    <div class="header">
        <a href="{{ url_for('settings') }}" class="back-btn"><i class="fa-solid fa-chevron-left"></i></a>
        <h1>About</h1>
    </div>
    <div class="about-container">
        <div class="profile-card">
            <img class="avatar" src="/static/uploads/default.svg" onerror="this.src='/static/default.svg'">
            <div class="name">Protas Felix</div>
            <div class="title">🌟 Developer &amp; IT Programmer</div>
            <div class="bio">Passionate developer building amazing experiences. Creating innovative solutions with code.</div>
        </div>
        <div class="info-card">
            <div class="card-title"><i class="fa-regular fa-user"></i> Personal Information</div>
            <div class="info-item"><span class="label">Full Name</span><span class="value">Protas Felix</span></div>
            <div class="info-item"><span class="label">Family</span><span class="value">Mother: Stella · Father: Felix</span></div>
            <div class="info-item"><span class="label">Birth Date</span><span class="value">28th, 2009</span></div>
            <div class="info-item"><span class="label">Education</span><span class="value">Educated</span></div>
            <div class="info-item"><span class="label">Knowledge</span><span class="value">IT Programmer</span></div>
        </div>
        <div class="info-card">
            <div class="card-title"><i class="fa-regular fa-heart"></i> Supporters</div>
            <div class="supporters-list">
                <span class="supporter-tag">🙏 God</span>
                <span class="supporter-tag">👨‍👩‍👦 Family</span>
                <span class="supporter-tag">👨‍💻 The User</span>
                <span class="supporter-tag">🤝 FlowUp Team</span>
                <span class="supporter-tag">❤️ You</span>
            </div>
            <div style="margin-top:8px; font-size:12px; color:rgba(255,255,255,0.3);"><i class="fa-regular fa-heart" style="color:#d868ff;"></i> Thanks to everyone who supports this project!</div>
        </div>
        <div class="info-card">
            <div class="card-title"><i class="fa-regular fa-address-card"></i> Contact</div>
            <div class="info-item"><span class="label">Phone</span><span class="value"><a href="tel:+255655266438">+255 655 266 438</a></span></div>
            <div class="info-item"><span class="label">Email</span><span class="value"><a href="mailto:youngblizz74@gmail.com">youngblizz74@gmail.com</a></span></div>
        </div>
        <div class="info-card">
            <div class="card-title"><i class="fa-regular fa-share-from-square"></i> Social Media</div>
            <div class="social-links">
                <a href="https://www.instagram.com/young_blizz32" target="_blank" class="social-link instagram"><i class="fa-brands fa-instagram"></i> @young_blizz32</a>
                <a href="https://www.facebook.com/youngblizz" target="_blank" class="social-link facebook"><i class="fa-brands fa-facebook"></i> Protas Felix</a>
                <a href="mailto:youngblizz74@gmail.com" class="social-link email"><i class="fa-regular fa-envelope"></i> Email</a>
                <a href="tel:+255655266438" class="social-link phone"><i class="fa-solid fa-phone"></i> Call</a>
            </div>
        </div>
        <div class="app-info">
            <div class="version">FlowUp v2.0.0</div>
            <div style="margin-top:4px;">Built with ❤️ by Protas Felix</div>
            <div style="margin-top:2px; font-size:10px;">&copy; 2026 FlowUp. All rights reserved.</div>
        </div>
    </div>
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=current_user.username) }}" class="active"><i class="fa-regular fa-user"></i></a>
    </div>
</body>
</html>
'''
REELS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Reels - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
        body{background:#000;max-width:430px;margin:auto;min-height:100vh}
        .header{background:#000;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.1)}
        .header h1{color:#fff;font-size:20px}
        .header a{color:#fff;font-size:22px;text-decoration:none}
        .reels-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:4px;padding:4px;background:#000}
        .reel-item{position:relative;aspect-ratio:9/16;overflow:hidden;background:#111;border-radius:8px;cursor:pointer}
        .reel-item video{width:100%;height:100%;object-fit:cover;display:block}
        .reel-item .overlay{position:absolute;bottom:0;left:0;right:0;padding:20px 10px 10px;background:linear-gradient(0deg,rgba(0,0,0,0.7) 0%,transparent 100%);display:flex;justify-content:space-between;align-items:flex-end}
        .reel-item .overlay .user{display:flex;align-items:center;gap:6px;color:#fff;font-size:12px;font-weight:600}
        .reel-item .overlay .user img{width:20px;height:20px;border-radius:50%;object-fit:cover;border:1px solid #fff}
        .reel-item .overlay .stats{color:#fff;font-size:11px;display:flex;gap:10px}
        .reel-item .overlay .stats i{margin-right:3px}
        .no-reels{text-align:center;padding:60px 20px;color:#888;grid-column:1/3}
        .no-reels i{font-size:48px;display:block;margin-bottom:16px;color:#333}
        .flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}
        .flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center}
        .flash-message.success{background:#28a745}
        .flash-message.danger{background:#dc3545}
        .flash-message.warning{background:#ffc107;color:#333}
        .bottom-nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:430px;height:65px;background:linear-gradient(45deg,#ff73d2,#d868ff);display:flex;justify-content:space-around;align-items:center;border-radius:25px 25px 0 0;padding:0 12px;z-index:50}
        .bottom-nav a{display:flex;align-items:center;justify-content:center;text-decoration:none;color:white;opacity:0.85;font-size:24px;transition:opacity 0.2s}
        .bottom-nav a.active{opacity:1}
        .bottom-nav a:hover{opacity:1}
        .plus-btn{width:58px;height:58px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;margin-top:-28px;text-decoration:none;box-shadow:0 4px 15px rgba(0,0,0,0.3)}
        .plus-btn:hover{transform:scale(1.1)}
        .plus-btn i{color:#000;font-size:30px}
        .bottom-spacer{height:65px}
        .pagination{display:flex;justify-content:center;gap:8px;padding:15px 0;background:#000}
        .pagination a{padding:6px 14px;background:rgba(255,255,255,0.1);color:#fff;border-radius:20px;text-decoration:none;font-size:13px}
        .pagination a:hover{background:rgba(255,255,255,0.2)}
        .pagination a.active{background:linear-gradient(135deg,#d868ff,#ff73d2);color:white}
    </style>
</head>
<body>
    <div class="flash-messages">{% for category, message in flashes %}<div class="flash-message {{ category }}">{{ message }}</div>{% endfor %}</div>
    <div class="header"><a href="{{ url_for('feed') }}"><i class="fa-solid fa-arrow-left"></i></a><h1>Reels</h1><a href="{{ url_for('upload') }}"><i class="fa-solid fa-plus"></i></a></div>
    <div class="reels-grid">{% if reels %}{% for r in reels %}<a href="{{ url_for('view_reel', reel_id=r.id) }}" class="reel-item"><video src="/{{ r.media_url }}" muted preload="metadata" playsinline></video><div class="overlay"><div class="user"><img src="/static/uploads/{{ r.profile_pic }}" onerror="this.src='/static/default.svg'"><span>{{ r.username|e }}</span></div><div class="stats"><span><i class="fa-regular fa-heart"></i> {{ r.like_count }}</span></div></div></a>{% endfor %}{% else %}<div class="no-reels"><i class="fa-regular fa-video"></i><h3>No reels yet</h3><p>Upload your first reel!</p><a href="{{ url_for('upload') }}" style="display:inline-block;margin-top:16px;padding:10px 30px;background:linear-gradient(45deg,#ff73d2,#d868ff);color:white;border-radius:25px;text-decoration:none;font-weight:600;"><i class="fa-solid fa-plus"></i> Upload Reel</a></div>{% endif %}</div>
    {% if total_pages and total_pages > 1 %}<div class="pagination">{% if page > 1 %}<a href="?page={{ page-1 }}"><i class="fa-solid fa-chevron-left"></i></a>{% endif %}{% for p in range(1, total_pages+1) %}{% if p == page %}<a href="?page={{ p }}" class="active">{{ p }}</a>{% elif p <= 3 or p > total_pages-2 %}<a href="?page={{ p }}">{{ p }}</a>{% elif p == 4 and total_pages > 5 %}<span style="color:#888;">...</span>{% endif %}{% endfor %}{% if page < total_pages %}<a href="?page={{ page+1 }}"><i class="fa-solid fa-chevron-right"></i></a>{% endif %}</div>{% endif %}
    <div class="bottom-spacer"></div>
    <div class="bottom-nav"><a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a><a href="{{ url_for('explore') }}" class="active"><i class="fa-regular fa-compass"></i></a><a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a><a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a><a href="{{ url_for('profile', username=current_user.username) }}"><i class="fa-regular fa-user"></i></a></div>
    <script>document.querySelectorAll('.reel-item video').forEach(function(video){var observer=new IntersectionObserver(function(entries){entries.forEach(function(entry){if(entry.isIntersecting){video.play().catch(function(){});}else{video.pause();}});},{threshold:0.3});observer.observe(video);});setTimeout(function(){document.querySelectorAll('.flash-message').forEach(function(el){el.style.opacity='0';setTimeout(function(){el.remove()},500)})},4000);</script>
</body>
</html>
'''
REEL_VIEW_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Reels - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #000; max-width: 430px; margin: auto; height: 100vh; overflow: hidden; position: relative; }
        
        .header { position: fixed; top: 0; left: 0; right: 0; z-index: 30; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; background: linear-gradient(180deg, rgba(0,0,0,0.6) 0%, transparent 100%); pointer-events: none; }
        .header > * { pointer-events: auto; }
        .header h1 { color: #fff; font-size: 20px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
        .header a { color: #fff; font-size: 22px; text-decoration: none; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: rgba(0,0,0,0.3); backdrop-filter: blur(8px); transition: all 0.3s ease; }
        .header a:hover { background: rgba(255,255,255,0.2); }
        .header a:active { transform: scale(0.9); }
        
        .reels-container { height: 100vh; overflow-y: scroll; scroll-snap-type: y mandatory; scroll-behavior: smooth; position: relative; }
        .reels-container::-webkit-scrollbar { display: none; }
        
        .reel-item { height: 100vh; width: 100%; scroll-snap-align: start; position: relative; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden; }
        .reel-item .reel-video { width: 100%; height: 100%; object-fit: contain; background: #000; position: absolute; top: 0; left: 0; }
        
        .reel-loading { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #fff; font-size: 16px; display: flex; flex-direction: column; align-items: center; gap: 12px; z-index: 5; }
        .reel-loading i { font-size: 32px; animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        
        .heart-pop-reel { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%) scale(0); font-size: 100px; z-index: 25; pointer-events: none; animation: heartPopReel 0.7s ease forwards; color: #ed4956; }
        @keyframes heartPopReel { 0% { transform: translate(-50%, -50%) scale(0); opacity: 1; } 50% { transform: translate(-50%, -50%) scale(1.8); opacity: 1; } 100% { transform: translate(-50%, -50%) scale(1); opacity: 0; } }
        
        .reel-info { position: absolute; bottom: 80px; left: 16px; right: 16px; z-index: 15; color: #fff; pointer-events: none; }
        .reel-info > * { pointer-events: auto; }
        
        .reel-user { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .reel-user .user-avatar { width: 40px; height: 40px; border-radius: 50%; object-fit: cover; border: 2px solid #d868ff; cursor: pointer; transition: transform 0.2s; }
        .reel-user .user-avatar:hover { transform: scale(1.05); }
        .reel-user .user-avatar:active { transform: scale(0.9); }
        .reel-user .user-details { flex: 1; cursor: pointer; }
        .reel-user .user-details .name { font-weight: 600; font-size: 15px; color: #fff; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
        .reel-user .user-details .username { font-size: 13px; color: rgba(255,255,255,0.7); text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
        
        .follow-btn { background: #d868ff; color: white; border: none; padding: 6px 18px; border-radius: 20px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; pointer-events: auto; white-space: nowrap; flex-shrink: 0; }
        .follow-btn:hover { opacity: 0.85; transform: scale(1.02); }
        .follow-btn:active { transform: scale(0.92); }
        .follow-btn.following { background: rgba(255,255,255,0.2); backdrop-filter: blur(8px); border: 1px solid rgba(255,255,255,0.2); }
        .follow-btn.following:hover { background: rgba(255,0,0,0.3); border-color: rgba(255,0,0,0.3); }
        
        .reel-caption { font-size: 14px; color: #fff; text-shadow: 0 2px 4px rgba(0,0,0,0.5); margin-top: 4px; max-width: 80%; }
        .reel-caption strong { color: #fff; margin-right: 6px; cursor: pointer; }
        .reel-caption strong:hover { text-decoration: underline; }
        
        .reel-actions { position: absolute; bottom: 160px; right: 16px; z-index: 15; display: flex; flex-direction: column; align-items: center; gap: 18px; pointer-events: none; }
        .reel-actions > * { pointer-events: auto; }
        
        .reel-action-btn { background: rgba(0,0,0,0.5); backdrop-filter: blur(8px); border: 1px solid rgba(255,255,255,0.1); border-radius: 50%; width: 48px; height: 48px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #fff; font-size: 22px; cursor: pointer; transition: all 0.3s ease; gap: 2px; text-decoration: none; }
        .reel-action-btn:hover { background: rgba(255,255,255,0.15); transform: scale(1.05); }
        .reel-action-btn:active { transform: scale(0.9); }
        .reel-action-btn .count { font-size: 11px; font-weight: 600; color: rgba(255,255,255,0.8); }
        .reel-action-btn .fa-solid.fa-heart { color: #ed4956; }
        .reel-action-btn .fa-regular.fa-heart { color: #fff; }
        .reel-action-btn .fa-solid.fa-bookmark { color: #d868ff; }
        .reel-action-btn .fa-regular.fa-bookmark { color: #fff; }
        
        .reel-mute-btn { position: absolute; bottom: 20px; right: 16px; z-index: 15; background: rgba(0,0,0,0.6); backdrop-filter: blur(8px); width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-size: 18px; cursor: pointer; border: 1px solid rgba(255,255,255,0.15); transition: all 0.3s ease; pointer-events: auto; }
        .reel-mute-btn:hover { background: rgba(255,255,255,0.2); transform: scale(1.05); }
        .reel-mute-btn:active { transform: scale(0.9); }
        .reel-mute-btn.muted { background: rgba(255,0,0,0.4); border-color: rgba(255,0,0,0.3); }
        .reel-mute-btn.unmuted { background: rgba(0,255,0,0.3); border-color: rgba(0,255,0,0.2); }
        
        .reel-progress { position: absolute; top: 60px; left: 12px; right: 12px; height: 3px; background: rgba(255,255,255,0.2); border-radius: 2px; overflow: hidden; z-index: 20; }
        .reel-progress .progress-fill { height: 100%; width: 0%; background: #d868ff; border-radius: 2px; transition: width 0.1s linear; }
        
        .share-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:999;display:none}
        .share-panel{position:fixed;bottom:0;left:50%;transform:translateX(-50%) translateY(100%);width:100%;max-width:430px;background:#fff;border-radius:20px 20px 0 0;box-shadow:0 -10px 40px rgba(0,0,0,0.3);z-index:1001;transition:transform 0.4s cubic-bezier(0.22,1,0.36,1);padding:20px 20px 30px}
        .share-panel.active{transform:translateX(-50%) translateY(0)}
        .share-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
        .share-header h3{font-size:18px;font-weight:700;color:#262626}
        .share-header h3 i{color:#d868ff;margin-right:8px}
        .close-share{background:none;border:none;font-size:24px;cursor:pointer;color:#8e8e8e;padding:4px}
        .close-share:hover{color:#262626}
        .share-options{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
        .share-option{display:flex;flex-direction:column;align-items:center;gap:6px;padding:16px 8px;background:#f8f8f8;border:none;border-radius:12px;cursor:pointer;transition:all 0.2s}
        .share-option:hover{background:#f0f0f0;transform:translateY(-2px)}
        .share-option:active{transform:scale(0.95)}
        .share-option i{font-size:28px}
        .share-option span{font-size:11px;color:#262626;font-weight:500}
        
        .flash-messages { position: fixed; top: 60px; left: 50%; transform: translateX(-50%); z-index: 999; width: 90%; max-width: 400px; }
        .flash-message { padding: 10px 16px; border-radius: 10px; margin-bottom: 6px; color: #fff; font-weight: 500; text-align: center; animation: slideDown 0.3s ease; }
        .flash-message.success { background: #28a745; }
        .flash-message.danger { background: #dc3545; }
        .flash-message.warning { background: #ffc107; color: #333; }
        .flash-message.info { background: #17a2b8; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        
        @media (max-width: 430px) {
            .reel-user .user-avatar { width: 34px; height: 34px; }
            .reel-user .user-details .name { font-size: 14px; }
            .reel-user .user-details .username { font-size: 12px; }
            .follow-btn { font-size: 12px; padding: 5px 14px; }
            .reel-action-btn { width: 42px; height: 42px; font-size: 20px; }
            .reel-action-btn .count { font-size: 10px; }
            .reel-caption { font-size: 13px; }
            .reel-actions { bottom: 140px; gap: 14px; right: 12px; }
            .reel-info { bottom: 70px; left: 12px; right: 12px; }
            .reel-mute-btn { width: 36px; height: 36px; font-size: 16px; bottom: 16px; right: 12px; }
            .header { padding: 10px 12px; }
            .header h1 { font-size: 18px; }
            .header a { width: 34px; height: 34px; font-size: 18px; }
            .heart-pop-reel { font-size: 70px; }
            .reel-progress { top: 55px; }
        }
    </style>
</head>
<body>
    <div class="flash-messages">{% for category, message in flashes %}<div class="flash-message {{ category }}">{{ message }}</div>{% endfor %}</div>
    
    <div class="header">
        <a href="{{ url_for('explore') }}"><i class="fa-solid fa-arrow-left"></i></a>
        <h1>Reels</h1>
        <a href="{{ url_for('upload') }}"><i class="fa-solid fa-plus"></i></a>
    </div>
    
    <div class="reels-container" id="reelsContainer">
        {% for reel in reels %}
        <div class="reel-item" data-reel-id="{{ reel.id }}" data-index="{{ loop.index0 }}">
            <div class="reel-loading" id="loading-{{ reel.id }}"><i class="fa-solid fa-spinner"></i><span>Loading...</span></div>
            <video class="reel-video" id="video-{{ reel.id }}" muted playsinline preload="metadata" loop poster="/static/uploads/{{ reel.id }}_thumb.jpg">
                <source src="/{{ reel.media_url }}" type="video/mp4"><source src="/{{ reel.media_url }}" type="video/webm">
            </video>
            <div class="reel-progress" id="progress-{{ reel.id }}"><div class="progress-fill" id="progressFill-{{ reel.id }}"></div></div>
            <div class="reel-mute-btn muted" id="muteBtn-{{ reel.id }}" onclick="event.stopPropagation(); toggleReelMute({{ reel.id }})"><i class="fa-solid fa-volume-xmark"></i></div>
            
            <div class="reel-actions">
                <button class="reel-action-btn" onclick="event.stopPropagation(); toggleReelLike({{ reel.id }})">
                    {% if reel.liked_by_user %}<i class="fa-solid fa-heart" id="likeIcon-{{ reel.id }}" style="color:#ed4956;"></i>{% else %}<i class="fa-regular fa-heart" id="likeIcon-{{ reel.id }}"></i>{% endif %}
                    <span class="count" id="likeCount-{{ reel.id }}">{{ reel.like_count }}</span>
                </button>
                <button class="reel-action-btn" onclick="event.stopPropagation(); toggleSaveReel({{ reel.id }})">
                    {% if reel.saved_by_user %}<i class="fa-solid fa-bookmark" id="saveIcon-{{ reel.id }}" style="color:#d868ff;"></i>{% else %}<i class="fa-regular fa-bookmark" id="saveIcon-{{ reel.id }}"></i>{% endif %}
                    <span class="count" id="saveCount-{{ reel.id }}">{% if reel.saved_by_user %}Saved{% else %}Save{% endif %}</span>
                </button>
                <button class="reel-action-btn" onclick="event.stopPropagation(); openSharePanelReel({{ reel.id }})"><i class="fa-regular fa-paper-plane"></i></button>
                {% if reel.is_owner %}<button class="reel-action-btn" onclick="event.stopPropagation(); deleteReel({{ reel.id }})" style="color:#ff4444;"><i class="fa-solid fa-trash"></i></button>{% endif %}
            </div>
            
            <div class="reel-info">
                <div class="reel-user">
                    <img class="user-avatar" src="/static/uploads/{{ reel.profile_pic }}" onerror="this.src='/static/default.svg'" onclick="event.stopPropagation(); goToProfile({{ reel.user_id }}, '{{ reel.username }}')">
                    <div class="user-details" onclick="event.stopPropagation(); goToProfile({{ reel.user_id }}, '{{ reel.username }}')">
                        <div class="name">{{ reel.full_name|e or reel.username|e }}</div>
                        <div class="username">@{{ reel.username|e }}</div>
                    </div>
                    {% if not reel.is_owner %}
                        {% if reel.is_following %}
                        <button class="follow-btn following" onclick="event.stopPropagation(); toggleFollow({{ reel.user_id }}, {{ reel.id }})"><i class="fa-solid fa-check"></i> Following</button>
                        {% else %}
                        <button class="follow-btn" onclick="event.stopPropagation(); toggleFollow({{ reel.user_id }}, {{ reel.id }})"><i class="fa-solid fa-user-plus"></i> Follow</button>
                        {% endif %}
                    {% endif %}
                </div>
                {% if reel.caption %}<div class="reel-caption"><strong onclick="event.stopPropagation(); goToProfile({{ reel.user_id }}, '{{ reel.username }}')">{{ reel.username|e }}</strong> {{ reel.caption|e }}</div>{% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
    
    <!-- Share Panel -->
    <div class="share-overlay" id="shareOverlayReel" onclick="closeSharePanelReel()"></div>
    <div class="share-panel" id="sharePanelReel">
        <div class="share-header">
            <h3><i class="fa-regular fa-share-from-square"></i> Share</h3>
            <button onclick="closeSharePanelReel()" class="close-share"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="share-content">
            <div class="share-options">
                <button onclick="shareActionReel('copy')" class="share-option"><i class="fa-solid fa-link"></i><span>Copy Link</span></button>
                <button onclick="shareActionReel('whatsapp')" class="share-option"><i class="fa-brands fa-whatsapp" style="color:#25D366;"></i><span>WhatsApp</span></button>
                <button onclick="shareActionReel('twitter')" class="share-option"><i class="fa-brands fa-twitter" style="color:#1DA1F2;"></i><span>Twitter</span></button>
                <button onclick="shareActionReel('facebook')" class="share-option"><i class="fa-brands fa-facebook" style="color:#1877F2;"></i><span>Facebook</span></button>
                <button onclick="shareActionReel('instagram')" class="share-option"><i class="fa-brands fa-instagram" style="color:#E4405F;"></i><span>Instagram</span></button>
                <button onclick="shareActionReel('telegram')" class="share-option"><i class="fa-brands fa-telegram" style="color:#0088CC;"></i><span>Telegram</span></button>
            </div>
        </div>
    </div>
    
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    
    <script>
        function getCsrfToken() {
            var el = document.getElementById('csrf_token');
            if (!el) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.id = 'csrf_token';
                input.value = '{{ csrf_token() }}';
                document.body.appendChild(input);
                return input.value;
            }
            return el.value;
        }
        
        function flash(message, type) {
            var container = document.querySelector('.flash-messages');
            if (!container) return;
            var div = document.createElement('div');
            div.className = 'flash-message ' + (type || 'info');
            div.textContent = message;
            container.appendChild(div);
            setTimeout(function() {
                div.style.transition = 'opacity 0.5s';
                div.style.opacity = '0';
                setTimeout(function() { div.remove(); }, 500);
            }, 4000);
        }
        
        setTimeout(function() {
            document.querySelectorAll('.flash-message').forEach(function(el) {
                el.style.transition = 'opacity 0.5s';
                el.style.opacity = '0';
                setTimeout(function() { el.remove(); }, 500);
            });
        }, 4000);
        
        function goToProfile(userId, username) {
            window.location.href = '/profile/' + username;
        }
        
        // ===== VIDEO INIT =====
        var videos = {};
        var videoObservers = {};
        
        function initVideo(video) {
            var reelId = video.id.replace('video-', '');
            var loading = document.getElementById('loading-' + reelId);
            var progressFill = document.getElementById('progressFill-' + reelId);
            
            video.addEventListener('canplay', function() {
                if (loading) loading.style.display = 'none';
            });
            
            video.addEventListener('timeupdate', function() {
                if (video.duration && progressFill) {
                    var percent = (video.currentTime / video.duration) * 100;
                    progressFill.style.width = percent + '%';
                }
            });
            
            video.addEventListener('ended', function() {
                if (progressFill) progressFill.style.width = '0%';
                video.currentTime = 0;
                video.play().catch(function() {});
            });
            
            videos[reelId] = video;
            
            var observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        video.play().catch(function(e) {});
                        updateMuteButton(reelId);
                    } else {
                        video.pause();
                    }
                });
            }, { threshold: 0.5 });
            observer.observe(video);
            videoObservers[reelId] = observer;
        }
        
        function updateMuteButton(reelId) {
            var video = videos[reelId];
            var muteBtn = document.getElementById('muteBtn-' + reelId);
            if (!video || !muteBtn) return;
            if (video.muted) {
                muteBtn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i>';
                muteBtn.className = 'reel-mute-btn muted';
            } else {
                muteBtn.innerHTML = '<i class="fa-solid fa-volume-high"></i>';
                muteBtn.className = 'reel-mute-btn unmuted';
            }
        }
        
        document.querySelectorAll('.reel-video').forEach(function(video) {
            initVideo(video);
        });
        
        function toggleReelMute(reelId) {
            var video = videos[reelId];
            if (!video) return;
            video.muted = !video.muted;
            updateMuteButton(reelId);
        }
        
        // ===== DOUBLE TAP LIKE =====
        document.querySelectorAll('.reel-item').forEach(function(item) {
            var lastTap = 0;
            var tapTimeout = null;
            var reelId = item.dataset.reelId;
            
            item.addEventListener('click', function(e) {
                if (e.target.closest('button') || e.target.closest('.reel-action-btn') ||
                    e.target.closest('.follow-btn') || e.target.closest('.reel-mute-btn') ||
                    e.target.closest('.user-avatar') || e.target.closest('.user-details') ||
                    e.target.closest('.reel-caption strong')) {
                    return;
                }
                var now = Date.now();
                var timeSinceLastTap = now - lastTap;
                if (timeSinceLastTap < 500 && timeSinceLastTap > 0) {
                    toggleReelLike(reelId);
                    createHeartAnimationReel(item);
                    lastTap = 0;
                    if (tapTimeout) { clearTimeout(tapTimeout); tapTimeout = null; }
                } else {
                    lastTap = now;
                    if (tapTimeout) { clearTimeout(tapTimeout); }
                    tapTimeout = setTimeout(function() {
                        lastTap = 0;
                        tapTimeout = null;
                    }, 500);
                }
            });
        });
        
        function createHeartAnimationReel(container) {
            var heart = document.createElement('div');
            heart.className = 'heart-pop-reel';
            heart.textContent = '❤️';
            container.appendChild(heart);
            setTimeout(function() { heart.remove(); }, 800);
        }
        
        // ===== REEL LIKE =====
        function toggleReelLike(reelId) {
            var csrf = getCsrfToken();
            if (!csrf) {
                flash('Session expired. Please refresh.', 'danger');
                return;
            }
            var icon = document.getElementById('likeIcon-' + reelId);
            var countSpan = document.getElementById('likeCount-' + reelId);
            if (!icon || !countSpan) {
                console.error('Like elements not found for reel:', reelId);
                return;
            }
            
            var isLiked = icon.classList.contains('fa-solid');
            var currentCount = parseInt(countSpan.textContent) || 0;
            
            if (isLiked) {
                icon.className = 'fa-regular fa-heart';
                icon.style.color = '';
                countSpan.textContent = Math.max(0, currentCount - 1);
            } else {
                icon.className = 'fa-solid fa-heart';
                icon.style.color = '#ed4956';
                countSpan.textContent = currentCount + 1;
                var item = document.querySelector('.reel-item[data-reel-id="' + reelId + '"]');
                if (item) createHeartAnimationReel(item);
            }
            
            fetch('/api/reel/like/' + reelId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) {
                if (!response.ok) throw new Error('Server error');
                return response.json();
            })
            .then(function(data) {
                if (data.success) {
                    if (data.liked) {
                        icon.className = 'fa-solid fa-heart';
                        icon.style.color = '#ed4956';
                    } else {
                        icon.className = 'fa-regular fa-heart';
                        icon.style.color = '';
                    }
                    countSpan.textContent = data.like_count;
                }
            })
            .catch(function(error) {
                console.error('Reel like error:', error);
                flash('Error liking reel.', 'danger');
                if (isLiked) {
                    icon.className = 'fa-solid fa-heart';
                    icon.style.color = '#ed4956';
                    countSpan.textContent = currentCount + 1;
                } else {
                    icon.className = 'fa-regular fa-heart';
                    icon.style.color = '';
                    countSpan.textContent = currentCount;
                }
            });
        }
        
        // ===== SAVE REEL =====
        function toggleSaveReel(reelId) {
            var csrf = getCsrfToken();
            if (!csrf) {
                flash('Session expired. Please refresh.', 'danger');
                return;
            }
            var icon = document.getElementById('saveIcon-' + reelId);
            var countSpan = document.getElementById('saveCount-' + reelId);
            if (!icon || !countSpan) return;
            
            var isSaved = icon.classList.contains('fa-solid');
            
            fetch('/api/reel/save/' + reelId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    if (data.saved) {
                        icon.className = 'fa-solid fa-bookmark';
                        icon.style.color = '#d868ff';
                        countSpan.textContent = 'Saved';
                        flash('Reel saved!', 'success');
                    } else {
                        icon.className = 'fa-regular fa-bookmark';
                        icon.style.color = '';
                        countSpan.textContent = 'Save';
                        flash('Reel unsaved.', 'info');
                    }
                } else {
                    flash(data.error || 'Error saving reel.', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error saving reel:', error);
                flash('Error saving reel.', 'danger');
            });
        }
        
        // ===== SHARE REEL =====
        function openSharePanelReel(reelId) {
            var panel = document.getElementById('sharePanelReel');
            var overlay = document.getElementById('shareOverlayReel');
            panel.dataset.reelId = reelId;
            panel.dataset.url = window.location.origin + '/reel/' + reelId;
            overlay.style.display = 'block';
            panel.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
        
        function closeSharePanelReel() {
            var overlay = document.getElementById('shareOverlayReel');
            var panel = document.getElementById('sharePanelReel');
            overlay.style.display = 'none';
            panel.classList.remove('active');
            document.body.style.overflow = '';
        }
        
        function shareActionReel(action) {
            var panel = document.getElementById('sharePanelReel');
            var url = panel ? panel.dataset.url : window.location.origin;
            var text = 'Check out this reel on FlowUp!';
            
            switch(action) {
                case 'copy':
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(url).then(function() {
                            flash('Link copied to clipboard!', 'success');
                            closeSharePanelReel();
                        }).catch(function() { copyLinkFallbackReel(url); });
                    } else {
                        copyLinkFallbackReel(url);
                    }
                    break;
                case 'whatsapp':
                    window.open('https://wa.me/?text=' + encodeURIComponent(text + ' ' + url), '_blank');
                    closeSharePanelReel();
                    break;
                case 'twitter':
                    window.open('https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(url), '_blank');
                    closeSharePanelReel();
                    break;
                case 'facebook':
                    window.open('https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url), '_blank');
                    closeSharePanelReel();
                    break;
                case 'instagram':
                    flash('Open Instagram app and paste this link: ' + url, 'info');
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(url);
                    }
                    closeSharePanelReel();
                    break;
                case 'telegram':
                    window.open('https://t.me/share/url?url=' + encodeURIComponent(url) + '&text=' + encodeURIComponent(text), '_blank');
                    closeSharePanelReel();
                    break;
            }
        }
        
        function copyLinkFallbackReel(url) {
            var textarea = document.createElement('textarea');
            textarea.value = url;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                flash('Link copied to clipboard!', 'success');
                closeSharePanelReel();
            } catch(err) {
                flash('Failed to copy link.', 'warning');
            }
            document.body.removeChild(textarea);
        }
        
        // ===== FOLLOW =====
        function toggleFollow(userId, reelId) {
            var csrf = getCsrfToken();
            if (!csrf) {
                flash('Session expired. Please refresh.', 'danger');
                return;
            }
            var btn = document.querySelector('.reel-item[data-reel-id="' + reelId + '"] .follow-btn');
            if (!btn) return;
            var isFollowing = btn.classList.contains('following');
            
            if (isFollowing) {
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Unfollowing...';
            } else {
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Following...';
            }
            btn.disabled = true;
            
            fetch('/api/follow/' + userId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    if (data.following) {
                        btn.innerHTML = '<i class="fa-solid fa-check"></i> Following';
                        btn.classList.add('following');
                        flash('Followed!', 'success');
                    } else {
                        btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Follow';
                        btn.classList.remove('following');
                        flash('Unfollowed.', 'info');
                    }
                } else {
                    flash(data.error || 'Error following user.', 'danger');
                    if (isFollowing) {
                        btn.innerHTML = '<i class="fa-solid fa-check"></i> Following';
                        btn.classList.add('following');
                    } else {
                        btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Follow';
                        btn.classList.remove('following');
                    }
                }
                btn.disabled = false;
            })
            .catch(function(error) {
                console.error('Error following user:', error);
                flash('Error following user.', 'danger');
                if (isFollowing) {
                    btn.innerHTML = '<i class="fa-solid fa-check"></i> Following';
                    btn.classList.add('following');
                } else {
                    btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Follow';
                    btn.classList.remove('following');
                }
                btn.disabled = false;
            });
        }
        
        // ===== DELETE REEL =====
        function deleteReel(reelId) {
            if (!confirm('Delete this reel? This cannot be undone.')) return;
            var csrf = getCsrfToken();
            if (!csrf) {
                flash('Session expired. Please refresh.', 'danger');
                return;
            }
            
            fetch('/api/reel/' + reelId, {
                method: 'DELETE',
                headers: { 'X-CSRFToken': csrf },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    flash('Reel deleted.', 'info');
                    var item = document.querySelector('.reel-item[data-reel-id="' + reelId + '"]');
                    if (item) item.remove();
                    if (document.querySelectorAll('.reel-item').length === 0) {
                        window.location.href = '/explore';
                    }
                } else {
                    flash(data.error || 'Error deleting reel.', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error deleting reel:', error);
                flash('Error deleting reel.', 'danger');
            });
        }
        
        // ===== KEYBOARD SHORTCUTS =====
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                if (document.getElementById('sharePanelReel').classList.contains('active')) {
                    closeSharePanelReel();
                }
            }
            if (e.key === 'm' || e.key === 'M') {
                var items = document.querySelectorAll('.reel-item');
                for (var i = 0; i < items.length; i++) {
                    var item = items[i];
                    var rect = item.getBoundingClientRect();
                    if (rect.top >= 0 && rect.top < window.innerHeight / 2) {
                        var reelId = item.dataset.reelId;
                        toggleReelMute(reelId);
                        break;
                    }
                }
            }
            if (e.key === 'l' || e.key === 'L') {
                var items = document.querySelectorAll('.reel-item');
                for (var i = 0; i < items.length; i++) {
                    var item = items[i];
                    var rect = item.getBoundingClientRect();
                    if (rect.top >= 0 && rect.top < window.innerHeight / 2) {
                        var reelId = item.dataset.reelId;
                        toggleReelLike(reelId);
                        createHeartAnimationReel(item);
                        break;
                    }
                }
            }
        });
        
        // ===== SCROLL TO REEL =====
        document.addEventListener('DOMContentLoaded', function() {
            var urlParams = new URLSearchParams(window.location.search);
            var reelId = urlParams.get('reel_id');
            if (reelId) {
                var targetItem = document.querySelector('.reel-item[data-reel-id="' + reelId + '"]');
                if (targetItem) {
                    var container = document.getElementById('reelsContainer');
                    setTimeout(function() {
                        container.scrollTo({ top: targetItem.offsetTop, behavior: 'smooth' });
                    }, 300);
                }
            }
        });
    </script>
</body>
</html>
'''
FEED_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>FlowUp - Feed</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background:#000; max-width:430px; margin:auto; height:100vh; overflow:hidden; position:relative; }
        
        .header {
            position:sticky;
            top:0;
            z-index:30;
            background:#000;
            display:flex;
            justify-content:space-between;
            align-items:center;
            padding:10px 16px;
            border-bottom:1px solid rgba(255,255,255,0.05);
            height:50px;
        }
        .header .logo {
            font-size:20px;
            font-weight:700;
            color:#fff;
            background:linear-gradient(45deg,#ff73d2,#d868ff);
            -webkit-background-clip:text;
            -webkit-text-fill-color:transparent;
        }
        .header .right-icons {
            display:flex;
            gap:16px;
            align-items:center;
        }
        .header .right-icons a {
            color:#fff;
            font-size:20px;
            text-decoration:none;
            opacity:0.8;
            transition:opacity 0.2s;
            position:relative;
        }
        .header .right-icons a:hover { opacity:1; }
        .header .right-icons a .badge {
            position:absolute;
            top:-6px;
            right:-8px;
            background:#ed4956;
            color:#fff;
            font-size:9px;
            border-radius:50%;
            width:18px;
            height:18px;
            display:flex;
            align-items:center;
            justify-content:center;
            font-weight:700;
        }
        
        .profile-pic-container {
            position:relative;
            width:36px;
            height:36px;
            flex-shrink:0;
        }
        .profile-pic-container img {
            width:100%;
            height:100%;
            border-radius:50%;
            object-fit:cover;
            border:2px solid #d868ff;
            display:block;
        }
        
        .feed-container {
            height:calc(100vh - 50px);
            overflow-y:scroll;
            scroll-behavior:smooth;
            scroll-snap-type:y mandatory;
            -webkit-overflow-scrolling:touch;
        }
        .feed-container::-webkit-scrollbar { display:none; }
        
        .stories-container {
            background:#000;
            padding:12px 0;
            border-bottom:1px solid rgba(255,255,255,0.05);
            overflow-x:auto;
            overflow-y:hidden;
            scrollbar-width:none;
            -webkit-overflow-scrolling:touch;
            flex-shrink:0;
        }
        .stories-container::-webkit-scrollbar { display:none; }
        .stories-wrapper {
            display:flex;
            gap:14px;
            padding:0 16px;
            min-width:max-content;
            align-items:center;
        }
        .story-item {
            display:flex;
            flex-direction:column;
            align-items:center;
            gap:4px;
            cursor:pointer;
            min-width:64px;
            flex-shrink:0;
            transition:transform 0.2s ease;
        }
        .story-item:active { transform:scale(0.92); }
        .story-avatar-wrapper {
            position:relative;
            width:60px;
            height:60px;
            flex-shrink:0;
        }
        .story-avatar {
            width:100%;
            height:100%;
            border-radius:50%;
            overflow:hidden;
            border:2px solid #333;
        }
        .story-avatar img {
            width:100%;
            height:100%;
            object-fit:cover;
            display:block;
        }
        .story-avatar.unviewed {
            border-color:#d868ff;
        }
        .story-avatar.viewed {
            border-color:#333;
        }
        .story-item.your-story .story-avatar {
            border-color:#d868ff;
        }
        .story-item:hover .story-avatar {
            border-color:#d868ff;
        }
        .story-username {
            font-size:10px;
            color:#888;
            text-align:center;
            max-width:60px;
            overflow:hidden;
            text-overflow:ellipsis;
            white-space:nowrap;
        }
        .story-add {
            position:absolute;
            bottom:-2px;
            right:-2px;
            width:22px;
            height:22px;
            background:#d868ff;
            border-radius:50%;
            display:flex;
            align-items:center;
            justify-content:center;
            border:2px solid #000;
            z-index:2;
        }
        .story-add i {
            font-size:11px;
            color:#fff;
        }
        
        .post-card {
            scroll-snap-align:start;
            scroll-snap-stop:always;
            position:relative;
            background:#000;
            overflow:hidden;
            display:flex;
            align-items:center;
            justify-content:center;
            min-height:calc(100vh - 50px);
            height:calc(100vh - 50px);
            cursor:pointer;
        }
        .post-media {
            width:100%;
            height:100%;
            object-fit:contain;
            background:#000;
            pointer-events:none;
        }
        .post-media.video-post { cursor:pointer; pointer-events:auto; }
        .video-wrapper {
            position:relative;
            width:100%;
            height:100%;
            background:#000;
            display:flex;
            align-items:center;
            justify-content:center;
        }
        .video-post {
            width:100%;
            height:100%;
            object-fit:contain;
            background:#000;
        }
        
        .post-header {
            position:absolute;
            bottom:120px;
            left:12px;
            z-index:15;
            display:flex;
            align-items:center;
            gap:8px;
            background:rgba(0,0,0,0.3);
            padding:3px 10px 3px 3px;
            border-radius:20px;
            backdrop-filter:blur(8px);
            pointer-events:auto;
        }
        .post-header .avatar {
            width:28px;
            height:28px;
            border-radius:50%;
            object-fit:cover;
            border:2px solid #d868ff;
            flex-shrink:0;
            cursor:pointer;
        }
        .post-header .username {
            font-weight:600;
            font-size:12px;
            color:#fff;
            text-shadow:0 1px 4px rgba(0,0,0,0.8);
            cursor:pointer;
        }
        .post-header .username:hover { text-decoration:underline; }
        
        .post-actions {
            position:absolute;
            bottom:130px;
            right:12px;
            z-index:15;
            display:flex;
            flex-direction:column;
            align-items:center;
            gap:10px;
            pointer-events:auto;
        }
        .post-actions button {
            background:rgba(0,0,0,0.4);
            backdrop-filter:blur(8px);
            border:1px solid rgba(255,255,255,0.06);
            border-radius:50%;
            width:38px;
            height:38px;
            display:flex;
            flex-direction:column;
            align-items:center;
            justify-content:center;
            color:#fff;
            font-size:16px;
            cursor:pointer;
            transition:all 0.2s;
            gap:1px;
            border:none;
        }
        .post-actions button:active { transform:scale(0.9); }
        .post-actions button:hover { background:rgba(255,255,255,0.12); }
        .post-actions button .count {
            font-size:9px;
            font-weight:600;
            color:rgba(255,255,255,0.6);
        }
        .post-actions .fa-solid.fa-heart { color:#ed4956; }
        .post-actions .fa-regular.fa-heart { color:#fff; }
        
        .post-caption {
            position:absolute;
            bottom:16px;
            left:12px;
            right:70px;
            z-index:15;
            color:#fff;
            font-size:12px;
            text-shadow:0 1px 4px rgba(0,0,0,0.8);
            background:rgba(0,0,0,0.25);
            padding:4px 10px;
            border-radius:6px;
            backdrop-filter:blur(4px);
            max-height:40px;
            overflow:hidden;
            white-space:nowrap;
            text-overflow:ellipsis;
            pointer-events:auto;
        }
        .post-caption strong {
            color:#fff;
            margin-right:4px;
            cursor:pointer;
            font-size:12px;
        }
        .post-caption strong:hover { text-decoration:underline; }
        
        .video-mute-btn {
            position:absolute;
            bottom:100px;
            right:12px;
            z-index:15;
            background:rgba(0,0,0,0.5);
            backdrop-filter:blur(8px);
            width:30px;
            height:30px;
            border-radius:50%;
            display:flex;
            align-items:center;
            justify-content:center;
            color:#fff;
            font-size:13px;
            cursor:pointer;
            border:1px solid rgba(255,255,255,0.08);
            transition:all 0.3s;
            pointer-events:auto;
        }
        .video-mute-btn:hover { background:rgba(255,255,255,0.15); }
        .video-mute-btn:active { transform:scale(0.9); }
        .video-mute-btn.muted { background:rgba(255,0,0,0.25); }
        .video-mute-btn.unmuted { background:rgba(0,255,0,0.15); }
        
        .heart-pop {
            position:absolute;
            top:50%;
            left:50%;
            transform:translate(-50%,-50%) scale(0);
            font-size:80px;
            z-index:20;
            pointer-events:none;
            animation:heartPop 0.6s ease forwards;
            color:#ed4956;
            text-shadow:0 2px 20px rgba(237,73,86,0.3);
        }
        @keyframes heartPop {
            0% { transform:translate(-50%,-50%) scale(0); opacity:1; }
            50% { transform:translate(-50%,-50%) scale(1.5); opacity:1; }
            100% { transform:translate(-50%,-50%) scale(1); opacity:0; }
        }
        
        .snap-indicator {
            position:absolute;
            bottom:8px;
            left:50%;
            transform:translateX(-50%);
            display:flex;
            gap:5px;
            z-index:10;
            background:rgba(0,0,0,0.3);
            padding:4px 10px;
            border-radius:12px;
            backdrop-filter:blur(4px);
            pointer-events:none;
        }
        .snap-indicator .dot {
            width:6px;
            height:6px;
            border-radius:50%;
            background:rgba(255,255,255,0.2);
            transition:all 0.3s ease;
        }
        .snap-indicator .dot.active {
            background:#d868ff;
            width:18px;
            border-radius:3px;
        }
        
        .no-posts {
            text-align:center;
            padding:60px 20px;
            color:#888;
            height:70vh;
            display:flex;
            flex-direction:column;
            justify-content:center;
            align-items:center;
        }
        .no-posts i {
            font-size:64px;
            color:#333;
            margin-bottom:16px;
        }
        .no-posts h3 {
            font-size:20px;
            margin-bottom:8px;
            color:#888;
        }
        .no-posts p { font-size:14px; color:#555; }
        
        .pagination {
            display:flex;
            justify-content:center;
            gap:8px;
            padding:16px;
            background:#000;
        }
        .pagination a {
            padding:6px 14px;
            background:rgba(255,255,255,0.05);
            color:#fff;
            border-radius:20px;
            text-decoration:none;
            font-size:13px;
            transition:background 0.3s;
        }
        .pagination a:hover { background:rgba(255,255,255,0.1); }
        .pagination a.active {
            background:linear-gradient(45deg,#ff73d2,#d868ff);
            color:#fff;
        }
        
        .bottom-nav {
            position:fixed;
            bottom:0;
            left:50%;
            transform:translateX(-50%);
            width:100%;
            max-width:430px;
            height:60px;
            background:linear-gradient(45deg,#ff73d2,#d868ff);
            display:flex;
            justify-content:space-around;
            align-items:center;
            border-radius:20px 20px 0 0;
            padding:0 12px;
            z-index:50;
        }
        .bottom-nav a {
            display:flex;
            align-items:center;
            justify-content:center;
            text-decoration:none;
            color:white;
            opacity:0.7;
            font-size:22px;
            transition:all 0.2s;
            position:relative;
        }
        .bottom-nav a.active { opacity:1; }
        .bottom-nav a:hover { opacity:1; }
        .bottom-nav a .nav-badge {
            position:absolute;
            top:-6px;
            right:-8px;
            background:#ed4956;
            color:white;
            font-size:8px;
            border-radius:50%;
            width:16px;
            height:16px;
            display:flex;
            align-items:center;
            justify-content:center;
            font-weight:700;
        }
        .plus-btn {
            width:52px;
            height:52px;
            border-radius:50%;
            background:#fff;
            display:flex;
            align-items:center;
            justify-content:center;
            margin-top:-26px;
            text-decoration:none;
            box-shadow:0 4px 15px rgba(0,0,0,0.3);
            transition:transform 0.3s ease;
        }
        .plus-btn:hover { transform:scale(1.1); }
        .plus-btn i { color:#000; font-size:26px; }
        .bottom-spacer { height:60px; }
        
        .flash-messages {
            position:fixed;
            top:60px;
            left:50%;
            transform:translateX(-50%);
            z-index:999;
            width:90%;
            max-width:400px;
        }
        .flash-message {
            padding:10px 16px;
            border-radius:10px;
            margin-bottom:6px;
            color:#fff;
            font-weight:500;
            text-align:center;
            animation:slideDown 0.3s ease;
        }
        .flash-message.success { background:#28a745; }
        .flash-message.danger { background:#dc3545; }
        .flash-message.warning { background:#ffc107; color:#333; }
        .flash-message.info { background:#17a2b8; }
        @keyframes slideDown {
            from { opacity:0; transform:translateY(-20px); }
            to { opacity:1; transform:translateY(0); }
        }
        
        /* Comment Panel */
        .comment-overlay{
            position:fixed;
            top:0;
            left:0;
            right:0;
            bottom:0;
            background:rgba(0,0,0,0.5);
            z-index:999;
            display:none;
        }
        .comment-overlay.active{
            display:block;
        }
        .comment-panel{
            position:fixed;
            bottom:0;
            left:50%;
            transform:translateX(-50%) translateY(100%);
            width:100%;
            max-width:430px;
            height:65vh;
            max-height:550px;
            background:#fff;
            border-radius:20px 20px 0 0;
            box-shadow:0 -10px 40px rgba(0,0,0,0.3);
            z-index:1000;
            display:flex;
            flex-direction:column;
            transition:transform 0.4s cubic-bezier(0.22,1,0.36,1);
            overflow:hidden;
        }
        .comment-panel.active{
            transform:translateX(-50%) translateY(0);
        }
        .panel-header{
            display:flex;
            justify-content:space-between;
            align-items:center;
            padding:14px 18px 10px;
            border-bottom:1px solid #f0f0f0;
            flex-shrink:0;
            background:#fff;
        }
        .panel-header-left{
            display:flex;
            align-items:center;
            gap:10px;
        }
        .panel-header-left h3{
            font-size:17px;
            font-weight:700;
            color:#262626;
            margin:0;
        }
        .panel-header-left .comment-count{
            font-size:13px;
            color:#8e8e8e;
            font-weight:400;
        }
        .close-panel{
            background:none;
            border:none;
            font-size:22px;
            cursor:pointer;
            color:#262626;
            padding:4px;
        }
        .close-panel:hover{
            transform:scale(1.1);
        }
        .close-btn{
            background:none;
            border:none;
            font-size:22px;
            cursor:pointer;
            color:#8e8e8e;
            padding:4px;
        }
        .close-btn:hover{
            color:#262626;
        }
        .panel-input-top{
            display:flex;
            align-items:center;
            gap:10px;
            padding:10px 14px;
            border-bottom:1px solid #f0f0f0;
            flex-shrink:0;
            background:#fafafa;
        }
        .panel-input-top .comment-avatar{
            width:30px;
            height:30px;
            border-radius:50%;
            object-fit:cover;
            flex-shrink:0;
        }
        .panel-input-top input{
            flex:1;
            padding:8px 14px;
            border:1px solid #e0e0e0;
            border-radius:20px;
            outline:none;
            font-size:14px;
            background:#fff;
        }
        .panel-input-top input:focus{
            border-color:#d868ff;
        }
        .panel-input-top button{
            background:linear-gradient(45deg,#ff73d2,#d868ff);
            color:white;
            border:none;
            border-radius:50%;
            width:34px;
            height:34px;
            cursor:pointer;
            font-size:14px;
            display:flex;
            align-items:center;
            justify-content:center;
            transition:transform 0.2s;
        }
        .panel-input-top button:hover{
            transform:scale(1.05);
        }
        .panel-input-top button:active{
            transform:scale(0.9);
        }
        .panel-input-top button:disabled{
            opacity:0.5;
            cursor:not-allowed;
        }
        .panel-comments{
            flex:1;
            overflow-y:auto;
            padding:10px 14px;
            background:#fff;
        }
        .panel-comments::-webkit-scrollbar{
            width:4px;
        }
        .panel-comments::-webkit-scrollbar-track{
            background:transparent;
        }
        .panel-comments::-webkit-scrollbar-thumb{
            background:#d868ff;
            border-radius:10px;
        }
        .loading-comments{
            text-align:center;
            color:#8e8e8e;
            padding:30px 0;
        }
        .loading-comments i{
            font-size:20px;
            display:block;
            margin-bottom:10px;
        }
        .comment-item{
            padding:8px 0;
            border-bottom:1px solid #f5f5f5;
            animation:commentSlideIn 0.3s ease;
        }
        .comment-item:last-child{
            border-bottom:none;
        }
        @keyframes commentSlideIn{
            from{opacity:0;transform:translateY(10px)}
            to{opacity:1;transform:translateY(0)}
        }
        .comment-item.reply{
            padding-left:30px;
            border-left:2px solid #d868ff;
            margin-left:8px;
        }
        .comment-user{
            display:flex;
            align-items:center;
            gap:8px;
        }
        .comment-user img{
            width:26px;
            height:26px;
            border-radius:50%;
            object-fit:cover;
        }
        .comment-user strong{
            font-size:12px;
            color:#262626;
        }
        .comment-user .comment-time{
            font-size:10px;
            color:#8e8e8e;
            font-weight:400;
        }
        .comment-text{
            font-size:13px;
            color:#262626;
            margin-left:34px;
            word-wrap:break-word;
            line-height:1.4;
        }
        .comment-actions{
            margin-left:34px;
            margin-top:3px;
            display:flex;
            gap:10px;
            align-items:center;
        }
        .comment-actions button{
            background:none;
            border:none;
            color:#8e8e8e;
            font-size:10px;
            cursor:pointer;
            padding:2px 4px;
        }
        .comment-actions button:hover{
            color:#262626;
        }
        .comment-actions .delete-comment{
            color:#ed4956;
        }
        .comment-actions .delete-comment:hover{
            color:#c0392b;
        }
        .comment-actions .reply-btn{
            color:#d868ff;
        }
        .comment-actions .reply-btn:hover{
            color:#b84ad8;
        }
        .panel-footer{
            padding:6px 14px;
            border-top:1px solid #f0f0f0;
            flex-shrink:0;
            background:#fff;
            min-height:34px;
        }
        #replyIndicator{
            display:none;
            font-size:12px;
            color:#262626;
        }
        #replyIndicator strong{
            color:#d868ff;
        }
        .cancel-reply{
            background:none;
            border:none;
            color:#ed4956;
            cursor:pointer;
            font-size:14px;
            margin-left:6px;
        }
        .no-comments{
            text-align:center;
            padding:30px 20px;
            color:#8e8e8e;
        }
        .no-comments i{
            font-size:40px;
            display:block;
            margin-bottom:12px;
            color:#e0e0e0;
        }
        .no-comments h4{
            font-size:15px;
            color:#262626;
            margin-bottom:2px;
        }
        .load-more-comments{
            text-align:center;
            padding:8px 0;
        }
        .load-more-btn{
            background:none;
            border:none;
            color:#d868ff;
            cursor:pointer;
            font-size:13px;
            font-weight:600;
            padding:6px 12px;
        }
        .load-more-btn:hover{
            text-decoration:underline;
        }

        /* Share Panel */
        .share-overlay {
            position:fixed;
            top:0; left:0; right:0; bottom:0;
            background:rgba(0,0,0,0.5);
            z-index:999;
            display:none;
        }
        .share-panel {
            position:fixed;
            bottom:0;
            left:50%;
            transform:translateX(-50%) translateY(100%);
            width:100%;
            max-width:430px;
            background:#fff;
            border-radius:20px 20px 0 0;
            box-shadow:0 -10px 40px rgba(0,0,0,0.3);
            z-index:1000;
            padding:20px 20px 30px;
            transition:transform 0.4s cubic-bezier(0.22,1,0.36,1);
        }
        .share-panel.active {
            transform:translateX(-50%) translateY(0);
        }
        .share-header {
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:20px;
        }
        .share-header h3 {
            font-size:18px;
            font-weight:700;
            color:#262626;
        }
        .share-header h3 i {
            color:#d868ff;
            margin-right:8px;
        }
        .close-share {
            background:none;
            border:none;
            font-size:24px;
            cursor:pointer;
            color:#8e8e8e;
            padding:4px;
        }
        .close-share:hover {
            color:#262626;
        }
        .share-options {
            display:grid;
            grid-template-columns:repeat(3,1fr);
            gap:12px;
            margin-bottom:20px;
        }
        .share-option {
            display:flex;
            flex-direction:column;
            align-items:center;
            gap:6px;
            padding:16px 8px;
            background:#f8f8f8;
            border:none;
            border-radius:12px;
            cursor:pointer;
            transition:all 0.2s;
            font-family:inherit;
        }
        .share-option:hover {
            background:#f0f0f0;
            transform:translateY(-2px);
        }
        .share-option:active {
            transform:scale(0.95);
        }
        .share-option i {
            font-size:28px;
        }
        .share-option span {
            font-size:11px;
            color:#262626;
            font-weight:500;
        }
        .share-actions {
            display:flex;
            gap:10px;
            border-top:1px solid #f0f0f0;
            padding-top:16px;
        }
        .share-actions button {
            flex:1;
            padding:10px;
            border:none;
            border-radius:12px;
            font-size:14px;
            font-weight:600;
            cursor:pointer;
            display:flex;
            align-items:center;
            justify-content:center;
            gap:8px;
            transition:all 0.2s;
        }
        .share-actions button:active {
            transform:scale(0.95);
        }
        .share-save-btn {
            background:#f0f0f0;
            color:#262626;
        }
        .share-save-btn:hover {
            background:#e0e0e0;
        }
        .share-save-btn.saved {
            background:#d868ff;
            color:white;
        }
        .share-report-btn {
            background:#fee2e2;
            color:#dc2626;
        }
        .share-report-btn:hover {
            background:#fecaca;
        }
        
        @media(max-width:430px) {
            .post-actions button { width:34px; height:34px; font-size:14px; }
            .post-actions { gap:8px; bottom:115px; right:10px; }
            .post-caption { font-size:11px; padding:3px 8px; bottom:12px; right:60px; }
            .post-header { bottom:100px; left:10px; padding:2px 8px 2px 2px; gap:6px; }
            .post-header .avatar { width:24px; height:24px; }
            .post-header .username { font-size:11px; }
            .video-mute-btn { width:26px; height:26px; font-size:11px; bottom:85px; right:10px; }
            .story-avatar-wrapper { width:52px; height:52px; }
            .story-item { min-width:56px; }
            .story-username { font-size:9px; max-width:52px; }
            .bottom-nav { height:55px; }
            .plus-btn { width:46px; height:46px; margin-top:-23px; }
            .plus-btn i { font-size:22px; }
            .snap-indicator { bottom:4px; padding:3px 8px; gap:4px; }
            .snap-indicator .dot { width:5px; height:5px; }
            .snap-indicator .dot.active { width:14px; }
        }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    
    <div class="header">
        <span class="logo">FlowUp</span>
        <div class="right-icons">
            <a href="{{ url_for('search_page') }}">
                <i class="fa-solid fa-magnifying-glass"></i>
            </a>
            <a href="{{ url_for('notifications') }}">
                <i class="fa-regular fa-bell"></i>
                {% if total_unread > 0 %}
                <span class="badge">{{ total_unread }}</span>
                {% endif %}
            </a>
            <a href="{{ url_for('profile', username=current_user.username) }}" class="profile-pic-container">
                <img src="/static/uploads/{{ current_user.profile_pic }}" 
                     onerror="this.src='/static/default.svg'"
                     alt="{{ current_user.username }}">
            </a>
        </div>
    </div>
    
    <div class="feed-container" id="feedContainer">
        <div class="stories-container">
            <div class="stories-wrapper" id="storiesWrapper">
                <div class="story-item your-story" onclick="window.location.href='/profile/{{ current_user.username }}'">
                    <div class="story-avatar-wrapper">
                        <div class="story-avatar viewed">
                            <img src="/static/uploads/{{ current_user.profile_pic }}" 
                                 onerror="this.src='/static/default.svg'"
                                 alt="{{ current_user.username }}">
                        </div>
                    </div>
                    <span class="story-username">You</span>
                </div>
            </div>
        </div>
        
        {% if not posts %}
        <div class="no-posts">
            <i class="fa-regular fa-image"></i>
            <h3>No posts yet</h3>
            <p>Follow people or upload your first post!</p>
        </div>
        {% else %}
            {% for post in posts %}
            <div class="post-card" id="post-{{ post.id }}" data-post-id="{{ post.id }}">
                {% if post.media_type == 'video' %}
                <div class="video-wrapper">
                    <video class="post-media video-post" id="video-{{ post.id }}"
                           muted playsinline preload="auto" loop autoplay
                           poster="/static/uploads/{{ post.id }}_thumb.jpg"
                           data-post-id="{{ post.id }}">
                        <source src="/{{ post.media_url }}" type="video/mp4">
                        <source src="/{{ post.media_url }}" type="video/webm">
                    </video>
                    <div class="video-mute-btn muted" id="muteBtn-{{ post.id }}" 
                         onclick="event.stopPropagation(); toggleMute({{ post.id }})">
                        <i class="fa-solid fa-volume-xmark"></i>
                    </div>
                </div>
                {% else %}
                <img class="post-media" src="/{{ post.media_url }}"
                     loading="lazy" onerror="this.src='/static/default_post.svg'">
                {% endif %}
                
                <div class="post-header">
                    <img class="avatar" src="/static/uploads/{{ post.profile_pic }}"
                         onerror="this.src='/static/default.svg'"
                         onclick="event.stopPropagation(); window.location.href='/profile/{{ post.username }}'">
                    <span class="username" onclick="event.stopPropagation(); window.location.href='/profile/{{ post.username }}'">
                        {{ post.username|e }}
                    </span>
                </div>
                
                <div class="post-actions">
                    <button onclick="event.stopPropagation(); toggleLike({{ post.id }})">
                        {% if post.liked_by_user %}
                        <i class="fa-solid fa-heart" id="likeIcon-{{ post.id }}" style="color:#ed4956;"></i>
                        {% else %}
                        <i class="fa-regular fa-heart" id="likeIcon-{{ post.id }}"></i>
                        {% endif %}
                        <span class="count" id="likeCount-{{ post.id }}">{{ post.like_count }}</span>
                    </button>
                    <button onclick="event.stopPropagation(); openCommentPanel({{ post.id }})">
                        <i class="fa-regular fa-comment"></i>
                        <span class="count" id="commentCount-{{ post.id }}">{{ post.comment_count }}</span>
                    </button>
                    <button onclick="event.stopPropagation(); openSharePanel({{ post.id }})">
                        <i class="fa-regular fa-paper-plane"></i>
                    </button>
                </div>
                
                <div class="post-caption">
                    <strong onclick="event.stopPropagation(); window.location.href='/profile/{{ post.username }}'">
                        {{ post.username|e }}
                    </strong>
                    {{ post.caption|e or '' }}
                </div>
                
                <div class="snap-indicator" id="snapIndicator-{{ post.id }}">
                    <span class="dot active"></span>
                    <span class="dot"></span>
                    <span class="dot"></span>
                </div>
            </div>
            <div style="height:2px; background:rgba(255,255,255,0.03);"></div>
            {% endfor %}
            
            {% if total_pages and total_pages > 1 %}
            <div class="pagination">
                {% if page > 1 %}
                <a href="?page={{ page-1 }}"><i class="fa-solid fa-chevron-left"></i></a>
                {% endif %}
                {% for p in range(1, total_pages+1) %}
                    {% if p == page %}
                    <a href="?page={{ p }}" class="active">{{ p }}</a>
                    {% elif p <= 3 or p > total_pages-2 %}
                    <a href="?page={{ p }}">{{ p }}</a>
                    {% elif p == 4 and total_pages > 5 %}
                    <span style="color:#555;">...</span>
                    {% endif %}
                {% endfor %}
                {% if page < total_pages %}
                <a href="?page={{ page+1 }}"><i class="fa-solid fa-chevron-right"></i></a>
                {% endif %}
            </div>
            {% endif %}
        {% endif %}
        
        <div class="bottom-spacer"></div>
    </div>
    
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}" class="active"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}">
            <i class="fa-regular fa-bell"></i>
            {% if total_unread > 0 %}
            <span class="nav-badge">{{ total_unread }}</span>
            {% endif %}
        </a>
        <a href="{{ url_for('profile', username=current_user.username) }}">
            <i class="fa-regular fa-user"></i>
        </a>
    </div>
    
    <!-- Comment Panel -->
    <div class="comment-overlay" id="commentOverlay" onclick="closeCommentPanel()"></div>
    <div class="comment-panel" id="commentPanel">
        <div class="panel-header">
            <div class="panel-header-left">
                <button class="close-panel" onclick="closeCommentPanel()">
                    <i class="fa-solid fa-chevron-down"></i>
                </button>
                <h3>Comments</h3>
                <span id="commentCountPanel" class="comment-count">0</span>
            </div>
            <button onclick="closeCommentPanel()" class="close-btn">
                <i class="fa-solid fa-xmark"></i>
            </button>
        </div>
        <div class="panel-input-top">
            <img id="commentUserAvatar" src="/static/uploads/{{ current_user.profile_pic }}"
                 onerror="this.src='/static/default.svg'" class="comment-avatar">
            <input type="text" id="commentInput" placeholder="Write a comment..." maxlength="500">
            <button onclick="submitComment()" id="commentSubmitBtn">
                <i class="fa-regular fa-paper-plane"></i>
            </button>
        </div>
        <div class="panel-comments" id="panelComments">
            <div class="loading-comments">
                <i class="fa-solid fa-spinner fa-spin"></i> Loading comments...
            </div>
        </div>
        <div class="panel-footer">
            <span id="replyIndicator">
                Replying to <strong id="replyToName"></strong>
                <button onclick="cancelReply()" class="cancel-reply"><i class="fa-solid fa-xmark"></i></button>
            </span>
        </div>
        <input type="hidden" id="replyTo" value="">
        <input type="hidden" id="currentPostId" value="">
    </div>
    
    <!-- Share Panel -->
    <div class="share-overlay" id="shareOverlay" onclick="closeSharePanel()"></div>
    <div class="share-panel" id="sharePanel">
        <div class="share-header">
            <h3><i class="fa-regular fa-share-from-square"></i> Share</h3>
            <button onclick="closeSharePanel()" class="close-share"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="share-content">
            <div class="share-options">
                <button onclick="shareAction('copy')" class="share-option"><i class="fa-solid fa-link"></i><span>Copy Link</span></button>
                <button onclick="shareAction('whatsapp')" class="share-option"><i class="fa-brands fa-whatsapp" style="color:#25D366;"></i><span>WhatsApp</span></button>
                <button onclick="shareAction('twitter')" class="share-option"><i class="fa-brands fa-twitter" style="color:#1DA1F2;"></i><span>Twitter</span></button>
                <button onclick="shareAction('facebook')" class="share-option"><i class="fa-brands fa-facebook" style="color:#1877F2;"></i><span>Facebook</span></button>
                <button onclick="shareAction('instagram')" class="share-option"><i class="fa-brands fa-instagram" style="color:#E4405F;"></i><span>Instagram</span></button>
                <button onclick="shareAction('telegram')" class="share-option"><i class="fa-brands fa-telegram" style="color:#0088CC;"></i><span>Telegram</span></button>
            </div>
            <div class="share-actions">
                <button onclick="shareAction('save')" class="share-save-btn"><i class="fa-regular fa-bookmark"></i> Save Post</button>
                <button onclick="shareAction('report')" class="share-report-btn"><i class="fa-regular fa-flag"></i> Report</button>
            </div>
        </div>
    </div>
    
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    
    <script>
        // ===== CSRF TOKEN =====
        function getCsrfToken() {
            var el = document.getElementById('csrf_token');
            if (!el) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.id = 'csrf_token';
                input.value = '{{ csrf_token() }}';
                document.body.appendChild(input);
                return input.value;
            }
            return el.value;
        }
        
        // ===== FLASH MESSAGES =====
        function flash(message, type) {
            var container = document.querySelector('.flash-messages');
            if (!container) {
                container = document.createElement('div');
                container.className = 'flash-messages';
                document.body.prepend(container);
            }
            var div = document.createElement('div');
            div.className = 'flash-message ' + (type || 'info');
            div.textContent = message;
            container.appendChild(div);
            setTimeout(function() {
                div.style.transition = 'opacity 0.5s';
                div.style.opacity = '0';
                setTimeout(function() { div.remove(); }, 500);
            }, 3000);
        }
        
        // ===== LIKE FUNCTION =====
        function toggleLike(postId) {
            var csrf = getCsrfToken();
            if (!csrf) {
                flash('Session expired. Please refresh.', 'danger');
                return;
            }
            var icon = document.getElementById('likeIcon-' + postId);
            var countSpan = document.getElementById('likeCount-' + postId);
            if (!icon || !countSpan) {
                console.error('Like elements not found for post:', postId);
                return;
            }
            
            var isLiked = icon.classList.contains('fa-solid');
            var currentCount = parseInt(countSpan.textContent) || 0;
            
            if (isLiked) {
                icon.className = 'fa-regular fa-heart';
                icon.style.color = '';
                countSpan.textContent = Math.max(0, currentCount - 1);
            } else {
                icon.className = 'fa-solid fa-heart';
                icon.style.color = '#ed4956';
                countSpan.textContent = currentCount + 1;
                createHeartAnimation(postId);
            }
            
            fetch('/api/like/' + postId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) {
                if (!response.ok) throw new Error('Server error: ' + response.status);
                return response.json();
            })
            .then(function(data) {
                if (data.success) {
                    if (data.liked) {
                        icon.className = 'fa-solid fa-heart';
                        icon.style.color = '#ed4956';
                    } else {
                        icon.className = 'fa-regular fa-heart';
                        icon.style.color = '';
                    }
                    countSpan.textContent = data.like_count;
                } else {
                    if (isLiked) {
                        icon.className = 'fa-solid fa-heart';
                        icon.style.color = '#ed4956';
                        countSpan.textContent = currentCount + 1;
                    } else {
                        icon.className = 'fa-regular fa-heart';
                        icon.style.color = '';
                        countSpan.textContent = currentCount;
                    }
                    flash('Error liking post. Please try again.', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Like error:', error);
                if (isLiked) {
                    icon.className = 'fa-solid fa-heart';
                    icon.style.color = '#ed4956';
                    countSpan.textContent = currentCount + 1;
                } else {
                    icon.className = 'fa-regular fa-heart';
                    icon.style.color = '';
                    countSpan.textContent = currentCount;
                }
                flash('Network error. Please check your connection.', 'danger');
            });
        }
        
        function createHeartAnimation(postId) {
            var card = document.getElementById('post-' + postId);
            if (!card) return;
            var heart = document.createElement('div');
            heart.className = 'heart-pop';
            heart.textContent = '❤️';
            card.appendChild(heart);
            setTimeout(function() { heart.remove(); }, 700);
        }
        
        // Double tap to like
        document.querySelectorAll('.post-card').forEach(function(card) {
            var lastTap = 0;
            var tapTimeout = null;
            card.addEventListener('click', function(e) {
                if (e.target.closest('button') || e.target.closest('a') ||
                    e.target.closest('.post-actions') || e.target.closest('.post-header') ||
                    e.target.closest('.video-mute-btn') || e.target.closest('.post-caption')) {
                    return;
                }
                var now = Date.now();
                var timeSinceLastTap = now - lastTap;
                var postId = this.dataset.postId;
                if (timeSinceLastTap < 500 && timeSinceLastTap > 0) {
                    e.preventDefault();
                    toggleLike(postId);
                    createHeartAnimation(postId);
                    lastTap = 0;
                    if (tapTimeout) { clearTimeout(tapTimeout); tapTimeout = null; }
                } else {
                    lastTap = now;
                    if (tapTimeout) { clearTimeout(tapTimeout); }
                    tapTimeout = setTimeout(function() { lastTap = 0; tapTimeout = null; }, 500);
                }
            });
        });
        
        // ===== COMMENT FUNCTIONS =====
        var currentPostId = null;
        var commentPage = 1;
        var hasMoreComments = true;
        var isLoadingComments = false;
        
        function openCommentPanel(postId) {
            currentPostId = postId;
            document.getElementById('currentPostId').value = postId;
            document.getElementById('replyTo').value = '';
            document.getElementById('replyIndicator').style.display = 'none';
            document.getElementById('commentInput').value = '';
            document.getElementById('commentSubmitBtn').disabled = false;
            
            var panel = document.getElementById('commentPanel');
            var overlay = document.getElementById('commentOverlay');
            overlay.style.display = 'block';
            overlay.classList.add('active');
            panel.classList.add('active');
            document.body.style.overflow = 'hidden';
            
            commentPage = 1;
            hasMoreComments = true;
            loadComments(postId, 1);
            setTimeout(function() { document.getElementById('commentInput').focus(); }, 400);
        }
        
        function closeCommentPanel() {
            var panel = document.getElementById('commentPanel');
            var overlay = document.getElementById('commentOverlay');
            panel.classList.remove('active');
            overlay.classList.remove('active');
            overlay.style.display = 'none';
            document.body.style.overflow = '';
            currentPostId = null;
        }
        
        function loadComments(postId, page) {
            if (isLoadingComments || !hasMoreComments) return;
            isLoadingComments = true;
            var container = document.getElementById('panelComments');
            if (page === 1) {
                container.innerHTML = '<div class="loading-comments"><i class="fa-solid fa-spinner fa-spin"></i> Loading comments...</div>';
            }
            fetch('/api/comments/' + postId + '?page=' + page + '&per_page=20')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    isLoadingComments = false;
                    var countSpan = document.getElementById('commentCountPanel');
                    if (data.total !== undefined) countSpan.textContent = data.total;
                    if (page === 1) container.innerHTML = '';
                    if (!data.comments || data.comments.length === 0) {
                        if (page === 1) {
                            container.innerHTML = '<div class="no-comments"><i class="fa-regular fa-comment-dots"></i><h4>No comments yet</h4><p>Be the first to comment!</p></div>';
                        }
                        hasMoreComments = false;
                        return;
                    }
                    if (data.comments.length < 20) hasMoreComments = false;
                    data.comments.forEach(function(c) {
                        var div = document.createElement('div');
                        div.className = 'comment-item' + (c.parent_id ? ' reply' : '');
                        div.id = 'comment-' + c.id;
                        var isOwner = c.user_id === {{ current_user.id }};
                        var deleteBtn = isOwner ? '<button onclick="deleteComment(' + c.id + ')" class="delete-comment"><i class="fa-regular fa-trash-can"></i></button>' : '';
                        div.innerHTML = 
                            '<div class="comment-user"><img src="/static/uploads/' + (c.profile_pic || 'default.svg') + '" onerror="this.src=\'/static/default.svg\'"><strong>' + escapeHtml(c.username) + '</strong><span class="comment-time">' + formatTime(c.created_at) + '</span></div>' +
                            '<div class="comment-text">' + escapeHtml(c.text) + '</div>' +
                            '<div class="comment-actions"><button onclick="setReplyTo(' + c.id + ', \'' + escapeHtml(c.username) + '\')" class="reply-btn"><i class="fa-regular fa-reply"></i> Reply</button>' + deleteBtn + '</div>';
                        container.appendChild(div);
                    });
                    if (hasMoreComments) {
                        var loadMore = document.createElement('div');
                        loadMore.className = 'load-more-comments';
                        loadMore.innerHTML = '<button onclick="loadMoreComments()" class="load-more-btn">Load more comments</button>';
                        container.appendChild(loadMore);
                    }
                })
                .catch(function(error) {
                    console.error('Error loading comments:', error);
                    isLoadingComments = false;
                    if (page === 1) {
                        container.innerHTML = '<div class="no-comments" style="color:#dc3545;">Error loading comments. Please try again.</div>';
                    }
                });
        }
        
        function loadMoreComments() {
            if (!hasMoreComments || isLoadingComments) return;
            commentPage++;
            loadComments(currentPostId, commentPage);
        }
        
        function submitComment() {
            var postId = parseInt(document.getElementById('currentPostId').value);
            var text = document.getElementById('commentInput').value.trim();
            var replyTo = document.getElementById('replyTo').value;
            var csrf = getCsrfToken();
            if (!text || !postId) { flash('Please write a comment.', 'warning'); return; }
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            
            var btn = document.getElementById('commentSubmitBtn');
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
            btn.disabled = true;
            
            fetch('/api/comment', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    post_id: postId,
                    text: text,
                    reply_to: replyTo ? parseInt(replyTo) : null
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    document.getElementById('commentInput').value = '';
                    document.getElementById('replyTo').value = '';
                    document.getElementById('replyIndicator').style.display = 'none';
                    commentPage = 1;
                    hasMoreComments = true;
                    loadComments(postId, 1);
                    var countSpan = document.getElementById('commentCount-' + postId);
                    if (countSpan) countSpan.textContent = parseInt(countSpan.textContent) + 1;
                    flash('Comment posted!', 'success');
                } else {
                    flash(data.error || 'Error posting comment', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error posting comment:', error);
                flash('Error posting comment. Please try again.', 'danger');
            })
            .finally(function() {
                btn.innerHTML = '<i class="fa-regular fa-paper-plane"></i>';
                btn.disabled = false;
            });
        }
        
        function setReplyTo(commentId, username) {
            document.getElementById('replyTo').value = commentId;
            document.getElementById('replyToName').textContent = username;
            document.getElementById('replyIndicator').style.display = 'block';
            document.getElementById('commentInput').value = '@' + username + ' ';
            document.getElementById('commentInput').focus();
        }
        
        function cancelReply() {
            document.getElementById('replyTo').value = '';
            document.getElementById('replyIndicator').style.display = 'none';
            document.getElementById('commentInput').value = '';
        }
        
        function deleteComment(commentId) {
            if (!confirm('Delete this comment?')) return;
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            fetch('/api/comment/' + commentId, {
                method: 'DELETE',
                headers: { 'X-CSRFToken': csrf },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    var commentEl = document.getElementById('comment-' + commentId);
                    if (commentEl) commentEl.remove();
                    flash('Comment deleted.', 'info');
                } else {
                    flash(data.error || 'Error deleting comment', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error deleting comment:', error);
                flash('Error deleting comment. Please try again.', 'danger');
            });
        }
        
        document.getElementById('commentInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                submitComment();
            }
        });
        
        // ===== SHARE FUNCTIONS =====
        function openSharePanel(postId) {
            var panel = document.getElementById('sharePanel');
            var overlay = document.getElementById('shareOverlay');
            panel.dataset.postId = postId;
            panel.dataset.url = window.location.origin + '/post/' + postId;
            overlay.style.display = 'block';
            panel.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
        
        function closeSharePanel() {
            var overlay = document.getElementById('shareOverlay');
            var panel = document.getElementById('sharePanel');
            overlay.style.display = 'none';
            panel.classList.remove('active');
            document.body.style.overflow = '';
        }
        
        function shareAction(action) {
            var panel = document.getElementById('sharePanel');
            var url = panel ? panel.dataset.url : window.location.origin;
            var postId = panel ? panel.dataset.postId : null;
            
            switch(action) {
                case 'copy':
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(url).then(function() {
                            flash('Link copied to clipboard!', 'success');
                            closeSharePanel();
                        }).catch(function() { copyLinkFallback(url); });
                    } else {
                        copyLinkFallback(url);
                    }
                    break;
                case 'whatsapp':
                    window.open('https://wa.me/?text=' + encodeURIComponent('Check out this post on FlowUp! ' + url), '_blank');
                    closeSharePanel();
                    break;
                case 'twitter':
                    window.open('https://twitter.com/intent/tweet?text=' + encodeURIComponent('Check out this post on FlowUp!') + '&url=' + encodeURIComponent(url), '_blank');
                    closeSharePanel();
                    break;
                case 'facebook':
                    window.open('https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url), '_blank');
                    closeSharePanel();
                    break;
                case 'instagram':
                    flash('Open Instagram app and paste this link: ' + url, 'info');
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(url);
                    }
                    closeSharePanel();
                    break;
                case 'telegram':
                    window.open('https://t.me/share/url?url=' + encodeURIComponent(url) + '&text=' + encodeURIComponent('Check out this post on FlowUp!'), '_blank');
                    closeSharePanel();
                    break;
                case 'save':
                    if (postId) toggleSavePost(postId);
                    closeSharePanel();
                    break;
                case 'report':
                    if (postId) reportPost(postId);
                    closeSharePanel();
                    break;
            }
        }
        
        function copyLinkFallback(url) {
            var textarea = document.createElement('textarea');
            textarea.value = url;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                flash('Link copied to clipboard!', 'success');
                closeSharePanel();
            } catch(err) {
                flash('Failed to copy link.', 'warning');
            }
            document.body.removeChild(textarea);
        }
        
        function toggleSavePost(postId) {
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            
            fetch('/api/save/' + postId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    if (data.saved) {
                        flash('Post saved!', 'success');
                    } else {
                        flash('Post unsaved.', 'info');
                    }
                } else {
                    flash(data.error || 'Error saving post', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error saving post:', error);
                flash('Error saving post. Please try again.', 'danger');
            });
        }
        
        function reportPost(postId) {
            if (!confirm('Report this post? This will be reviewed by moderators.')) return;
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            
            fetch('/api/report/' + postId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    flash('Post reported. Thank you for helping keep our community safe.', 'success');
                } else {
                    flash(data.error || 'Error reporting post', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error reporting post:', error);
                flash('Error reporting post. Please try again.', 'danger');
            });
        }
        
        // ===== VIDEO MUTE =====
        function toggleMute(postId) {
            var video = document.getElementById('video-' + postId);
            if (!video) return;
            video.muted = !video.muted;
            var muteBtn = document.getElementById('muteBtn-' + postId);
            if (muteBtn) {
                if (video.muted) {
                    muteBtn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i>';
                    muteBtn.className = 'video-mute-btn muted';
                } else {
                    muteBtn.innerHTML = '<i class="fa-solid fa-volume-high"></i>';
                    muteBtn.className = 'video-mute-btn unmuted';
                }
            }
        }
        
        // ===== VIDEO INIT =====
        var initializedVideos = new Set();
        
        function initVideo(video) {
            if (!video || initializedVideos.has(video.id)) return;
            var postId = video.dataset.postId;
            if (!postId) return;
            
            video.muted = true;
            video.playsInline = true;
            video.load();
            
            video.addEventListener('canplay', function() {
                video.play().catch(function() {});
            });
            
            if (video.readyState >= 3) {
                video.play().catch(function() {});
            }
            
            video.addEventListener('click', function(e) {
                e.stopPropagation();
                toggleMute(postId);
            });
            
            video.addEventListener('ended', function() {
                video.currentTime = 0;
                video.play().catch(function() {});
            });
            
            initializedVideos.add(video.id);
            
            var observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    if (entry.isIntersecting) {
                        video.play().catch(function() {});
                    } else {
                        video.pause();
                    }
                });
            }, { threshold: 0.3 });
            observer.observe(video);
        }
        
        function initAllVideos() {
            document.querySelectorAll('.video-post').forEach(function(video) {
                initVideo(video);
            });
        }
        
        // ===== SNAP INDICATOR =====
        function updateSnapIndicator() {
            var container = document.getElementById('feedContainer');
            var cards = container.querySelectorAll('.post-card');
            if (cards.length === 0) return;
            var scrollTop = container.scrollTop;
            var cardHeight = cards[0].offsetHeight;
            var currentIndex = Math.round(scrollTop / cardHeight);
            cards.forEach(function(card, index) {
                var indicator = card.querySelector('.snap-indicator');
                if (!indicator) return;
                var dots = indicator.querySelectorAll('.dot');
                dots.forEach(function(dot, dotIndex) {
                    if (dotIndex === 0 && index === currentIndex) {
                        dot.classList.add('active');
                    } else if (dotIndex === 1 && (index === currentIndex + 1 || (index === 0 && currentIndex === cards.length - 1))) {
                        dot.classList.add('active');
                    } else if (dotIndex === 2 && (index === currentIndex + 2 || (index === 0 && currentIndex === cards.length - 1))) {
                        dot.classList.add('active');
                    } else {
                        dot.classList.remove('active');
                    }
                });
            });
        }
        
        var feedContainer = document.getElementById('feedContainer');
        if (feedContainer) {
            feedContainer.addEventListener('scroll', function() {
                updateSnapIndicator();
            });
            window.addEventListener('resize', function() {
                updateSnapIndicator();
            });
            setTimeout(updateSnapIndicator, 500);
        }
        
        // ===== UTILITY FUNCTIONS =====
        function escapeHtml(text) {
            if (!text) return '';
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatTime(timestamp) {
            var date = new Date(timestamp);
            var now = new Date();
            var diff = Math.floor((now - date) / 1000);
            if (diff < 60) return 'Just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h';
            if (diff < 604800) return Math.floor(diff / 86400) + 'd';
            return date.toLocaleDateString();
        }
        
        // ===== KEYBOARD SHORTCUTS =====
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                if (document.getElementById('commentPanel').classList.contains('active')) {
                    closeCommentPanel();
                }
                if (document.getElementById('sharePanel').classList.contains('active')) {
                    closeSharePanel();
                }
            }
        });
        
        // ===== AUTO DISMISS FLASH =====
        setTimeout(function() {
            document.querySelectorAll('.flash-message').forEach(function(el) {
                el.style.transition = 'opacity 0.5s';
                el.style.opacity = '0';
                setTimeout(function() { el.remove(); }, 500);
            });
        }, 4000);
        
        // ===== INIT =====
        document.addEventListener('DOMContentLoaded', function() {
            console.log('🚀 Feed loaded');
            setTimeout(initAllVideos, 500);
        });
        
        if (document.readyState === 'complete' || document.readyState === 'interactive') {
            setTimeout(initAllVideos, 500);
        }
    </script>
</body>
</html>
'''
UPLOAD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Upload - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
        html,body { width:100%; height:100%; overflow:hidden; background:#000; touch-action:none; }
        #app { position:fixed; inset:0; overflow:hidden; background:#111; }
        #videoContainer { position:absolute; inset:0; overflow:hidden; z-index:10; background:#000; }
        #video, #previewMedia { position:absolute; inset:0; width:100%; height:100%; object-fit:cover; transform-origin:center center; }
        #previewMedia { display:none; z-index:2; background:#000; object-fit:contain; }
        .grid { position:absolute; inset:0; display:grid; grid-template-columns:1fr 1fr 1fr; grid-template-rows:1fr 1fr 1fr; pointer-events:none; z-index:5; opacity:0.25; transition:opacity 0.3s ease; }
        .grid.hidden { display:none !important; }
        .grid div { border:1px solid rgba(255,255,255,0.1); }
        #backBtn { position:absolute; top:20px; left:20px; z-index:25; width:44px; height:44px; border-radius:50%; border:2px solid rgba(255,255,255,0.3); background:rgba(0,0,0,0.6); backdrop-filter:blur(8px); color:white; font-size:20px; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:0.3s ease; text-decoration:none; }
        #backBtn:hover { background:rgba(255,255,255,0.15); transform:scale(1.05); }
        #backBtn:active { transform:scale(0.9); }
        #cancelBtn { position:absolute; top:20px; right:20px; z-index:25; width:44px; height:44px; border-radius:50%; border:2px solid rgba(255,255,255,0.3); background:rgba(0,0,0,0.6); backdrop-filter:blur(8px); color:white; font-size:22px; cursor:pointer; display:none; align-items:center; justify-content:center; transition:0.3s ease; }
        #cancelBtn:hover { background:rgba(255,0,0,0.3); border-color:#ff4444; transform:scale(1.1); }
        #cancelBtn:active { transform:scale(0.85); }
        .top { position:absolute; top:0; left:0; right:0; padding:18px 16px; display:flex; justify-content:space-between; z-index:20; background:linear-gradient(180deg,rgba(0,0,0,0.5) 0%,transparent 100%); pointer-events:none; }
        .top .btn { pointer-events:auto; }
        .bottom { position:absolute; bottom:0; left:0; right:0; padding:12px 16px 20px; display:flex; flex-direction:column; gap:10px; z-index:20; background:linear-gradient(0deg,rgba(0,0,0,0.8) 0%,transparent 100%); pointer-events:none; }
        .bottom>* { pointer-events:auto; }
        .btn { border:none; color:#fff; padding:8px 16px; border-radius:40px; background:rgba(0,0,0,0.5); backdrop-filter:blur(6px); font-size:14px; font-weight:500; transition:0.2s ease; box-shadow:0 2px 10px rgba(0,0,0,0.3); cursor:pointer; }
        .btn:active { transform:scale(0.93); opacity:0.7; }
        .controls { display:flex; justify-content:space-around; align-items:center; gap:8px; flex-wrap:wrap; }
        .capture-group { display:flex; gap:12px; align-items:center; }
        .capture-btn { width:60px; height:60px; border-radius:50%; border:3px solid white; background:rgba(255,255,255,0.1); backdrop-filter:blur(4px); cursor:pointer; display:flex; align-items:center; justify-content:center; transition:0.15s; position:relative; }
        .capture-btn:active { transform:scale(0.85); }
        .capture-btn .inner { width:44px; height:44px; border-radius:50%; background:white; transition:0.15s; }
        .capture-btn.video-mode .inner { border-radius:8px; width:36px; height:36px; background:#ff3b3b; }
        .capture-btn.recording { border-color:#ff0000; animation:pulseRing 1s infinite; }
        @keyframes pulseRing { 0% { box-shadow:0 0 0 0 rgba(255,0,0,0.5); } 70% { box-shadow:0 0 0 20px rgba(255,0,0,0); } 100% { box-shadow:0 0 0 0 rgba(255,0,0,0); } }
        .capture-btn .record-timer { position:absolute; top:-32px; left:50%; transform:translateX(-50%); font-size:12px; font-weight:700; color:#ff3b3b; background:rgba(0,0,0,0.6); padding:3px 10px; border-radius:10px; display:none; backdrop-filter:blur(6px); }
        .modes { display:flex; justify-content:center; gap:20px; color:rgba(255,255,255,0.6); font-size:12px; font-weight:600; padding:2px 0; }
        .mode { cursor:pointer; padding:4px 12px; transition:0.3s; border-bottom:2px solid transparent; }
        .mode.active { color:white; font-weight:700; border-bottom:2px solid #d868ff; }
        .mode:hover { color:white; }
        #thumbs { display:flex; gap:10px; overflow-x:auto; padding:4px 0; scrollbar-width:none; min-height:70px; align-items:center; }
        #thumbs::-webkit-scrollbar { display:none; }
        #thumbs .media-card { width:65px; height:65px; border-radius:14px; overflow:hidden; flex-shrink:0; border:2px solid rgba(255,255,255,0.25); background:#222; box-shadow:0 2px 8px rgba(0,0,0,0.5); position:relative; cursor:pointer; transition:0.15s; }
        #thumbs .media-card:active { transform:scale(0.92); border-color:white; }
        #thumbs .media-card img, #thumbs .media-card video { width:100%; height:100%; object-fit:cover; display:block; }
        #thumbs .media-card .play-icon { position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); font-size:20px; color:white; background:rgba(0,0,0,0.5); border-radius:50%; padding:3px 8px; backdrop-filter:blur(4px); pointer-events:none; line-height:1; }
        #thumbs .media-card .duration { position:absolute; bottom:3px; right:3px; background:rgba(0,0,0,0.7); color:#fff; font-size:10px; padding:1px 6px; border-radius:8px; backdrop-filter:blur(4px); }
        .empty-thumbs { color:#555; font-size:12px; padding:10px 0; width:100%; text-align:center; }
        .filters-bar { display:flex; flex-direction:row; overflow-x:auto; scroll-behavior:smooth; gap:6px; padding:2px 0; -webkit-overflow-scrolling:touch; scrollbar-width:none; }
        .filters-bar::-webkit-scrollbar { display:none; }
        .filter-card { min-width:56px; width:56px; height:56px; border-radius:14px; border:2px solid rgba(255,255,255,0.15); flex-shrink:0; overflow:hidden; position:relative; cursor:pointer; backdrop-filter:blur(8px); display:flex; align-items:center; justify-content:center; }
        .filter-card .preview { width:100%; height:100%; }
        .filter-card span { position:absolute; bottom:0; left:0; right:0; text-align:center; font-size:9px; font-weight:600; background:rgba(0,0,0,0.5); color:#fff; padding:2px; }
        .filter-card.active { border-color:#d868ff; box-shadow:0 0 20px rgba(216,104,255,0.3); }
        .normal { background:linear-gradient(135deg,#ff6b6b66,#ffffff66); }
        .vintage { background:linear-gradient(135deg,#c8a97e99,#f4e1b899); }
        .bw { background:linear-gradient(135deg,#111,#ddd); }
        .vivid { background:linear-gradient(135deg,#ff0080aa,#00e5ffaa); }
        .cool { background:linear-gradient(135deg,#0066ffaa,#66ffffaa); }
        .warm { background:linear-gradient(135deg,#ff6600aa,#ffd54faa); }
        .neon { background:linear-gradient(135deg,#39ff14aa,#00ffffaa); }
        .cyber { background:linear-gradient(135deg,#ff00ffaa,#00ffffaa); }
        .dream { background:linear-gradient(135deg,#ffb6c1aa,#d8b4feaa); }
        .moody { background:linear-gradient(135deg,#232526cc,#414345cc); }
        .retro { background:linear-gradient(135deg,#ff9966aa,#ff5e62aa); }
        .tokyo { background:linear-gradient(135deg,#7f00ffaa,#e100ffaa); }
        .miami { background:linear-gradient(135deg,#00c6ffaa,#0072ffaa); }
        .dark { background:linear-gradient(135deg,#000000cc,#333333cc); }
        .caption-input { display:none; padding:0 16px; }
        .caption-input.active { display:block; }
        .caption-input input { width:100%; padding:10px 16px; border-radius:25px; border:1px solid rgba(255,255,255,0.15); background:rgba(255,255,255,0.08); color:white; font-size:14px; outline:none; }
        .caption-input input::placeholder { color:rgba(255,255,255,0.4); }
        .caption-input input:focus { border-color:#d868ff; }
        .share-btn { display:none; padding:0 16px; }
        .share-btn.active { display:block; }
        .share-btn button { width:100%; padding:12px; border:none; border-radius:25px; background:linear-gradient(45deg,#ff73d2,#d868ff); color:white; font-size:16px; font-weight:600; cursor:pointer; transition:0.3s; }
        .share-btn button:hover { opacity:0.9; transform:scale(1.02); }
        .share-btn button:active { transform:scale(0.95); }
        .share-btn button:disabled { opacity:0.5; cursor:not-allowed; transform:none; }
        .flash-messages { position:fixed; top:60px; left:50%; transform:translateX(-50%); z-index:999; width:90%; max-width:400px; }
        .flash-message { padding:10px 16px; border-radius:10px; margin-bottom:6px; color:#fff; font-weight:500; text-align:center; animation:slideDown 0.3s ease; }
        .flash-message.success { background:#28a745; }
        .flash-message.danger { background:#dc3545; }
        .flash-message.warning { background:#ffc107; color:#333; }
        @keyframes slideDown { from { opacity:0; transform:translateY(-20px); } to { opacity:1; transform:translateY(0); } }
        @media(max-width:480px) { .capture-btn { width:52px; height:52px; } .capture-btn .inner { width:38px; height:38px; } .capture-btn.video-mode .inner { width:30px; height:30px; } .btn { font-size:12px; padding:6px 12px; } #thumbs .media-card { width:55px; height:55px; } .modes { gap:12px; font-size:11px; } .filter-card { width:48px; height:48px; min-width:48px; } .filter-card span { font-size:8px; } #cancelBtn { width:38px; height:38px; font-size:18px; top:12px; right:12px; } #backBtn { width:38px; height:38px; font-size:18px; top:12px; left:12px; } }
        .camera-message { position:absolute; inset:0; display:none; flex-direction:column; align-items:center; justify-content:center; color:white; z-index:1; background:#111; text-align:center; padding:20px; }
        .camera-message .icon { font-size:48px; margin-bottom:16px; }
        .camera-message .title { font-size:20px; font-weight:600; margin-bottom:8px; }
        .camera-message .sub { font-size:14px; color:#aaa; }
        .loading-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.8); z-index:1000; display:none; align-items:center; justify-content:center; flex-direction:column; gap:20px; }
        .loading-overlay .spinner { width:48px; height:48px; border:4px solid rgba(255,255,255,0.1); border-top-color:#d868ff; border-radius:50%; animation:spin 0.8s linear infinite; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .loading-overlay .status { color:white; font-size:16px; font-weight:500; }
        .loading-overlay .sub-status { color:rgba(255,255,255,0.5); font-size:13px; margin-top:-8px; }
        .capture-mode-toggle { display:none; gap:6px; background:rgba(255,255,255,0.08); border-radius:30px; padding:4px; }
        .capture-mode-toggle.visible { display:flex; }
        .capture-mode-toggle button { background:transparent; border:none; color:rgba(255,255,255,0.5); padding:6px 14px; border-radius:20px; cursor:pointer; font-size:12px; font-weight:600; transition:0.3s; }
        .capture-mode-toggle button.active { background:rgba(255,255,255,0.15); color:white; }
        .capture-mode-toggle button:hover { color:white; }
        .capture-mode-toggle button i { margin-right:4px; }
        .video-preview-container { position:absolute; inset:0; z-index:3; display:none; background:#000; }
        .video-preview-container video { width:100%; height:100%; object-fit:contain; }
        .upload-progress { width:80%; max-width:300px; height:4px; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden; margin-top:8px; }
        .upload-progress .progress-bar { height:100%; width:0%; background:linear-gradient(45deg,#ff73d2,#d868ff); border-radius:2px; transition:width 0.3s ease; }
        #gridBtn { background:rgba(255,255,255,0.05); color:white; border:1px solid rgba(255,255,255,0.1); padding:8px 16px; border-radius:40px; font-size:14px; font-weight:500; cursor:pointer; transition:0.3s ease; }
        #gridBtn:hover { background:rgba(255,255,255,0.15); }
        #gridBtn:active { transform:scale(0.93); }
        #gridBtn.active { background:rgba(216,104,255,0.15); color:#d868ff; border-color:rgba(216,104,255,0.2); }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>

    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
        <div class="status" id="uploadStatus">Uploading...</div>
        <div class="sub-status">Please wait, this may take a moment</div>
        <div class="upload-progress"><div class="progress-bar" id="uploadProgress"></div></div>
    </div>

    <div id="app">
        <div id="videoContainer">
            <video id="video" autoplay playsinline muted></video>
            <img id="previewMedia" alt="preview">
            <button id="backBtn" onclick="goBack()">
                <i class="fa-solid fa-arrow-left"></i>
            </button>
            <button id="cancelBtn" onclick="cancelCapture()">
                <i class="fa-solid fa-xmark"></i>
            </button>
            <div class="camera-message" id="cameraMessage">
                <div class="icon">📷</div>
                <div class="title">Kamera haipatikani</div>
                <div class="sub">Tumia <strong>Gallery</strong> kuupload picha au video</div>
            </div>
            <div class="video-preview-container" id="videoPreviewContainer">
                <video id="videoPreview" controls></video>
            </div>
        </div>
        <div class="grid" id="grid">
            <div></div><div></div><div></div>
            <div></div><div></div><div></div>
            <div></div><div></div><div></div>
        </div>
        <div class="top">
            <button class="btn" id="flash">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                    <path d="M13 2L4 14H11L10 22L20 9H13L13 2Z" fill="currentColor"/>
                </svg>
            </button>
            <button class="btn" id="flip">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                    <path d="M7 7H17L14 4M17 17H7L10 20" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    <path d="M17 7C19.209 7 21 8.791 21 11V12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    <path d="M7 17C4.791 17 3 15.209 3 13V12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                </svg>
            </button>
        </div>
        <div class="bottom">
            <div id="thumbs">
                <div class="empty-thumbs">📸 No media selected</div>
            </div>
            <div class="caption-input" id="captionInput">
                <input type="text" id="caption" placeholder="Write a caption..." maxlength="2200">
            </div>
            <div class="filters-bar" id="filtersBar">
                <div class="filter-card active" data-filter="none" onclick="setFilter('none',this)">
                    <div class="preview normal"></div><span>Normal</span>
                </div>
                <div class="filter-card" data-filter="brightness(1.15) saturate(1.2)" onclick="setFilter('brightness(1.15) saturate(1.2)',this)">
                    <div class="preview bright"></div><span>Bright</span>
                </div>
                <div class="filter-card" data-filter="contrast(1.4)" onclick="setFilter('contrast(1.4)',this)">
                    <div class="preview contrast"></div><span>Contrast</span>
                </div>
                <div class="filter-card" data-filter="saturate(2)" onclick="setFilter('saturate(2)',this)">
                    <div class="preview vivid"></div><span>Vivid</span>
                </div>
                <div class="filter-card" data-filter="sepia(0.6)" onclick="setFilter('sepia(0.6)',this)">
                    <div class="preview vintage"></div><span>Vintage</span>
                </div>
                <div class="filter-card" data-filter="grayscale(1)" onclick="setFilter('grayscale(1)',this)">
                    <div class="preview bw"></div><span>B&W</span>
                </div>
                <div class="filter-card" data-filter="hue-rotate(180deg)" onclick="setFilter('hue-rotate(180deg)',this)">
                    <div class="preview cool"></div><span>Cool</span>
                </div>
                <div class="filter-card" data-filter="sepia(0.3) saturate(1.6)" onclick="setFilter('sepia(0.3) saturate(1.6)',this)">
                    <div class="preview warm"></div><span>Warm</span>
                </div>
                <div class="filter-card" data-filter="saturate(3) contrast(1.3)" onclick="setFilter('saturate(3) contrast(1.3)',this)">
                    <div class="preview neon"></div><span>Neon</span>
                </div>
                <div class="filter-card" data-filter="hue-rotate(220deg) saturate(2)" onclick="setFilter('hue-rotate(220deg) saturate(2)',this)">
                    <div class="preview cyber"></div><span>Cyber</span>
                </div>
                <div class="filter-card" data-filter="blur(0.4px) brightness(1.1)" onclick="setFilter('blur(0.4px) brightness(1.1)',this)">
                    <div class="preview dream"></div><span>Dream</span>
                </div>
                <div class="filter-card" data-filter="brightness(0.7) contrast(1.4)" onclick="setFilter('brightness(0.7) contrast(1.4)',this)">
                    <div class="preview moody"></div><span>Moody</span>
                </div>
                <div class="filter-card" data-filter="sepia(0.5) contrast(0.9)" onclick="setFilter('sepia(0.5) contrast(0.9)',this)">
                    <div class="preview retro"></div><span>Retro</span>
                </div>
                <div class="filter-card" data-filter="hue-rotate(250deg) saturate(1.8)" onclick="setFilter('hue-rotate(250deg) saturate(1.8)',this)">
                    <div class="preview tokyo"></div><span>Tokyo</span>
                </div>
                <div class="filter-card" data-filter="hue-rotate(320deg) saturate(2)" onclick="setFilter('hue-rotate(320deg) saturate(2)',this)">
                    <div class="preview miami"></div><span>Miami</span>
                </div>
                <div class="filter-card" data-filter="brightness(0.5) contrast(1.6)" onclick="setFilter('brightness(0.5) contrast(1.6)',this)">
                    <div class="preview dark"></div><span>Dark</span>
                </div>
            </div>
            <div class="controls">
                <button class="btn" id="galleryBtn">📁 Gallery</button>
                <div class="capture-group">
                    <div class="capture-mode-toggle visible" id="captureModeToggle">
                        <button class="active" data-mode="photo" onclick="setCaptureMode('photo')"><i class="fa-solid fa-camera"></i> Photo</button>
                        <button data-mode="video" onclick="setCaptureMode('video')"><i class="fa-solid fa-video"></i> Video</button>
                    </div>
                    <div class="capture-btn" id="captureBtn">
                        <div class="inner"></div>
                        <div class="record-timer" id="recordTimer">0:00</div>
                    </div>
                </div>
                <button class="btn" id="gridBtn" onclick="toggleGrid()">⊞ Grid</button>
            </div>
            <div class="modes">
                <div class="mode" data-type="story" onclick="selectMode('story')">📖 STORY</div>
                <div class="mode active" data-type="post" onclick="selectMode('post')">📷 POST</div>
                <div class="mode" data-type="reel" onclick="selectMode('reel')">🎬 REEL</div>
            </div>
            <div class="share-btn" id="shareBtn">
                <button onclick="submitPost()" id="shareButton"><i class="fa-regular fa-share-from-square"></i> Share</button>
            </div>
        </div>
    </div>

    <form id="uploadForm" method="POST" enctype="multipart/form-data">
        <input type="file" id="gallery" name="media" accept="image/*,video/*" hidden>
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="post_type" id="postType" value="post">
        <input type="hidden" name="caption" id="captionHidden">
        <input type="hidden" name="media_data" id="mediaData">
    </form>

    <script>
        var video = document.getElementById('video');
        var previewMedia = document.getElementById('previewMedia');
        var videoPreviewContainer = document.getElementById('videoPreviewContainer');
        var videoPreview = document.getElementById('videoPreview');
        var galleryInput = document.getElementById('gallery');
        var galleryBtn = document.getElementById('galleryBtn');
        var thumbsContainer = document.getElementById('thumbs');
        var flipBtn = document.getElementById('flip');
        var gridBtn = document.getElementById('gridBtn');
        var gridOverlay = document.getElementById('grid');
        var captureBtn = document.getElementById('captureBtn');
        var flashBtn = document.getElementById('flash');
        var captionInput = document.getElementById('caption');
        var captionHidden = document.getElementById('captionHidden');
        var mediaData = document.getElementById('mediaData');
        var uploadForm = document.getElementById('uploadForm');
        var postType = document.getElementById('postType');
        var shareBtn = document.getElementById('shareBtn');
        var shareButton = document.getElementById('shareButton');
        var captionDiv = document.getElementById('captionInput');
        var modes = document.querySelectorAll('.mode');
        var recordTimer = document.getElementById('recordTimer');
        var loadingOverlay = document.getElementById('loadingOverlay');
        var uploadStatus = document.getElementById('uploadStatus');
        var uploadProgress = document.getElementById('uploadProgress');
        var cameraMessage = document.getElementById('cameraMessage');
        var captureModeToggle = document.getElementById('captureModeToggle');
        var cancelBtn = document.getElementById('cancelBtn');
        var backBtn = document.getElementById('backBtn');

        var currentStream = null;
        var facingMode = 'environment';
        var selectedMode = 'post';
        var activeFilter = 'none';
        var captureMode = 'photo';
        var capturedFile = null;
        var capturedDataURL = null;
        var isVideo = false;
        var videoDuration = 0;
        var mediaType = 'image';
        var isRecording = false;
        var mediaRecorder = null;
        var recordedChunks = [];
        var recordSeconds = 0;
        var recordInterval = null;
        var gridVisible = true;
        var flashEnabled = false;
        var zoomLevel = 1;
        var startPinchDist = 0;
        var hasMedia = false;

        function getCsrfToken() {
            return document.querySelector('input[name="csrf_token"]').value;
        }

        function goBack() {
            if (hasMedia) {
                if (confirm('You have unsaved media. Are you sure you want to leave?')) {
                    window.location.href = '/feed';
                }
            } else {
                window.location.href = '/feed';
            }
        }

        function cancelCapture() {
            capturedFile = null;
            capturedDataURL = null;
            isVideo = false;
            mediaType = 'image';
            hasMedia = false;
            cancelBtn.style.display = 'none';
            previewMedia.style.display = 'none';
            videoPreviewContainer.style.display = 'none';
            video.style.display = 'block';
            var cards = thumbsContainer.querySelectorAll('.media-card');
            for (var i = 0; i < cards.length; i++) {
                cards[i].remove();
            }
            var empty = document.createElement('div');
            empty.className = 'empty-thumbs';
            empty.textContent = '📸 No media selected';
            thumbsContainer.appendChild(empty);
            shareBtn.classList.remove('active');
            captionDiv.classList.remove('active');
            mediaData.value = '';
            galleryInput.value = '';
            shareButton.disabled = false;
            shareButton.innerHTML = '<i class="fa-regular fa-share-from-square"></i> Share';
            if (isRecording) {
                if (mediaRecorder && mediaRecorder.state === 'recording') {
                    mediaRecorder.stop();
                }
                isRecording = false;
                captureBtn.classList.remove('recording');
                if (recordInterval) { clearInterval(recordInterval); recordInterval = null; }
                recordTimer.style.display = 'none';
            }
            flash('Media cleared. Take a new one.', 'warning');
        }

        function toggleGrid() {
            gridVisible = !gridVisible;
            if (gridVisible) {
                gridOverlay.style.display = 'grid';
                gridOverlay.classList.remove('hidden');
                gridBtn.innerHTML = '⊞ Grid';
                gridBtn.style.background = 'rgba(255,255,255,0.05)';
                gridBtn.style.color = 'white';
                gridBtn.style.border = '1px solid rgba(255,255,255,0.1)';
            } else {
                gridOverlay.style.display = 'none';
                gridOverlay.classList.add('hidden');
                gridBtn.innerHTML = '⊟ Grid';
                gridBtn.style.background = 'rgba(216,104,255,0.15)';
                gridBtn.style.color = '#d868ff';
                gridBtn.style.border = '1px solid rgba(216,104,255,0.2)';
            }
        }

        function flashMessage(message, type) {
            var container = document.querySelector('.flash-messages');
            if (!container) return;
            var div = document.createElement('div');
            div.className = 'flash-message ' + type;
            div.textContent = message;
            container.appendChild(div);
            setTimeout(function() {
                div.style.transition = 'opacity 0.5s';
                div.style.opacity = '0';
                setTimeout(function() { div.remove(); }, 500);
            }, 3000);
        }

        gridOverlay.style.display = 'grid';
        gridOverlay.classList.remove('hidden');

        function setCaptureMode(mode) {
            captureMode = mode;
            var buttons = document.querySelectorAll('.capture-mode-toggle button');
            for (var i = 0; i < buttons.length; i++) {
                buttons[i].classList.toggle('active', buttons[i].dataset.mode === mode);
            }
            var inner = captureBtn.querySelector('.inner');
            if (mode === 'video') {
                captureBtn.classList.add('video-mode');
                inner.style.borderRadius = '8px';
                inner.style.width = '36px';
                inner.style.height = '36px';
                inner.style.background = '#ff3b3b';
            } else {
                captureBtn.classList.remove('video-mode');
                inner.style.borderRadius = '50%';
                inner.style.width = '44px';
                inner.style.height = '44px';
                inner.style.background = 'white';
            }
            if (isRecording) {
                if (mediaRecorder && mediaRecorder.state === 'recording') {
                    mediaRecorder.stop();
                }
                isRecording = false;
                captureBtn.classList.remove('recording');
                if (recordInterval) { clearInterval(recordInterval); recordInterval = null; }
                recordTimer.style.display = 'none';
            }
        }

        function isCameraSupported() {
            return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
        }

        async function startCamera(facing) {
            facing = facing || 'environment';
            cameraMessage.style.display = 'none';
            video.style.display = 'block';
            if (!isCameraSupported()) {
                cameraMessage.style.display = 'flex';
                video.style.display = 'none';
                captureBtn.style.display = 'none';
                document.getElementById('flash').style.display = 'none';
                document.getElementById('flip').style.display = 'none';
                document.getElementById('galleryBtn').style.background = 'linear-gradient(45deg, #ff73d2, #d868ff)';
                document.getElementById('galleryBtn').style.color = 'white';
                return;
            }
            try {
                if (currentStream) {
                    currentStream.getTracks().forEach(function(track) { track.stop(); });
                    currentStream = null;
                }
                var constraints = {
                    video: { facingMode: { ideal: facing }, width: { ideal: 1280 }, height: { ideal: 720 } },
                    audio: { echoCancellation: true, noiseSuppression: true }
                };
                var stream = await navigator.mediaDevices.getUserMedia(constraints);
                currentStream = stream;
                video.srcObject = stream;
                previewMedia.style.display = 'none';
                videoPreviewContainer.style.display = 'none';
                video.style.display = 'block';
                cameraMessage.style.display = 'none';
                await video.play();
                captureBtn.style.display = 'flex';
                document.getElementById('flash').style.display = 'block';
                document.getElementById('flip').style.display = 'block';
                document.getElementById('galleryBtn').style.background = '';
                document.getElementById('galleryBtn').style.color = '';
            } catch (err) {
                console.error(err);
                var msg = '';
                if (err.name === 'NotAllowedError') msg = 'Ruhusa ya kamera imekataliwa. Ruhusu kamera kwenye browser.';
                else if (err.name === 'NotFoundError') msg = 'Hakuna kamera iliyopatikana kwenye kifaa chako.';
                else if (err.name === 'NotReadableError') msg = 'Kamera inatumiwa na programu nyingine.';
                else if (err.name === 'OverconstrainedError') msg = 'Kamera haisaidii ubora ulioombwa.';
                else msg = err.message;
                cameraMessage.style.display = 'flex';
                video.style.display = 'none';
                captureBtn.style.display = 'none';
                document.getElementById('flash').style.display = 'none';
                document.getElementById('flip').style.display = 'none';
                document.getElementById('galleryBtn').style.background = 'linear-gradient(45deg, #ff73d2, #d868ff)';
                document.getElementById('galleryBtn').style.color = 'white';
                document.querySelector('#cameraMessage .sub').innerHTML = msg + '<br>Tumia <strong>Gallery</strong> kuupload picha au video.';
            }
        }

        flipBtn.addEventListener('click', function() {
            facingMode = (facingMode === 'environment') ? 'user' : 'environment';
            startCamera(facingMode);
        });

        flashBtn.addEventListener('click', async function() {
            if (!currentStream) { alert('Camera haijawashwa'); return; }
            var track = currentStream.getVideoTracks()[0];
            try {
                var capabilities = track.getCapabilities();
                if (!capabilities.torch) { alert('Flash/Torch haijaungwa mkono'); return; }
                flashEnabled = !flashEnabled;
                await track.applyConstraints({ advanced: [{ torch: flashEnabled }] });
                flashBtn.classList.toggle('on', flashEnabled);
                flashBtn.innerHTML = flashEnabled ? 'ON' :
                    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none">' +
                    '<path d="M13 2L4 14H11L10 22L20 9H13L13 2Z" fill="currentColor"/>' +
                    '</svg>';
            } catch (err) { console.error(err); alert('Flash imeshindikana'); }
        });

        function setFilter(filter, el) {
            activeFilter = filter;
            var cards = document.querySelectorAll('.filter-card');
            for (var i = 0; i < cards.length; i++) {
                cards[i].classList.remove('active');
            }
            if (el) el.classList.add('active');
            video.style.filter = filter;
            previewMedia.style.filter = filter;
            videoPreview.style.filter = filter;
        }

        function capturePhoto() {
            if (!video.videoWidth) {
                alert('Kamera haijawashwa. Tumia Gallery.');
                return;
            }
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            ctx.filter = activeFilter;
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            var dataUrl = canvas.toDataURL('image/jpeg', 0.92);
            capturedDataURL = dataUrl;
            isVideo = false;
            mediaType = 'image';
            capturedFile = null;
            hasMedia = true;
            previewMedia.src = dataUrl;
            previewMedia.style.display = 'block';
            video.style.display = 'none';
            videoPreviewContainer.style.display = 'none';
            addMediaCard(dataUrl, 'image');
            showShareButton();
            mediaData.value = dataUrl;
            cancelBtn.style.display = 'flex';
        }

        function startRecording() {
            if (!currentStream) {
                alert('Kamera haijawashwa. Tumia Gallery.');
                return;
            }
            if (isRecording) {
                if (mediaRecorder && mediaRecorder.state === 'recording') {
                    mediaRecorder.stop();
                }
                isRecording = false;
                captureBtn.classList.remove('recording');
                if (recordInterval) { clearInterval(recordInterval); recordInterval = null; }
                recordTimer.style.display = 'none';
                return;
            }
            try {
                navigator.mediaDevices.getUserMedia({ audio: true })
                    .then(function(audioStream) {
                        var audioTracks = audioStream.getAudioTracks();
                        var streamToRecord = currentStream;
                        if (audioTracks.length > 0) {
                            streamToRecord = new MediaStream([
                                currentStream.getVideoTracks()[0],
                                audioTracks[0]
                            ]);
                        }
                        startMediaRecorder(streamToRecord);
                    })
                    .catch(function() {
                        startMediaRecorder(currentStream);
                    });
            } catch (err) {
                console.error(err);
                alert('Error starting recording: ' + err.message);
            }
        }

        function startMediaRecorder(stream) {
            try {
                var mimeTypes = ['video/webm;codecs=vp9', 'video/webm;codecs=vp8', 'video/webm', 'video/mp4'];
                var mimeType = 'video/webm';
                for (var i = 0; i < mimeTypes.length; i++) {
                    if (MediaRecorder.isTypeSupported(mimeTypes[i])) {
                        mimeType = mimeTypes[i];
                        break;
                    }
                }
                mediaRecorder = new MediaRecorder(stream, { mimeType: mimeType });
                recordedChunks = [];
                mediaRecorder.ondataavailable = function(e) {
                    if (e.data.size > 0) { recordedChunks.push(e.data); console.log('📦 Chunk received:', e.data.size, 'bytes'); }
                };
                mediaRecorder.onstop = function() {
                    console.log('📹 Recording stopped, chunks:', recordedChunks.length);
                    if (recordedChunks.length === 0) { alert('Error: No video data recorded. Please try again.'); return; }
                    var blob = new Blob(recordedChunks, { type: mimeType });
                    console.log('📹 Blob created, size:', blob.size, 'bytes');
                    if (blob.size < 1000) { alert('Error: Video too small. Please record longer.'); return; }
                    var fileName = 'video_' + Date.now() + '.mp4';
                    capturedFile = new File([blob], fileName, { type: 'video/mp4' });
                    isVideo = true;
                    mediaType = 'video';
                    capturedDataURL = null;
                    hasMedia = true;
                    var url = URL.createObjectURL(blob);
                    previewMedia.style.display = 'none';
                    video.style.display = 'none';
                    videoPreviewContainer.style.display = 'block';
                    videoPreview.src = url;
                    videoPreview.load();
                    videoPreview.play();
                    var tempVid = document.createElement('video');
                    tempVid.src = url;
                    tempVid.onloadedmetadata = function() {
                        videoDuration = tempVid.duration || 0;
                        tempVid.currentTime = Math.min(0.1, videoDuration / 2);
                        tempVid.onseeked = function() {
                            var canvas = document.createElement('canvas');
                            canvas.width = tempVid.videoWidth || 640;
                            canvas.height = tempVid.videoHeight || 480;
                            var ctx = canvas.getContext('2d');
                            ctx.drawImage(tempVid, 0, 0, canvas.width, canvas.height);
                            var cover = canvas.toDataURL('image/jpeg');
                            addMediaCardWithCover(url, cover, videoDuration);
                            showShareButton();
                            mediaData.value = '';
                            tempVid.remove();
                        };
                        tempVid.currentTime = Math.min(0.1, videoDuration / 2);
                    };
                    if (tempVid.readyState >= 1) { tempVid.onloadedmetadata(); }
                    isRecording = false;
                    captureBtn.classList.remove('recording');
                    recordTimer.style.display = 'none';
                    if (recordInterval) { clearInterval(recordInterval); recordInterval = null; }
                    cancelBtn.style.display = 'flex';
                    console.log('✅ Video capture complete:', fileName, 'size:', blob.size);
                };
                isRecording = true;
                captureBtn.classList.add('recording');
                recordTimer.style.display = 'block';
                recordSeconds = 0;
                recordTimer.textContent = '0:00';
                recordInterval = setInterval(function() {
                    recordSeconds++;
                    var mins = Math.floor(recordSeconds / 60);
                    var secs = recordSeconds % 60;
                    recordTimer.textContent = mins + ':' + (secs < 10 ? '0' + secs : secs);
                    if (recordSeconds >= 60) {
                        if (mediaRecorder && mediaRecorder.state === 'recording') {
                            mediaRecorder.stop();
                        }
                    }
                }, 1000);
                mediaRecorder.start(1000);
                console.log('📹 Recording started');
            } catch (err) {
                console.error('❌ Error starting recording:', err);
                alert('Error starting recording: ' + err.message);
            }
        }

        captureBtn.addEventListener('click', function() {
            if (selectedMode === 'reel') {
                startRecording();
            } else if (captureMode === 'video') {
                startRecording();
            } else {
                capturePhoto();
            }
        });

        function addMediaCard(dataUrl, type) {
            var empty = thumbsContainer.querySelector('.empty-thumbs');
            if (empty) empty.remove();
            var existing = thumbsContainer.querySelectorAll('.media-card');
            for (var i = 0; i < existing.length; i++) {
                existing[i].remove();
            }
            var card = document.createElement('div');
            card.className = 'media-card';
            var img = document.createElement('img');
            img.src = dataUrl;
            img.alt = 'capture';
            card.appendChild(img);
            card.onclick = function() {
                previewMedia.src = dataUrl;
                previewMedia.style.display = 'block';
                video.style.display = 'none';
                videoPreviewContainer.style.display = 'none';
                cancelBtn.style.display = 'flex';
            };
            thumbsContainer.prepend(card);
        }

        function addMediaCardWithCover(videoUrl, coverDataUrl, duration) {
            var empty = thumbsContainer.querySelector('.empty-thumbs');
            if (empty) empty.remove();
            var existing = thumbsContainer.querySelectorAll('.media-card');
            for (var i = 0; i < existing.length; i++) {
                existing[i].remove();
            }
            var card = document.createElement('div');
            card.className = 'media-card';
            var img = document.createElement('img');
            img.src = coverDataUrl;
            img.alt = 'video cover';
            card.appendChild(img);
            var playIcon = document.createElement('span');
            playIcon.className = 'play-icon';
            playIcon.textContent = '▶';
            card.appendChild(playIcon);
            var dur = document.createElement('span');
            dur.className = 'duration';
            if (duration && !isNaN(duration) && isFinite(duration)) {
                var mins = Math.floor(duration / 60);
                var secs = Math.floor(duration % 60);
                dur.textContent = mins + ':' + (secs < 10 ? '0' + secs : secs);
            } else {
                dur.textContent = '0:00';
            }
            card.appendChild(dur);
            card.onclick = function() {
                previewMedia.style.display = 'none';
                video.style.display = 'none';
                videoPreviewContainer.style.display = 'block';
                videoPreview.src = videoUrl;
                videoPreview.load();
                videoPreview.play();
                cancelBtn.style.display = 'flex';
            };
            thumbsContainer.prepend(card);
        }

        function showShareButton() {
            shareBtn.classList.add('active');
            if (selectedMode !== 'story') captionDiv.classList.add('active');
        }

        function selectMode(type) {
            selectedMode = type;
            postType.value = type;
            for (var i = 0; i < modes.length; i++) {
                modes[i].classList.toggle('active', modes[i].dataset.type === type);
            }
            var toggle = document.getElementById('captureModeToggle');
            var inner = captureBtn.querySelector('.inner');
            if (type === 'reel') {
                toggle.classList.remove('visible');
                captureBtn.classList.add('video-mode');
                inner.style.borderRadius = '8px';
                inner.style.width = '36px';
                inner.style.height = '36px';
                inner.style.background = '#ff3b3b';
                captureMode = 'video';
            } else {
                toggle.classList.add('visible');
                var activeBtn = toggle.querySelector('button.active');
                if (activeBtn) {
                    var mode = activeBtn.dataset.mode;
                    if (mode === 'video') {
                        captureBtn.classList.add('video-mode');
                        inner.style.borderRadius = '8px';
                        inner.style.width = '36px';
                        inner.style.height = '36px';
                        inner.style.background = '#ff3b3b';
                    } else {
                        captureBtn.classList.remove('video-mode');
                        inner.style.borderRadius = '50%';
                        inner.style.width = '44px';
                        inner.style.height = '44px';
                        inner.style.background = 'white';
                    }
                    captureMode = mode;
                }
            }
            if (type === 'story') {
                captionDiv.classList.remove('active');
            } else {
                var hasMedia = thumbsContainer.querySelector('.media-card');
                if (hasMedia) captionDiv.classList.add('active');
            }
            if (isRecording) {
                if (mediaRecorder && mediaRecorder.state === 'recording') {
                    mediaRecorder.stop();
                }
                isRecording = false;
                captureBtn.classList.remove('recording');
                if (recordInterval) { clearInterval(recordInterval); recordInterval = null; }
                recordTimer.style.display = 'none';
            }
        }

        galleryBtn.addEventListener('click', function() { galleryInput.click(); });
        galleryInput.addEventListener('change', function(e) {
            if (e.target.files.length) {
                var file = e.target.files[0];
                var isVideoFile = file.type.startsWith('video');
                console.log('📁 Gallery file selected:', file.name, file.type, file.size);
                capturedFile = file;
                isVideo = isVideoFile;
                mediaType = isVideoFile ? 'video' : 'image';
                capturedDataURL = null;
                hasMedia = true;
                var objectUrl = URL.createObjectURL(file);
                if (isVideoFile) {
                    console.log('🎬 Processing video file...');
                    mediaData.value = '';
                    var empty = thumbsContainer.querySelector('.empty-thumbs');
                    if (empty) empty.remove();
                    var existing = thumbsContainer.querySelectorAll('.media-card');
                    for (var i = 0; i < existing.length; i++) {
                        existing[i].remove();
                    }
                    var tempVid = document.createElement('video');
                    tempVid.src = objectUrl;
                    tempVid.muted = true;
                    tempVid.playsInline = true;
                    tempVid.preload = 'metadata';
                    tempVid.onloadedmetadata = function() {
                        videoDuration = tempVid.duration || 0;
                        console.log('🎬 Video duration:', videoDuration);
                        tempVid.currentTime = Math.min(0.1, videoDuration / 2);
                        tempVid.onseeked = function() {
                            try {
                                var canvas = document.createElement('canvas');
                                canvas.width = tempVid.videoWidth || 640;
                                canvas.height = tempVid.videoHeight || 480;
                                var ctx = canvas.getContext('2d');
                                ctx.drawImage(tempVid, 0, 0, canvas.width, canvas.height);
                                var cover = canvas.toDataURL('image/jpeg');
                                previewMedia.style.display = 'none';
                                video.style.display = 'none';
                                videoPreviewContainer.style.display = 'block';
                                videoPreview.src = objectUrl;
                                videoPreview.load();
                                videoPreview.play();
                                addMediaCardWithCover(objectUrl, cover, videoDuration);
                                showShareButton();
                                cancelBtn.style.display = 'flex';
                                console.log('✅ Video thumbnail created, duration:', videoDuration);
                            } catch (err) {
                                console.error('❌ Error creating thumbnail:', err);
                                previewMedia.style.display = 'none';
                                video.style.display = 'none';
                                videoPreviewContainer.style.display = 'block';
                                videoPreview.src = objectUrl;
                                videoPreview.load();
                                videoPreview.play();
                                showShareButton();
                                cancelBtn.style.display = 'flex';
                            }
                            tempVid.remove();
                        };
                        setTimeout(function() {
                            if (tempVid.parentNode) {
                                tempVid.onseeked();
                            }
                        }, 2000);
                    };
                    tempVid.onerror = function() {
                        console.error('❌ Video loading error');
                        previewMedia.style.display = 'none';
                        video.style.display = 'none';
                        videoPreviewContainer.style.display = 'block';
                        videoPreview.src = objectUrl;
                        videoPreview.load();
                        videoPreview.play();
                        showShareButton();
                        cancelBtn.style.display = 'flex';
                        tempVid.remove();
                    };
                    tempVid.load();
                } else {
                    console.log('📸 Processing image file...');
                    previewMedia.src = objectUrl;
                    previewMedia.style.display = 'block';
                    video.style.display = 'none';
                    videoPreviewContainer.style.display = 'none';
                    addMediaCard(objectUrl, 'image');
                    showShareButton();
                    cancelBtn.style.display = 'flex';
                    var reader = new FileReader();
                    reader.onload = function(ev) {
                        mediaData.value = ev.target.result;
                        console.log('✅ Image converted to base64, size:', ev.target.result.length);
                    };
                    reader.onerror = function() {
                        console.error('❌ Error reading image file');
                        mediaData.value = objectUrl;
                    };
                    reader.readAsDataURL(file);
                }
            }
        });

        function submitPost() {
            captionHidden.value = captionInput.value.trim();
            console.log('📤 Submitting post:', {
                hasFile: !!capturedFile,
                fileType: capturedFile ? capturedFile.type : 'N/A',
                fileSize: capturedFile ? capturedFile.size : 'N/A',
                hasDataURL: !!capturedDataURL,
                postType: selectedMode,
                caption: captionInput.value,
                isVideo: isVideo
            });
            if (!capturedFile && !capturedDataURL) {
                alert('Chagua picha au video kwanza');
                return;
            }
            shareButton.disabled = true;
            shareButton.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing...';
            loadingOverlay.style.display = 'flex';
            uploadStatus.textContent = 'Uploading...';
            uploadProgress.style.width = '0%';
            if (capturedFile) {
                console.log('📤 Uploading file via FormData...');
                var formData = new FormData();
                formData.append('csrf_token', getCsrfToken());
                formData.append('post_type', selectedMode);
                formData.append('caption', captionInput.value);
                formData.append('media', capturedFile);
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/upload');
                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) {
                        var percent = (e.loaded / e.total) * 100;
                        uploadProgress.style.width = percent + '%';
                        uploadStatus.textContent = 'Uploading... ' + Math.round(percent) + '%';
                    }
                });
                xhr.onload = function() {
                    console.log('📤 Upload response:', xhr.status, xhr.responseText);
                    if (xhr.status === 302 || xhr.responseURL.includes('/feed') || xhr.responseURL.includes('/explore')) {
                        window.location.href = xhr.responseURL;
                    } else if (xhr.status === 200) {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            if (data.redirect) {
                                window.location.href = data.redirect;
                            } else {
                                window.location.href = '/feed';
                            }
                        } catch (e) {
                            window.location.href = '/feed';
                        }
                    } else {
                        var errorMsg = 'Upload failed. Please try again.';
                        try {
                            var data = JSON.parse(xhr.responseText);
                            if (data.error) errorMsg = data.error;
                        } catch (e) {}
                        alert(errorMsg);
                        shareButton.disabled = false;
                        shareButton.innerHTML = '<i class="fa-regular fa-share-from-square"></i> Share';
                        loadingOverlay.style.display = 'none';
                    }
                };
                xhr.onerror = function() {
                    alert('Network error. Please check your connection.');
                    shareButton.disabled = false;
                    shareButton.innerHTML = '<i class="fa-regular fa-share-from-square"></i> Share';
                    loadingOverlay.style.display = 'none';
                };
                xhr.send(formData);
                return;
            }
            if (capturedDataURL) {
                console.log('📤 Uploading base64 data...');
                mediaData.value = capturedDataURL;
                galleryInput.value = '';
                uploadForm.submit();
            }
        }

        video.addEventListener('click', function() {
            if (previewMedia.style.display !== 'none' || videoPreviewContainer.style.display !== 'none') {
                previewMedia.style.display = 'none';
                videoPreviewContainer.style.display = 'none';
                video.style.display = 'block';
                zoomLevel = 1;
                video.style.transform = 'scale(1)';
                cancelBtn.style.display = 'none';
            }
        });

        function getDistance(touches) {
            if (touches.length < 2) return 0;
            var dx = touches[0].clientX - touches[1].clientX;
            var dy = touches[0].clientY - touches[1].clientY;
            return Math.sqrt(dx * dx + dy * dy);
        }
        function handleTouchStart(e) {
            if (e.touches.length === 2) startPinchDist = getDistance(e.touches);
        }
        function handleTouchMove(e) {
            if (e.touches.length !== 2) return;
            var newDist = getDistance(e.touches);
            if (startPinchDist === 0) { startPinchDist = newDist; return; }
            var delta = newDist / startPinchDist;
            var newZoom = zoomLevel * delta;
            newZoom = Math.min(Math.max(newZoom, 1), 5);
            zoomLevel = newZoom;
            startPinchDist = newDist;
            if (previewMedia.style.display !== 'none') {
                previewMedia.style.transform = 'scale(' + zoomLevel + ')';
            } else if (video.style.display !== 'none') {
                video.style.transform = 'scale(' + zoomLevel + ')';
            }
        }
        function handleTouchEnd(e) { startPinchDist = 0; }
        var container = document.getElementById('videoContainer');
        container.addEventListener('touchstart', handleTouchStart, { passive: true });
        container.addEventListener('touchmove', handleTouchMove, { passive: true });
        container.addEventListener('touchend', handleTouchEnd, { passive: true });

        container.addEventListener('dblclick', function() {
            zoomLevel = 1;
            if (previewMedia.style.display !== 'none') {
                previewMedia.style.transform = 'scale(1)';
            } else if (video.style.display !== 'none') {
                video.style.transform = 'scale(1)';
            }
        });

        document.addEventListener('keydown', function(e) {
            if (e.key === 'g' || e.key === 'G') toggleGrid();
            if (e.key === 'p' || e.key === 'P') setCaptureMode('photo');
            if (e.key === 'v' || e.key === 'V') setCaptureMode('video');
            if (e.key === 'Escape' || e.key === 'x' || e.key === 'X') {
                if (cancelBtn.style.display === 'flex') {
                    cancelCapture();
                }
            }
        });

        startCamera('environment');
        selectMode('post');
        setCaptureMode('photo');

        setTimeout(function() {
            var messages = document.querySelectorAll('.flash-message');
            for (var i = 0; i < messages.length; i++) {
                messages[i].style.transition = 'opacity 0.5s';
                messages[i].style.opacity = '0';
                setTimeout(function(el) { el.remove(); }, 500);
            }
        }, 4000);

        window.addEventListener('beforeunload', function() {
            if (currentStream) {
                currentStream.getTracks().forEach(function(track) { track.stop(); });
            }
            if (mediaRecorder && mediaRecorder.state === 'recording') {
                mediaRecorder.stop();
            }
        });
    </script>
</body>
</html>
'''
POST_VIEW_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Post - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
        body{max-width:430px;margin:auto;background:#000;min-height:100vh}
        .header{background:#000;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.1)}
        .header h1{color:#fff;font-size:20px}
        .header a{color:#fff;font-size:22px;text-decoration:none}
        .post-card{position:relative;height:60vh;background:#000;overflow:hidden;display:flex;align-items:center;justify-content:center}
        .post-media{width:100%;height:100%;object-fit:contain;background:#000}
        .post-info{padding:16px;background:#000}
        .post-user{display:flex;align-items:center;gap:10px;margin-bottom:10px}
        .post-user img{width:32px;height:32px;border-radius:50%;object-fit:cover;border:2px solid #ff4d9e}
        .post-user .name{color:#fff;font-weight:600;font-size:15px}
        .post-user .username{color:#888;font-size:13px}
        .post-caption{color:#fff;font-size:14px;margin:10px 0;padding:10px;background:rgba(255,255,255,0.05);border-radius:8px}
        .post-actions{display:flex;gap:8px;padding:10px 0;border-top:1px solid rgba(255,255,255,0.1);border-bottom:1px solid rgba(255,255,255,0.1);margin:10px 0;flex-wrap:wrap;align-items:center}
        .post-actions button{background:rgba(255,255,255,0.05);border:none;color:#fff;font-size:20px;cursor:pointer;padding:8px 14px;border-radius:12px;transition:all 0.2s;display:flex;align-items:center;gap:6px}
        .post-actions button:hover{background:rgba(255,255,255,0.12)}
        .post-actions button:active{transform:scale(0.92)}
        .post-actions .fa-heart{color:#ed4956}
        .post-actions .action-label{font-size:12px;color:#888;font-weight:500}
        .post-stats{color:#888;font-size:13px;margin:10px 0}
        .comment-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:999;display:none}
        .comment-overlay.active{display:block}
        .comment-panel{position:fixed;bottom:0;left:50%;transform:translateX(-50%) translateY(100%);width:100%;max-width:430px;height:70vh;max-height:600px;background:#fff;border-radius:20px 20px 0 0;box-shadow:0 -10px 40px rgba(0,0,0,0.3);z-index:1000;display:flex;flex-direction:column;transition:transform 0.4s cubic-bezier(0.22,1,0.36,1);overflow:hidden}
        .comment-panel.active{transform:translateX(-50%) translateY(0)}
        .panel-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px 12px;border-bottom:1px solid #f0f0f0;flex-shrink:0;background:#fff}
        .panel-header-left{display:flex;align-items:center;gap:12px}
        .panel-header-left h3{font-size:18px;font-weight:700;color:#262626;margin:0}
        .panel-header-left .comment-count{font-size:14px;color:#8e8e8e;font-weight:400}
        .close-panel{background:none;border:none;font-size:24px;cursor:pointer;color:#262626;padding:4px 8px}
        .close-panel:hover{transform:scale(1.1)}
        .close-btn{background:none;border:none;font-size:24px;cursor:pointer;color:#8e8e8e;padding:4px 8px}
        .close-btn:hover{color:#262626;transform:scale(1.1)}
        .panel-input-top{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid #f0f0f0;flex-shrink:0;background:#fafafa}
        .panel-input-top .comment-avatar{width:32px;height:32px;border-radius:50%;object-fit:cover;flex-shrink:0}
        .panel-input-top input{flex:1;padding:10px 14px;border:1px solid #e0e0e0;border-radius:20px;outline:none;font-size:14px;background:#fff}
        .panel-input-top input:focus{border-color:#d868ff}
        .panel-input-top input::placeholder{color:#8e8e8e}
        .panel-input-top button{background:linear-gradient(45deg,#ff73d2,#d868ff);color:white;border:none;border-radius:50%;width:38px;height:38px;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:transform 0.2s}
        .panel-input-top button:hover{transform:scale(1.05)}
        .panel-input-top button:active{transform:scale(0.9)}
        .panel-input-top button:disabled{opacity:0.5;cursor:not-allowed}
        .panel-comments{flex:1;overflow-y:auto;padding:12px 16px;background:#fff}
        .panel-comments::-webkit-scrollbar{width:4px}
        .panel-comments::-webkit-scrollbar-track{background:transparent}
        .panel-comments::-webkit-scrollbar-thumb{background:#d868ff;border-radius:10px}
        .loading-comments{text-align:center;color:#8e8e8e;padding:40px 0}
        .loading-comments i{font-size:24px;display:block;margin-bottom:12px}
        .comment-item{padding:10px 0;border-bottom:1px solid #f5f5f5;animation:commentSlideIn 0.3s ease}
        .comment-item:last-child{border-bottom:none}
        @keyframes commentSlideIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        .comment-item.reply{padding-left:40px;border-left:2px solid #d868ff;margin-left:10px}
        .comment-user{display:flex;align-items:center;gap:8px}
        .comment-user img{width:28px;height:28px;border-radius:50%;object-fit:cover}
        .comment-user strong{font-size:13px;color:#262626}
        .comment-user .comment-time{font-size:11px;color:#8e8e8e;font-weight:400}
        .comment-text{font-size:14px;color:#262626;margin-left:36px;word-wrap:break-word;line-height:1.4}
        .comment-actions{margin-left:36px;margin-top:4px;display:flex;gap:12px;align-items:center}
        .comment-actions button{background:none;border:none;color:#8e8e8e;font-size:11px;cursor:pointer;padding:2px 6px}
        .comment-actions button:hover{color:#262626}
        .comment-actions .delete-comment{color:#ed4956}
        .comment-actions .delete-comment:hover{color:#c0392b}
        .comment-actions .reply-btn{color:#d868ff}
        .comment-actions .reply-btn:hover{color:#b84ad8}
        .panel-footer{padding:8px 16px;border-top:1px solid #f0f0f0;flex-shrink:0;background:#fff;min-height:40px}
        #replyIndicatorView{display:none;font-size:13px;color:#262626}
        #replyIndicatorView strong{color:#d868ff}
        .cancel-reply{background:none;border:none;color:#ed4956;cursor:pointer;font-size:16px;margin-left:8px}
        .no-comments{text-align:center;padding:40px 20px;color:#8e8e8e}
        .no-comments i{font-size:48px;display:block;margin-bottom:16px;color:#e0e0e0}
        .no-comments h4{font-size:16px;color:#262626;margin-bottom:4px}
        .load-more-comments{text-align:center;padding:10px 0}
        .load-more-btn{background:none;border:none;color:#d868ff;cursor:pointer;font-size:14px;font-weight:600;padding:8px 16px}
        .load-more-btn:hover{text-decoration:underline}
        
        .share-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:999;display:none}
        .share-panel{position:fixed;bottom:0;left:50%;transform:translateX(-50%) translateY(100%);width:100%;max-width:430px;background:#fff;border-radius:20px 20px 0 0;box-shadow:0 -10px 40px rgba(0,0,0,0.3);z-index:1001;transition:transform 0.4s cubic-bezier(0.22,1,0.36,1);padding:20px 20px 30px}
        .share-panel.active{transform:translateX(-50%) translateY(0)}
        .share-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
        .share-header h3{font-size:18px;font-weight:700;color:#262626}
        .share-header h3 i{color:#d868ff;margin-right:8px}
        .close-share{background:none;border:none;font-size:24px;cursor:pointer;color:#8e8e8e;padding:4px}
        .close-share:hover{color:#262626}
        .share-options{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
        .share-option{display:flex;flex-direction:column;align-items:center;gap:6px;padding:16px 8px;background:#f8f8f8;border:none;border-radius:12px;cursor:pointer;transition:all 0.2s}
        .share-option:hover{background:#f0f0f0;transform:translateY(-2px)}
        .share-option:active{transform:scale(0.95)}
        .share-option i{font-size:28px}
        .share-option span{font-size:11px;color:#262626;font-weight:500}
        .share-actions{display:flex;gap:10px;border-top:1px solid #f0f0f0;padding-top:16px}
        .share-actions button{flex:1;padding:10px;border:none;border-radius:12px;font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:all 0.2s}
        .share-actions button:active{transform:scale(0.95)}
        .share-save-btn{background:#f0f0f0;color:#262626}
        .share-save-btn:hover{background:#e0e0e0}
        .share-save-btn.saved{background:#d868ff;color:white}
        .share-report-btn{background:#fee2e2;color:#dc2626}
        .share-report-btn:hover{background:#fecaca}
        
        .post-menu-overlay{position:fixed;top:0;left:0;right:0;bottom:0;z-index:999;display:none;background:rgba(0,0,0,0.4)}
        .post-menu-panel{position:absolute;bottom:0;left:0;right:0;background:white;border-radius:20px 20px 0 0;padding:20px 0 30px;animation:slideUp 0.3s ease}
        @keyframes slideUp{from{transform:translateY(100%)}to{transform:translateY(0)}}
        .post-menu-item{display:flex;align-items:center;gap:14px;padding:14px 24px;border:none;background:none;width:100%;font-size:15px;color:#262626;cursor:pointer;border-bottom:1px solid #f5f5f5}
        .post-menu-item:last-child{border-bottom:none}
        .post-menu-item:active{background:#f5f5f5}
        .post-menu-item i{font-size:20px;width:24px;text-align:center}
        .post-menu-item.danger{color:#ed4956}
        .post-menu-item.danger i{color:#ed4956}
        .post-menu-cancel{display:block;width:90%;margin:12px auto 0;padding:12px;border:none;border-radius:12px;background:#f5f5f5;font-size:16px;font-weight:600;color:#262626;cursor:pointer;text-align:center}
        .post-menu-cancel:active{background:#e5e5e5}
        
        .video-mute-btn{position:absolute;bottom:20px;right:20px;z-index:15;background:rgba(0,0,0,0.6);backdrop-filter:blur(8px);width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:20px;cursor:pointer;border:1px solid rgba(255,255,255,0.15);transition:all 0.3s ease}
        .video-mute-btn:hover{background:rgba(255,255,255,0.2);transform:scale(1.05)}
        .video-mute-btn:active{transform:scale(0.9)}
        .video-mute-btn.muted{background:rgba(255,0,0,0.4);border-color:rgba(255,0,0,0.3)}
        
        .bottom-nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:430px;height:65px;background:linear-gradient(45deg,#ff73d2,#d868ff);display:flex;justify-content:space-around;align-items:center;border-radius:25px 25px 0 0;padding:0 12px;z-index:50}
        .bottom-nav a{display:flex;align-items:center;justify-content:center;text-decoration:none;color:white;opacity:0.85;font-size:24px}
        .bottom-nav a:hover{opacity:1}
        .plus-btn{width:58px;height:58px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;margin-top:-28px;text-decoration:none;box-shadow:0 4px 15px rgba(0,0,0,0.3)}
        .plus-btn:hover{transform:scale(1.1)}
        .plus-btn i{color:#000;font-size:30px}
        .bottom-spacer{height:65px}
        
        .flash-messages{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:999;width:90%;max-width:400px}
        .flash-message{padding:10px 16px;border-radius:10px;margin-bottom:6px;color:#fff;font-weight:500;text-align:center;animation:slideDown 0.3s ease}
        .flash-message.success{background:#28a745}
        .flash-message.danger{background:#dc3545}
        .flash-message.warning{background:#ffc107;color:#333}
        .flash-message.info{background:#17a2b8}
        @keyframes slideDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
    </style>
</head>
<body>
    <div class="flash-messages">{% for category, message in flashes %}<div class="flash-message {{ category }}">{{ message }}</div>{% endfor %}</div>
    <div class="header"><a href="{{ url_for('feed') }}"><i class="fa-solid fa-arrow-left"></i></a><h1>Post</h1><div style="width:30px;"></div></div>
    <div class="post-card">{% if post.media_type == 'video' %}<video class="post-media" id="postVideo" playsinline autoplay muted loop><source src="/{{ post.media_url }}" type="video/mp4"></video><div class="video-mute-btn" id="muteBtnView" onclick="event.stopPropagation(); toggleMuteView()"><i class="fa-solid fa-volume-xmark"></i></div>{% else %}<img class="post-media" src="/{{ post.media_url }}" onerror="this.src='/static/default_post.svg'">{% endif %}</div>
    <div class="post-info"><div class="post-user"><img src="/static/uploads/{{ post.profile_pic }}" onerror="this.src='/static/default.svg'"><div><div class="name">{{ post.full_name|e or post.username|e }}</div><div class="username">@{{ post.username|e }}</div></div></div><div class="post-caption"><strong>{{ post.username|e }}</strong> {{ post.caption|e or '' }}</div>
    <div class="post-actions"><button onclick="event.stopPropagation(); toggleLikeView({{ post.id }})">{% if post.liked_by_user %}<i class="fa-solid fa-heart" id="viewLikeIcon" style="color:#ed4956;"></i>{% else %}<i class="fa-regular fa-heart" id="viewLikeIcon"></i>{% endif %}<span class="action-label" id="viewLikeCount">{{ post.like_count }}</span></button><button onclick="event.stopPropagation(); openCommentPanelView({{ post.id }})"><i class="fa-regular fa-comment"></i><span class="action-label">{{ post.comment_count }}</span></button><button onclick="event.stopPropagation(); openSharePanelView({{ post.id }})"><i class="fa-regular fa-paper-plane"></i><span class="action-label">Share</span></button><button onclick="event.stopPropagation(); openPostMenuView({{ post.id }})"><i class="fa-solid fa-ellipsis-h"></i><span class="action-label">More</span></button></div>
    <div class="post-stats"><i class="fa-regular fa-heart"></i> <span id="viewLikeCount2">{{ post.like_count }}</span> likes · <i class="fa-regular fa-comment"></i> {{ post.comment_count }} comments</div></div>
    
    <!-- Comment Panel -->
    <div class="comment-overlay" id="commentOverlay" onclick="closeCommentPanelView()"></div>
    <div class="comment-panel" id="commentPanel">
        <div class="panel-header">
            <div class="panel-header-left">
                <button class="close-panel" onclick="closeCommentPanelView()"><i class="fa-solid fa-chevron-down"></i></button>
                <h3>Comments</h3>
                <span id="commentCountPanel" class="comment-count">0</span>
            </div>
            <button onclick="closeCommentPanelView()" class="close-btn"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="panel-input-top">
            <img id="commentUserAvatar" src="/static/uploads/{{ current_user.profile_pic }}" onerror="this.src='/static/default.svg'" class="comment-avatar">
            <input type="text" id="commentInputView" placeholder="Write a comment..." maxlength="500">
            <button onclick="submitCommentView()" id="commentSubmitBtn"><i class="fa-regular fa-paper-plane"></i></button>
        </div>
        <div class="panel-comments" id="panelCommentsView"><div class="loading-comments"><i class="fa-solid fa-spinner fa-spin"></i> Loading comments...</div></div>
        <div class="panel-footer"><span id="replyIndicatorView" style="display:none;">Replying to <strong id="replyToNameView"></strong><button onclick="cancelReplyView()" class="cancel-reply"><i class="fa-solid fa-xmark"></i></button></span></div>
        <input type="hidden" id="replyToView" value="">
    </div>
    
    <!-- Share Panel -->
    <div class="share-overlay" id="shareOverlayView" onclick="closeSharePanelView()"></div>
    <div class="share-panel" id="sharePanelView">
        <div class="share-header">
            <h3><i class="fa-regular fa-share-from-square"></i> Share</h3>
            <button onclick="closeSharePanelView()" class="close-share"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="share-content">
            <div class="share-options">
                <button onclick="shareActionView('copy')" class="share-option"><i class="fa-solid fa-link"></i><span>Copy Link</span></button>
                <button onclick="shareActionView('whatsapp')" class="share-option"><i class="fa-brands fa-whatsapp" style="color:#25D366;"></i><span>WhatsApp</span></button>
                <button onclick="shareActionView('twitter')" class="share-option"><i class="fa-brands fa-twitter" style="color:#1DA1F2;"></i><span>Twitter</span></button>
                <button onclick="shareActionView('facebook')" class="share-option"><i class="fa-brands fa-facebook" style="color:#1877F2;"></i><span>Facebook</span></button>
                <button onclick="shareActionView('instagram')" class="share-option"><i class="fa-brands fa-instagram" style="color:#E4405F;"></i><span>Instagram</span></button>
                <button onclick="shareActionView('telegram')" class="share-option"><i class="fa-brands fa-telegram" style="color:#0088CC;"></i><span>Telegram</span></button>
            </div>
            <div class="share-actions">
                <button onclick="shareActionView('save')" class="share-save-btn"><i class="fa-regular fa-bookmark"></i> Save Post</button>
                <button onclick="shareActionView('report')" class="share-report-btn"><i class="fa-regular fa-flag"></i> Report</button>
            </div>
        </div>
    </div>
    
    <!-- Post Menu -->
    <div class="post-menu-overlay" id="postMenuOverlay" onclick="closePostMenuView()">
        <div class="post-menu-panel" onclick="event.stopPropagation()">
            <button class="post-menu-item" onclick="shareActionView('copy')"><i class="fa-regular fa-share-from-square"></i> Share</button>
            <button class="post-menu-item" onclick="savePostFromMenuView()" id="menuSaveView"><i class="fa-regular fa-bookmark"></i> Save</button>
            <button class="post-menu-item danger" onclick="deletePostFromMenuView()" id="menuDeleteView"><i class="fa-solid fa-trash"></i> Delete</button>
            <button class="post-menu-cancel" onclick="closePostMenuView()">Cancel</button>
        </div>
    </div>
    
    <div class="bottom-spacer"></div>
    <div class="bottom-nav">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-house"></i></a>
        <a href="{{ url_for('explore') }}"><i class="fa-regular fa-compass"></i></a>
        <a href="{{ url_for('upload') }}" class="plus-btn"><i class="fa-solid fa-plus"></i></a>
        <a href="{{ url_for('notifications') }}"><i class="fa-regular fa-bell"></i></a>
        <a href="{{ url_for('profile', username=current_user.username) }}"><i class="fa-regular fa-user"></i></a>
    </div>
    
    <input type="hidden" id="csrf_token" value="{{ csrf_token() }}">
    
    <script>
        function getCsrfToken() {
            var el = document.getElementById('csrf_token');
            if (!el) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.id = 'csrf_token';
                input.value = '{{ csrf_token() }}';
                document.body.appendChild(input);
                return input.value;
            }
            return el.value;
        }
        
        function flash(message, type) {
            var container = document.querySelector('.flash-messages');
            if (!container) return;
            var div = document.createElement('div');
            div.className = 'flash-message ' + (type || 'info');
            div.textContent = message;
            container.appendChild(div);
            setTimeout(function() {
                div.style.transition = 'opacity 0.5s';
                div.style.opacity = '0';
                setTimeout(function() { div.remove(); }, 500);
            }, 4000);
        }
        
        function toggleMuteView() {
            var video = document.getElementById('postVideo');
            if (!video) return;
            video.muted = !video.muted;
            var muteBtn = document.getElementById('muteBtnView');
            if (muteBtn) {
                if (video.muted) {
                    muteBtn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i>';
                    muteBtn.classList.add('muted');
                } else {
                    muteBtn.innerHTML = '<i class="fa-solid fa-volume-high"></i>';
                    muteBtn.classList.remove('muted');
                }
            }
        }
        
        // ===== LIKE =====
        function toggleLikeView(postId) {
            var csrf = getCsrfToken();
            if (!csrf) {
                flash('Session expired. Please refresh.', 'danger');
                return;
            }
            var icon = document.getElementById('viewLikeIcon');
            var countSpan = document.getElementById('viewLikeCount');
            var countSpan2 = document.getElementById('viewLikeCount2');
            if (!icon || !countSpan) {
                console.error('Like elements not found');
                return;
            }
            
            var isLiked = icon.classList.contains('fa-solid');
            var currentCount = parseInt(countSpan.textContent) || 0;
            
            if (isLiked) {
                icon.className = 'fa-regular fa-heart';
                icon.style.color = '';
                countSpan.textContent = Math.max(0, currentCount - 1);
                if (countSpan2) countSpan2.textContent = Math.max(0, currentCount - 1);
            } else {
                icon.className = 'fa-solid fa-heart';
                icon.style.color = '#ed4956';
                countSpan.textContent = currentCount + 1;
                if (countSpan2) countSpan2.textContent = currentCount + 1;
            }
            
            fetch('/api/like/' + postId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) {
                if (!response.ok) throw new Error('Server error');
                return response.json();
            })
            .then(function(data) {
                if (data.success) {
                    if (data.liked) {
                        icon.className = 'fa-solid fa-heart';
                        icon.style.color = '#ed4956';
                    } else {
                        icon.className = 'fa-regular fa-heart';
                        icon.style.color = '';
                    }
                    countSpan.textContent = data.like_count;
                    if (countSpan2) countSpan2.textContent = data.like_count;
                }
            })
            .catch(function(error) {
                console.error('Like error:', error);
                flash('Error liking post.', 'danger');
                if (isLiked) {
                    icon.className = 'fa-solid fa-heart';
                    icon.style.color = '#ed4956';
                    countSpan.textContent = currentCount + 1;
                    if (countSpan2) countSpan2.textContent = currentCount + 1;
                } else {
                    icon.className = 'fa-regular fa-heart';
                    icon.style.color = '';
                    countSpan.textContent = currentCount;
                    if (countSpan2) countSpan2.textContent = currentCount;
                }
            });
        }
        
        // ===== COMMENTS =====
        var currentPostIdView = {{ post.id }};
        var commentPageView = 1;
        var hasMoreCommentsView = true;
        var isLoadingCommentsView = false;
        
        function openCommentPanelView(postId) {
            currentPostIdView = postId;
            document.getElementById('replyToView').value = '';
            document.getElementById('replyIndicatorView').style.display = 'none';
            document.getElementById('commentInputView').value = '';
            document.getElementById('commentSubmitBtn').disabled = false;
            var panel = document.getElementById('commentPanel');
            var overlay = document.getElementById('commentOverlay');
            overlay.style.display = 'block';
            overlay.classList.add('active');
            panel.classList.add('active');
            document.body.style.overflow = 'hidden';
            commentPageView = 1;
            hasMoreCommentsView = true;
            loadCommentsView(postId, 1);
            setTimeout(function() { document.getElementById('commentInputView').focus(); }, 400);
        }
        
        function closeCommentPanelView() {
            var panel = document.getElementById('commentPanel');
            var overlay = document.getElementById('commentOverlay');
            panel.classList.remove('active');
            overlay.classList.remove('active');
            overlay.style.display = 'none';
            document.body.style.overflow = '';
        }
        
        function loadCommentsView(postId, page) {
            if (isLoadingCommentsView || !hasMoreCommentsView) return;
            isLoadingCommentsView = true;
            var container = document.getElementById('panelCommentsView');
            if (page === 1) {
                container.innerHTML = '<div class="loading-comments"><i class="fa-solid fa-spinner fa-spin"></i> Loading comments...</div>';
            }
            fetch('/api/comments/' + postId + '?page=' + page + '&per_page=20')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    isLoadingCommentsView = false;
                    var countSpan = document.getElementById('commentCountPanel');
                    if (data.total !== undefined) countSpan.textContent = data.total;
                    if (page === 1) container.innerHTML = '';
                    if (!data.comments || data.comments.length === 0) {
                        if (page === 1) {
                            container.innerHTML = '<div class="no-comments"><i class="fa-regular fa-comment-dots"></i><h4>No comments yet</h4><p>Be the first to comment!</p></div>';
                        }
                        hasMoreCommentsView = false;
                        return;
                    }
                    if (data.comments.length < 20) hasMoreCommentsView = false;
                    data.comments.forEach(function(c) {
                        var div = document.createElement('div');
                        div.className = 'comment-item' + (c.parent_id ? ' reply' : '');
                        div.id = 'comment-' + c.id;
                        var isOwner = c.user_id === {{ current_user.id }};
                        var deleteBtn = isOwner ? '<button onclick="deleteCommentView(' + c.id + ')" class="delete-comment"><i class="fa-regular fa-trash-can"></i></button>' : '';
                        div.innerHTML = 
                            '<div class="comment-user"><img src="/static/uploads/' + (c.profile_pic || 'default.svg') + '" onerror="this.src=\'/static/default.svg\'"><strong>' + escapeHtml(c.username) + '</strong><span class="comment-time">' + formatTime(c.created_at) + '</span></div>' +
                            '<div class="comment-text">' + escapeHtml(c.text) + '</div>' +
                            '<div class="comment-actions"><button onclick="setReplyToView(' + c.id + ', \'' + escapeHtml(c.username) + '\')" class="reply-btn"><i class="fa-regular fa-reply"></i> Reply</button>' + deleteBtn + '</div>';
                        container.appendChild(div);
                    });
                    if (hasMoreCommentsView) {
                        var loadMore = document.createElement('div');
                        loadMore.className = 'load-more-comments';
                        loadMore.innerHTML = '<button onclick="loadMoreCommentsView()" class="load-more-btn">Load more comments</button>';
                        container.appendChild(loadMore);
                    }
                })
                .catch(function(error) {
                    console.error('Error loading comments:', error);
                    isLoadingCommentsView = false;
                    if (page === 1) {
                        container.innerHTML = '<div class="no-comments" style="color:#dc3545;">Error loading comments. Please try again.</div>';
                    }
                });
        }
        
        function loadMoreCommentsView() {
            if (!hasMoreCommentsView || isLoadingCommentsView) return;
            commentPageView++;
            loadCommentsView(currentPostIdView, commentPageView);
        }
        
        function submitCommentView() {
            var postId = currentPostIdView;
            var text = document.getElementById('commentInputView').value.trim();
            var replyTo = document.getElementById('replyToView').value;
            var csrf = getCsrfToken();
            if (!text || !postId) { flash('Please write a comment.', 'warning'); return; }
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            
            var btn = document.getElementById('commentSubmitBtn');
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
            btn.disabled = true;
            
            fetch('/api/comment', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    post_id: postId,
                    text: text,
                    reply_to: replyTo ? parseInt(replyTo) : null
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    document.getElementById('commentInputView').value = '';
                    document.getElementById('replyToView').value = '';
                    document.getElementById('replyIndicatorView').style.display = 'none';
                    commentPageView = 1;
                    hasMoreCommentsView = true;
                    loadCommentsView(postId, 1);
                    flash('Comment posted!', 'success');
                } else {
                    flash(data.error || 'Error posting comment', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error posting comment:', error);
                flash('Error posting comment. Please try again.', 'danger');
            })
            .finally(function() {
                btn.innerHTML = '<i class="fa-regular fa-paper-plane"></i>';
                btn.disabled = false;
            });
        }
        
        function setReplyToView(commentId, username) {
            document.getElementById('replyToView').value = commentId;
            document.getElementById('replyToNameView').textContent = username;
            document.getElementById('replyIndicatorView').style.display = 'block';
            document.getElementById('commentInputView').value = '@' + username + ' ';
            document.getElementById('commentInputView').focus();
        }
        
        function cancelReplyView() {
            document.getElementById('replyToView').value = '';
            document.getElementById('replyIndicatorView').style.display = 'none';
            document.getElementById('commentInputView').value = '';
        }
        
        function deleteCommentView(commentId) {
            if (!confirm('Delete this comment?')) return;
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            fetch('/api/comment/' + commentId, {
                method: 'DELETE',
                headers: { 'X-CSRFToken': csrf },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    var commentEl = document.getElementById('comment-' + commentId);
                    if (commentEl) commentEl.remove();
                    flash('Comment deleted.', 'info');
                } else {
                    flash(data.error || 'Error deleting comment', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error deleting comment:', error);
                flash('Error deleting comment. Please try again.', 'danger');
            });
        }
        
        document.getElementById('commentInputView').addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                submitCommentView();
            }
        });
        
        // ===== SHARE =====
        var sharePostIdView = {{ post.id }};
        var sharePostUrlView = window.location.origin + '/post/{{ post.id }}';
        
        function openSharePanelView(postId) {
            sharePostIdView = postId;
            sharePostUrlView = window.location.origin + '/post/' + postId;
            var panel = document.getElementById('sharePanelView');
            var overlay = document.getElementById('shareOverlayView');
            panel.dataset.postId = postId;
            panel.dataset.url = sharePostUrlView;
            overlay.style.display = 'block';
            panel.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
        
        function closeSharePanelView() {
            var overlay = document.getElementById('shareOverlayView');
            var panel = document.getElementById('sharePanelView');
            overlay.style.display = 'none';
            panel.classList.remove('active');
            document.body.style.overflow = '';
        }
        
        function shareActionView(action) {
            var panel = document.getElementById('sharePanelView');
            var url = panel ? panel.dataset.url : sharePostUrlView;
            var postId = panel ? panel.dataset.postId : sharePostIdView;
            var text = 'Check out this post on FlowUp!';
            
            switch(action) {
                case 'copy':
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(url).then(function() {
                            flash('Link copied to clipboard!', 'success');
                            closeSharePanelView();
                            closePostMenuView();
                        }).catch(function() { copyLinkFallbackView(url); });
                    } else {
                        copyLinkFallbackView(url);
                    }
                    break;
                case 'whatsapp':
                    window.open('https://wa.me/?text=' + encodeURIComponent(text + ' ' + url), '_blank');
                    closeSharePanelView();
                    closePostMenuView();
                    break;
                case 'twitter':
                    window.open('https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(url), '_blank');
                    closeSharePanelView();
                    closePostMenuView();
                    break;
                case 'facebook':
                    window.open('https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url), '_blank');
                    closeSharePanelView();
                    closePostMenuView();
                    break;
                case 'instagram':
                    flash('Open Instagram app and paste this link: ' + url, 'info');
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(url);
                    }
                    closeSharePanelView();
                    closePostMenuView();
                    break;
                case 'telegram':
                    window.open('https://t.me/share/url?url=' + encodeURIComponent(url) + '&text=' + encodeURIComponent(text), '_blank');
                    closeSharePanelView();
                    closePostMenuView();
                    break;
                case 'save':
                    toggleSavePostView(postId);
                    closeSharePanelView();
                    closePostMenuView();
                    break;
                case 'report':
                    reportPostView(postId);
                    closeSharePanelView();
                    closePostMenuView();
                    break;
            }
        }
        
        function copyLinkFallbackView(url) {
            var textarea = document.createElement('textarea');
            textarea.value = url;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                flash('Link copied to clipboard!', 'success');
                closeSharePanelView();
                closePostMenuView();
            } catch(err) {
                flash('Failed to copy link. Please copy manually.', 'warning');
            }
            document.body.removeChild(textarea);
        }
        
        // ===== POST MENU =====
        var menuPostIdView = {{ post.id }};
        
        function openPostMenuView(postId) {
            menuPostIdView = postId;
            var overlay = document.getElementById('postMenuOverlay');
            overlay.style.display = 'block';
            document.body.style.overflow = 'hidden';
            var isOwner = {{ post.is_owner|tojson }};
            var deleteBtn = document.getElementById('menuDeleteView');
            if (deleteBtn) {
                deleteBtn.style.display = isOwner ? 'flex' : 'none';
            }
        }
        
        function closePostMenuView() {
            var overlay = document.getElementById('postMenuOverlay');
            overlay.style.display = 'none';
            document.body.style.overflow = '';
        }
        
        function deletePostFromMenuView() {
            if (!menuPostIdView) return;
            if (!confirm('Delete this post? This cannot be undone.')) return;
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            fetch('/api/post/' + menuPostIdView, {
                method: 'DELETE',
                headers: { 'X-CSRFToken': csrf },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    flash('Post deleted.', 'info');
                    closePostMenuView();
                    window.location.href = '/feed';
                } else {
                    flash(data.error || 'Error deleting post', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error deleting post:', error);
                flash('Error deleting post. Please try again.', 'danger');
            });
        }
        
        function savePostFromMenuView() {
            if (menuPostIdView) {
                toggleSavePostView(menuPostIdView);
                closePostMenuView();
            }
        }
        
        function toggleSavePostView(postId) {
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            var saveBtn = document.getElementById('menuSaveView');
            var originalText = saveBtn.innerHTML;
            saveBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
            saveBtn.disabled = true;
            
            fetch('/api/save/' + postId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    if (data.saved) {
                        saveBtn.innerHTML = '<i class="fa-solid fa-bookmark"></i> Saved';
                        flash('Post saved!', 'success');
                    } else {
                        saveBtn.innerHTML = '<i class="fa-regular fa-bookmark"></i> Save';
                        flash('Post unsaved.', 'info');
                    }
                } else {
                    flash(data.error || 'Error saving post', 'danger');
                    saveBtn.innerHTML = originalText;
                }
            })
            .catch(function(error) {
                console.error('Error saving post:', error);
                flash('Error saving post. Please try again.', 'danger');
                saveBtn.innerHTML = originalText;
            })
            .finally(function() {
                saveBtn.disabled = false;
            });
        }
        
        function reportPostView(postId) {
            if (!confirm('Report this post? This will be reviewed by moderators.')) return;
            var csrf = getCsrfToken();
            if (!csrf) { flash('Session expired. Please refresh.', 'danger'); return; }
            
            fetch('/api/report/' + postId, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                credentials: 'same-origin'
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    flash('Post reported. Thank you for helping keep our community safe.', 'success');
                } else {
                    flash(data.error || 'Error reporting post', 'danger');
                }
            })
            .catch(function(error) {
                console.error('Error reporting post:', error);
                flash('Error reporting post. Please try again.', 'danger');
            });
        }
        
        // ===== UTILITY =====
        function escapeHtml(text) {
            if (!text) return '';
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatTime(timestamp) {
            var date = new Date(timestamp);
            var now = new Date();
            var diff = Math.floor((now - date) / 1000);
            if (diff < 60) return 'Just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h';
            if (diff < 604800) return Math.floor(diff / 86400) + 'd';
            return date.toLocaleDateString();
        }
        
        // ===== KEYBOARD =====
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                if (document.getElementById('commentPanel').classList.contains('active')) closeCommentPanelView();
                if (document.getElementById('sharePanelView').classList.contains('active')) closeSharePanelView();
                if (document.getElementById('postMenuOverlay').style.display === 'block') closePostMenuView();
            }
        });
        
        // ===== AUTO DISMISS FLASH =====
        setTimeout(function() {
            document.querySelectorAll('.flash-message').forEach(function(el) {
                el.style.transition = 'opacity 0.5s';
                el.style.opacity = '0';
                setTimeout(function() { el.remove(); }, 500);
            });
        }, 4000);
        
        // ===== VIDEO INIT =====
        document.addEventListener('DOMContentLoaded', function() {
            var video = document.getElementById('postVideo');
            if (video) {
                var muteBtn = document.getElementById('muteBtnView');
                if (muteBtn && video.muted) {
                    muteBtn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i>';
                    muteBtn.classList.add('muted');
                }
            }
        });
    </script>
</body>
</html>
'''
PROFILE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Profile - FlowUp</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { max-width:430px; margin:auto; padding:20px; background:#ffffff; min-height:100vh; padding-bottom:20px; }
        .profile-header { text-align:center; margin-bottom:20px; }
        .profile-header .avatar-wrapper { width:100px; height:100px; border-radius:50%; margin:0 auto; border:3px solid #d868ff; overflow:hidden; position:relative; background:linear-gradient(135deg, #d868ff, #ff73d2); cursor:pointer; transition:transform 0.3s ease; }
        .profile-header .avatar-wrapper:hover { transform:scale(1.05); }
        .profile-header .avatar-wrapper:active { transform:scale(0.95); }
        .profile-header .avatar-wrapper img { width:100%; height:100%; object-fit:cover; display:block; }
        .profile-header .name { margin:10px 0 5px; font-size:22px; font-weight:700; color:#262626; }
        .profile-header .bio { color:#555; font-size:14px; margin:5px 0; word-wrap:break-word; max-width:300px; margin-left:auto; margin-right:auto; }
        .profile-header .username { color:#888; font-size:15px; margin-bottom:5px; }
        .online-status { display:inline-block; width:12px; height:12px; border-radius:50%; margin-left:8px; border:2px solid #fff; }
        .online-status.online { background:#2ecc71; }
        .online-status.offline { background:#95a5a6; }
        .stats { display:flex; justify-content:center; gap:40px; margin:15px 0; }
        .stats .stat-item { text-align:center; cursor:pointer; }
        .stats .stat-number { font-size:18px; font-weight:700; color:#262626; }
        .stats .stat-label { font-size:12px; color:#888; margin-top:2px; }
        .action-buttons { display:flex; justify-content:center; gap:10px; flex-wrap:wrap; margin-top:10px; }
        .action-buttons .btn { padding:8px 30px; border-radius:25px; border:none; font-weight:600; cursor:pointer; transition:all 0.3s; text-decoration:none; display:inline-block; }
        .action-buttons .btn-primary { background:#d868ff; color:white; }
        .action-buttons .btn-primary:hover { opacity:0.85; transform:scale(1.02); }
        .action-buttons .btn-secondary { background:#eee; color:#262626; }
        .action-buttons .btn-secondary:hover { background:#ddd; }
        .profile-tabs { display:flex; border-top:1px solid #e0e0e0; margin-top:20px; margin-bottom:4px; }
        .profile-tabs .tab { flex:1; text-align:center; padding:12px 0; font-size:14px; font-weight:600; color:#888; cursor:pointer; transition:all 0.3s; border-bottom:2px solid transparent; display:flex; align-items:center; justify-content:center; gap:8px; }
        .profile-tabs .tab:hover { color:#262626; background:#f5f5f5; }
        .profile-tabs .tab.active { color:#d868ff; border-bottom:2px solid #d868ff; }
        .profile-tabs .tab i { font-size:16px; }
        .profile-tabs .tab .count { font-size:11px; color:#999; font-weight:400; }
        .profile-tabs .tab.active .count { color:#d868ff; }
        .post-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:4px; margin-top:4px; background:#ffffff; }
        .post-grid a { display:block; aspect-ratio:1/1; overflow:hidden; border-radius:4px; background:#f5f5f5; position:relative; min-height:120px; }
        .post-grid a img, .post-grid a video { width:100%; height:100%; object-fit:cover; display:block; background:#f5f5f5; }
        .post-grid .media-overlay { position:absolute; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.4); display:flex; align-items:center; justify-content:center; opacity:0; transition:opacity 0.3s; color:white; gap:16px; }
        .post-grid a:hover .media-overlay { opacity:1; }
        .post-grid .media-overlay span { display:flex; align-items:center; gap:4px; font-size:14px; font-weight:600; }
        .header { background:white; padding:14px 20px; border-bottom:1px solid #f0f0f0; margin:-20px -20px 20px -20px; display:flex; align-items:center; gap:15px; }
        .header h2 { font-size:22px; flex:1; color:#262626; }
        .header a { color:#262626; font-size:22px; text-decoration:none; }
        .no-posts { text-align:center; padding:60px 20px; color:#999; grid-column:1/4; background:#ffffff; }
        .no-posts i { font-size:48px; display:block; margin-bottom:10px; color:#ddd; }
        .no-posts h4 { color:#262626; margin-bottom:4px; }
        .no-posts p { color:#888; font-size:14px; }
        .pagination { display:flex; justify-content:center; gap:8px; padding:15px 0; grid-column:1/4; background:#ffffff; }
        .pagination a { padding:6px 14px; background:#eee; color:#333; border-radius:20px; text-decoration:none; font-size:13px; }
        .pagination a:hover { background:#ddd; }
        .pagination a.active { background:linear-gradient(135deg, #d868ff, #ff73d2); color:white; }
        .tab-content { display:none; }
        .tab-content.active { display:block; }
        .flash-messages { position:fixed; top:60px; left:50%; transform:translateX(-50%); z-index:999; width:90%; max-width:400px; }
        .flash-message { padding:10px 16px; border-radius:10px; margin-bottom:6px; color:#fff; font-weight:500; text-align:center; }
        .flash-message.success { background:#28a745; }
        .flash-message.danger { background:#dc3545; }
        .flash-message.warning { background:#ffc107; color:#333; }
        .profile-viewer-overlay { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.92); z-index:10000; display:none; align-items:center; justify-content:center; backdrop-filter:blur(30px); -webkit-backdrop-filter:blur(30px); animation:fadeIn 0.3s ease; padding:0; }
        .profile-viewer-overlay.active { display:flex; }
        @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
        .profile-viewer-content { position:relative; width:100%; height:100%; display:flex; flex-direction:column; align-items:center; justify-content:center; animation:scaleIn 0.4s cubic-bezier(0.34, 1.56, 0.64, 1); padding:60px 20px 80px 20px; }
        @keyframes scaleIn { from { transform:scale(0.9); opacity:0; } to { transform:scale(1); opacity:1; } }
        .profile-viewer-content .viewer-image-wrapper { width:100%; max-width:500px; max-height:75vh; border-radius:16px; overflow:hidden; border:2px solid rgba(255,255,255,0.1); box-shadow:0 0 60px rgba(216,104,255,0.2), 0 0 120px rgba(216,104,255,0.05); background:#1a1a2e; position:relative; }
        .profile-viewer-content .viewer-image-wrapper img { width:100%; height:100%; max-height:75vh; object-fit:contain; display:block; }
        .profile-viewer-content .viewer-image-wrapper::before { content:''; position:absolute; inset:-3px; border-radius:18px; padding:3px; background:conic-gradient(from 0deg, #d868ff, #ff73d2, #d868ff, #ff73d2, #d868ff); -webkit-mask:linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0); -webkit-mask-composite:xor; mask-composite:exclude; animation:spinGlow 6s linear infinite; opacity:0.4; }
        @keyframes spinGlow { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }
        .profile-viewer-content .viewer-info { text-align:center; color:white; width:100%; max-width:500px; padding:16px 20px; margin-top:20px; background:rgba(0,0,0,0.4); backdrop-filter:blur(10px); border-radius:16px; border:1px solid rgba(255,255,255,0.05); }
        .profile-viewer-content .viewer-info .name { font-size:22px; font-weight:700; margin-bottom:2px; background:linear-gradient(45deg, #fff, #d868ff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
        .profile-viewer-content .viewer-info .username { font-size:15px; color:rgba(255,255,255,0.6); }
        .profile-viewer-content .viewer-info .bio { font-size:13px; color:rgba(255,255,255,0.4); margin-top:4px; }
        .profile-viewer-close { position:fixed; top:20px; right:20px; background:rgba(255,255,255,0.1); backdrop-filter:blur(10px); border:1px solid rgba(255,255,255,0.15); color:white; font-size:28px; width:50px; height:50px; border-radius:50%; cursor:pointer; transition:all 0.3s ease; display:flex; align-items:center; justify-content:center; z-index:10; }
        .profile-viewer-close:hover { background:rgba(255,0,0,0.3); transform:rotate(90deg) scale(1.1); }
        .profile-viewer-close:active { transform:scale(0.9); }
        .profile-viewer-bg { position:fixed; top:-50px; left:-50px; right:-50px; bottom:-50px; z-index:-1; background-size:cover; background-position:center; filter:blur(50px) brightness(0.3) saturate(0.5); transform:scale(1.1); }
        .viewer-hint { color:rgba(255,255,255,0.15); font-size:11px; margin-top:12px; letter-spacing:2px; animation:pulseHint 2s ease-in-out infinite; }
        @keyframes pulseHint { 0%,100% { opacity:0.15; } 50% { opacity:0.5; } }
        @media (max-width:430px) { body { padding:12px; } .header { margin:-12px -12px 20px -12px; padding:12px 16px; } .profile-header .avatar-wrapper { width:80px; height:80px; } .stats { gap:20px; } .profile-tabs .tab { font-size:12px; padding:10px 0; } .post-grid a { min-height:120px; } .profile-viewer-content .viewer-image-wrapper { max-height:65vh; border-radius:12px; } .profile-viewer-content .viewer-image-wrapper img { max-height:65vh; } .profile-viewer-close { top:12px; right:12px; width:42px; height:42px; font-size:22px; } .profile-viewer-content .viewer-info { padding:12px 16px; margin-top:14px; } .profile-viewer-content .viewer-info .name { font-size:18px; } .profile-viewer-content .viewer-info .username { font-size:13px; } .profile-viewer-content .viewer-info .bio { font-size:12px; } .profile-viewer-content { padding:50px 16px 60px 16px; } }
    </style>
</head>
<body>
    <div class="flash-messages">
        {% for category, message in flashes %}
        <div class="flash-message {{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    <div class="header">
        <a href="{{ url_for('feed') }}"><i class="fa-solid fa-arrow-left"></i></a>
        <h2>{{ user.username|e }}</h2>
        <a href="{{ url_for('settings') }}"><i class="fa-solid fa-gear"></i></a>
    </div>
    <div class="profile-header">
        <div class="avatar-wrapper" onclick="openProfileViewer()">
            <img id="profileAvatar" src="/static/uploads/{{ user.profile_pic }}" onerror="this.src='/static/default.svg'" alt="{{ user.username }}'s profile picture">
        </div>
        <div class="name">
            {{ user.full_name|e or user.username|e }}
            <span class="online-status {% if user.online_status == 'online' %}online{% elif user.online_status == 'sleep' %}sleep{% else %}offline{% endif %}" title="{% if user.online_status == 'online' %}Online{% elif user.online_status == 'sleep' %}Away{% else %}Offline{% endif %}"></span>
        </div>
        <div class="username">@{{ user.username|e }}</div>
        <div class="bio">{{ user.bio|e or '' }}</div>
        <div class="stats">
            <div class="stat-item"><div class="stat-number">{{ total_posts + total_reels }}</div><div class="stat-label">Posts</div></div>
            <div class="stat-item"><div class="stat-number">{{ followers_count }}</div><div class="stat-label">Followers</div></div>
            <div class="stat-item"><div class="stat-number">{{ following_count }}</div><div class="stat-label">Following</div></div>
        </div>
        <div class="action-buttons">
            {% if current_user.id != user.id %}
                <a href="{{ follow_url }}" class="btn btn-primary">{{ follow_action }}</a>
                {% if is_mutual %}
                    <a href="{{ url_for('chat_with_user', user_id=user.id) }}" class="btn btn-secondary"><i class="fa-regular fa-message"></i> Message</a>
                {% endif %}
            {% else %}
                <a href="{{ url_for('edit_profile') }}" class="btn btn-primary"><i class="fa-regular fa-pen-to-square"></i> Edit Profile</a>
                <a href="{{ url_for('history') }}" class="btn btn-secondary"><i class="fa-regular fa-clock"></i> History</a>
            {% endif %}
        </div>
    </div>
    <div class="profile-tabs">
        <div class="tab active" onclick="switchTab('posts')" id="tabPosts"><i class="fa-regular fa-image"></i> Posts <span class="count">({{ total_posts }})</span></div>
        <div class="tab" onclick="switchTab('reels')" id="tabReels"><i class="fa-solid fa-video"></i> Reels <span class="count">({{ total_reels }})</span></div>
    </div>
    <div class="tab-content active" id="postsContent">
        <div class="post-grid">
            {% if posts %}
                {% for p in posts %}
                <a href="{{ url_for('view_post', post_id=p.id) }}">
                    {% if p.media_type == 'image' %}
                        <img src="/{{ p.media_url }}" loading="lazy" onerror="this.src='/static/default_post.svg'">
                    {% else %}
                        <video src="/{{ p.media_url }}" muted preload="metadata"></video>
                    {% endif %}
                    <div class="media-overlay">
                        <span><i class="fa-regular fa-heart"></i> {{ p.like_count }}</span>
                        <span><i class="fa-regular fa-comment"></i> {{ p.comment_count }}</span>
                    </div>
                </a>
                {% endfor %}
                {% if total_post_pages and total_post_pages > 1 %}
                <div class="pagination">
                    {% if post_page > 1 %}<a href="?post_page={{ post_page-1 }}&tab=posts"><i class="fa-solid fa-chevron-left"></i></a>{% endif %}
                    {% for p in range(1, total_post_pages+1) %}
                        {% if p == post_page %}<a href="?post_page={{ p }}&tab=posts" class="active">{{ p }}</a>
                        {% elif p <= 3 or p > total_post_pages-2 %}<a href="?post_page={{ p }}&tab=posts">{{ p }}</a>
                        {% elif p == 4 and total_post_pages > 5 %}<span style="color:#999;">...</span>{% endif %}
                    {% endfor %}
                    {% if post_page < total_post_pages %}<a href="?post_page={{ post_page+1 }}&tab=posts"><i class="fa-solid fa-chevron-right"></i></a>{% endif %}
                </div>
                {% endif %}
            {% else %}
                <div class="no-posts"><i class="fa-regular fa-image"></i><h4>No Posts Yet</h4><p>{% if current_user.id == user.id %}Upload your first post!{% else %}This user hasn't posted yet{% endif %}</p></div>
            {% endif %}
        </div>
    </div>
    <div class="tab-content" id="reelsContent">
        <div class="post-grid">
            {% if reels %}
                {% for r in reels %}
                <a href="{{ url_for('view_reel', reel_id=r.id) }}">
                    <video src="/{{ r.media_url }}" muted preload="metadata"></video>
                    <div class="media-overlay">
                        <span><i class="fa-regular fa-heart"></i> {{ r.like_count }}</span>
                        <span><i class="fa-regular fa-comment"></i> 0</span>
                    </div>
                </a>
                {% endfor %}
                {% if total_reel_pages and total_reel_pages > 1 %}
                <div class="pagination">
                    {% if reel_page > 1 %}<a href="?reel_page={{ reel_page-1 }}&tab=reels"><i class="fa-solid fa-chevron-left"></i></a>{% endif %}
                    {% for p in range(1, total_reel_pages+1) %}
                        {% if p == reel_page %}<a href="?reel_page={{ p }}&tab=reels" class="active">{{ p }}</a>
                        {% elif p <= 3 or p > total_reel_pages-2 %}<a href="?reel_page={{ p }}&tab=reels">{{ p }}</a>
                        {% elif p == 4 and total_reel_pages > 5 %}<span style="color:#999;">...</span>{% endif %}
                    {% endfor %}
                    {% if reel_page < total_reel_pages %}<a href="?reel_page={{ reel_page+1 }}&tab=reels"><i class="fa-solid fa-chevron-right"></i></a>{% endif %}
                </div>
                {% endif %}
            {% else %}
                <div class="no-posts"><i class="fa-solid fa-video"></i><h4>No Reels Yet</h4><p>{% if current_user.id == user.id %}Upload your first reel!{% else %}This user hasn't posted reels yet{% endif %}</p></div>
            {% endif %}
        </div>
    </div>
    <div class="profile-viewer-overlay" id="profileViewer" onclick="closeProfileViewer()">
        <div class="profile-viewer-bg" id="viewerBg"></div>
        <div class="profile-viewer-content" onclick="event.stopPropagation()">
            <button class="profile-viewer-close" onclick="closeProfileViewer()"><i class="fa-solid fa-xmark"></i></button>
            <div class="viewer-image-wrapper"><img id="viewerImage" src="" alt="Profile picture"></div>
            <div class="viewer-info">
                <div class="name">{{ user.full_name|e or user.username|e }}</div>
                <div class="username">@{{ user.username|e }}</div>
                <div class="bio">{{ user.bio|e or '' }}</div>
            </div>
            <div class="viewer-hint">✕ Tap anywhere to close</div>
        </div>
    </div>
    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab-content').forEach(function(el) { el.classList.remove('active'); });
            document.querySelectorAll('.profile-tabs .tab').forEach(function(el) { el.classList.remove('active'); });
            if (tab === 'posts') { document.getElementById('postsContent').classList.add('active'); document.getElementById('tabPosts').classList.add('active'); }
            else { document.getElementById('reelsContent').classList.add('active'); document.getElementById('tabReels').classList.add('active'); }
            var url = new URL(window.location); url.searchParams.set('tab', tab); window.history.pushState({}, '', url);
        }
        document.addEventListener('DOMContentLoaded', function() {
            var params = new URLSearchParams(window.location.search);
            var tab = params.get('tab');
            if (tab) switchTab(tab);
        });
        function openProfileViewer() {
            var avatar = document.getElementById('profileAvatar');
            var viewer = document.getElementById('profileViewer');
            var viewerImg = document.getElementById('viewerImage');
            var bg = document.getElementById('viewerBg');
            var imgSrc = avatar.src;
            viewerImg.src = imgSrc;
            bg.style.backgroundImage = 'url(' + imgSrc + ')';
            viewer.classList.add('active');
            document.body.style.overflow = 'hidden';
            document.addEventListener('touchmove', preventScroll, { passive: false });
        }
        function closeProfileViewer() {
            var viewer = document.getElementById('profileViewer');
            viewer.classList.remove('active');
            document.body.style.overflow = '';
            document.removeEventListener('touchmove', preventScroll);
        }
        function preventScroll(e) { e.preventDefault(); }
        document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeProfileViewer(); });
        var touchStartY = 0;
        var viewer = document.getElementById('profileViewer');
        viewer.addEventListener('touchstart', function(e) { if (viewer.classList.contains('active')) touchStartY = e.touches[0].clientY; }, { passive: true });
        viewer.addEventListener('touchmove', function(e) {
            if (!viewer.classList.contains('active')) return;
            var touchY = e.touches[0].clientY;
            var deltaY = touchY - touchStartY;
            if (deltaY > 80) closeProfileViewer();
        }, { passive: true });
        setTimeout(function() {
            document.querySelectorAll('.flash-message').forEach(function(el) {
                el.style.transition = 'opacity 0.5s';
                el.style.opacity = '0';
                setTimeout(function() { el.remove(); }, 500);
            });
        }, 4000);
        document.getElementById('viewerImage').addEventListener('error', function() { this.src = '/static/default.svg'; });
    </script>
</body>
</html>
'''
# ============================================================
# RUN APP
# ============================================================
if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(STATIC_FOLDER, exist_ok=True)
    
    force_reset = os.environ.get('FORCE_RESET_DB', 'false').lower() == 'true'
    if force_reset and os.path.exists(DATABASE):
        try:
            os.remove(DATABASE)
            print("🗑️ Force deleted old database")
        except:
            pass
    
    if not os.path.exists(DATABASE):
        print("🔄 Creating fresh database...")
        try:
            init_db()
            print("✅ Fresh database created!")
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("✅ Database already exists. Verifying schema...")
        try:
            init_db()
            print("✅ Database schema verified!")
        except Exception as e:
            print(f"❌ Error verifying database: {e}")
            import traceback
            traceback.print_exc()
    
    print("🚀 Starting FlowUp server...")
    print("📱 Open http://127.0.0.1:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000)
