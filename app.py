import io
import os
import re
import secrets

from dotenv import load_dotenv
load_dotenv()

import bcrypt
import psycopg2
import psycopg2.extras
import psycopg2.errorcodes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import (Flask, flash, redirect, render_template,
                   request, send_file, session, url_for)
from supabase import create_client, Client
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ─── STARTUP CHECKS ───────────────────────────────────────────────────────────
_required_env = ['FLASK_SECRET_KEY', 'SUPABASE_URL', 'SUPABASE_KEY', 'DATABASE_URL']
_missing = [k for k in _required_env if not os.environ.get(k)]
if _missing:
    raise RuntimeError(
        f"Missing required environment variables: {', '.join(_missing)}\n"
        "Copy .env.example to .env and fill in all values."
    )

app.secret_key = os.environ['FLASK_SECRET_KEY']

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
MAX_FILE_SIZE = 16 * 1024 * 1024
PBKDF2_ITERS  = 600_000
SALT_SIZE     = 32
NONCE_SIZE    = 12
BUCKET        = 'encrypted-files'

app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',
    'docx', 'xlsx', 'pptx', 'zip', 'csv', 'mp4', 'mp3'
}

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────

@app.errorhandler(413)
def file_too_large(e):
    flash('File is too large. Maximum upload size is 16 MB.', 'danger')
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found(e):
    flash('The page you were looking for does not exist.', 'danger')
    return redirect(url_for('dashboard') if logged_in() else url_for('login'))

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f'Server error: {e}')
    flash('An unexpected error occurred. Please try again.', 'danger')
    return redirect(url_for('dashboard') if logged_in() else url_for('login'))

# ─── DB & STORAGE CLIENTS ─────────────────────────────────────────────────────

def get_supabase() -> Client:
    return create_client(os.environ['SUPABASE_URL'], os.environ['SUPABASE_KEY'])

def get_db():
    url = os.environ['DATABASE_URL']
    if 'sslmode' not in url:
        sep = '&' if '?' in url else '?'
        url += f'{sep}sslmode=require'
    return psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)

# ─── CRYPTO ───────────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    ).derive(password.encode())

def encrypt_file(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)

def decrypt_file(blob: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], None)

# ─── STORAGE HELPERS ──────────────────────────────────────────────────────────

def storage_upload(stored_name: str, data: bytes) -> None:
    get_supabase().storage.from_(BUCKET).upload(
        path=stored_name,
        file=data,
        file_options={"content-type": "application/octet-stream"}
    )

def storage_download(stored_name: str) -> bytes:
    return get_supabase().storage.from_(BUCKET).download(stored_name)

def storage_delete(stored_name: str) -> None:
    get_supabase().storage.from_(BUCKET).remove([stored_name])

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def logged_in() -> bool:
    return 'user_id' in session and 'aes_key' in session

def get_aes_key() -> bytes:
    return bytes.fromhex(session['aes_key'])

def _get_file_record(file_id: int) -> dict | None:
    db = None
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM files WHERE id = %s AND user_id = %s",
            (file_id, session['user_id'])
        )
        return cur.fetchone()
    except Exception as e:
        app.logger.error(f"File record lookup error: {e}")
        return None
    finally:
        if db: db.close()

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('dashboard') if logged_in() else url_for('login'))

# ── Register ──
@app.route('/register', methods=['GET', 'POST'])
def register():
    if logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username     = request.form.get('username', '').strip()
        raw_password = request.form.get('password', '')

        if not username or len(username) > 80:
            flash('Username must be between 1 and 80 characters.', 'danger')
            return render_template('register.html')
        if len(raw_password) < 8 or len(raw_password) > 16:
            flash('Password must be between 8 and 16 characters.', 'danger')
            return render_template('register.html')
        if not re.search(r'[A-Z]', raw_password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return render_template('register.html')
        if not re.search(r'[0-9]', raw_password):
            flash('Password must contain at least one number.', 'danger')
            return render_template('register.html')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-\[\]\\/+=;\'`~]', raw_password):
            flash('Password must contain at least one special character (e.g. !@#$%).', 'danger')
            return render_template('register.html')

        password_hash = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
        kdf_salt      = secrets.token_bytes(SALT_SIZE)

        db = None
        try:
            db  = get_db()
            cur = db.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, kdf_salt) VALUES (%s, %s, %s)",
                (username, password_hash, psycopg2.Binary(kdf_salt))
            )
            db.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except psycopg2.errors.UniqueViolation:
            if db: db.rollback()
            flash('Username already taken. Please choose another.', 'danger')
        except psycopg2.OperationalError as e:
            app.logger.error(f"Register DB connection error: {e}")
            flash('Cannot connect to the database. Please try again later.', 'danger')
        except Exception as e:
            if db: db.rollback()
            app.logger.error(f"Register error: {e}")
            flash('Registration failed. Please try again.', 'danger')
        finally:
            if db: db.close()

    return render_template('register.html')

# ── Login ──
@app.route('/login', methods=['GET', 'POST'])
def login():
    if logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username     = request.form.get('username', '').strip()
        raw_password = request.form.get('password', '')

        if not username or not raw_password:
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html')

        db   = None
        user = None
        try:
            db  = get_db()
            cur = db.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
        except psycopg2.OperationalError as e:
            app.logger.error(f"Login DB connection error: {e}")
            flash('Cannot connect to the database. Please try again later.', 'danger')
            return render_template('login.html')
        except Exception as e:
            app.logger.error(f"Login DB error: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html')
        finally:
            if db: db.close()

        if user and bcrypt.checkpw(raw_password.encode(), user['password_hash'].encode()):
            aes_key = derive_key(raw_password, bytes(user['kdf_salt']))
            session.clear()
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['aes_key']  = aes_key.hex()
            return redirect(url_for('dashboard'))
        else:
            # Same message for wrong username or wrong password — prevents user enumeration
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

# ── Logout ──
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# ── Dashboard ──
@app.route('/dashboard')
def dashboard():
    if not logged_in():
        return redirect(url_for('login'))

    db    = None
    files = []
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM files WHERE user_id = %s ORDER BY uploaded_at DESC",
            (session['user_id'],)
        )
        files = cur.fetchall()
    except Exception as e:
        app.logger.error(f"Dashboard DB error: {e}")
        flash('Could not load your files. Please try again.', 'danger')
    finally:
        if db: db.close()

    return render_template('dashboard.html', files=files, username=session['username'])

# ── Upload ──
@app.route('/upload', methods=['POST'])
def upload():
    if not logged_in():
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file selected.', 'warning')
        return redirect(url_for('dashboard'))

    if not allowed_file(file.filename):
        flash('File type not allowed.', 'danger')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    if not filename:
        flash('Invalid filename.', 'danger')
        return redirect(url_for('dashboard'))

    if request.content_length and request.content_length > MAX_FILE_SIZE:
        flash('File is too large. Maximum upload size is 16 MB.', 'danger')
        return redirect(url_for('dashboard'))

    file_data   = file.read()
    encrypted   = encrypt_file(file_data, get_aes_key())
    stored_name = f"{secrets.token_hex(8)}_{filename}.enc"

    # Step 1: upload to Supabase Storage
    try:
        storage_upload(stored_name, encrypted)
    except Exception as e:
        app.logger.error(f"Storage upload error: {e}")
        flash('Upload to cloud storage failed. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

    # Step 2: save metadata — rollback storage if DB fails
    db = None
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO files (user_id, original_name, stored_name, file_size)"
            " VALUES (%s, %s, %s, %s)",
            (session['user_id'], filename, stored_name, len(file_data))
        )
        db.commit()
    except Exception as e:
        app.logger.error(f"Upload DB error: {e}")
        try:
            storage_delete(stored_name)
        except Exception:
            pass
        flash('Upload failed. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db: db.close()

    flash(f'"{filename}" uploaded and encrypted successfully!', 'success')
    return redirect(url_for('dashboard'))

# ── Delete ──
@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if not logged_in():
        return redirect(url_for('login'))

    # Ownership check built into _get_file_record
    file = _get_file_record(file_id)
    if not file:
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))

    stored_name   = file['stored_name']
    original_name = file['original_name']

    # Step 1: remove DB record first so the file vanishes from the dashboard immediately
    db = None
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "DELETE FROM files WHERE id = %s AND user_id = %s",
            (file_id, session['user_id'])
        )
        db.commit()
    except Exception as e:
        app.logger.error(f"Delete DB error: {e}")
        flash('Could not delete file. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db: db.close()

    # Step 2: remove encrypted blob from Supabase Storage
    try:
        storage_delete(stored_name)
    except Exception as e:
        # DB row is already gone — log the orphan but don't show a confusing error
        app.logger.error(f"Storage delete orphan {stored_name}: {e}")

    flash(f'"{original_name}" has been permanently deleted.', 'success')
    return redirect(url_for('dashboard'))

# ── Download Encrypted ──
@app.route('/download/encrypted/<int:file_id>')
def download_encrypted(file_id):
    if not logged_in():
        return redirect(url_for('login'))

    file = _get_file_record(file_id)
    if not file:
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        blob = storage_download(file['stored_name'])
    except Exception as e:
        app.logger.error(f"Storage download error: {e}")
        flash('Could not retrieve file from cloud storage.', 'danger')
        return redirect(url_for('dashboard'))

    return send_file(
        io.BytesIO(blob),
        as_attachment=True,
        download_name=file['original_name'] + '.enc',
        mimetype='application/octet-stream'
    )

# ── Download Decrypted ──
@app.route('/download/decrypted/<int:file_id>')
def download_decrypted(file_id):
    if not logged_in():
        return redirect(url_for('login'))

    file = _get_file_record(file_id)
    if not file:
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        blob = storage_download(file['stored_name'])
    except Exception as e:
        app.logger.error(f"Storage download error: {e}")
        flash('Could not retrieve file from cloud storage.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        plaintext = decrypt_file(blob, get_aes_key())
    except Exception:
        flash('Decryption failed — file may be corrupted or tampered with.', 'danger')
        return redirect(url_for('dashboard'))

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file['original_name'],
        mimetype='application/octet-stream'
    )

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
# Local:      python app.py
# Production: gunicorn app:app
if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
