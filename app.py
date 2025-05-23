from flask import Flask, request, jsonify
import psycopg2
import os
from werkzeug.utils import secure_filename
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from dotenv import load_dotenv
import logging

app = Flask(__name__)

# Configure CORS
from flask_cors import CORS
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'apk'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database configuration
DB_CONFIG = {
    'dbname': 'flask_viramind',
    'user': 'flask',
    'password': 'viramind',
    'host': 'localhost',
    'port': '5432'
}

load_dotenv()
SECRET_KEY = os.getenv('JWT_SECRET_KEY')

# Logging setup
logging.basicConfig(level=logging.INFO)

# Database connection
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

# Check file extension
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Upload APK endpoint
@app.route('/api/upload-apk', methods=['POST'])
def upload_apk():
    try:
        if 'user_id' not in request.form:
            return jsonify({'success': False, 'message': 'user_id is required'}), 400

        user_id = request.form['user_id']

        if 'apk' not in request.files:
            return jsonify({'success': False, 'message': 'No file part in the request'}), 400

        file = request.files['apk']

        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            file.save(file_path)

            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute(
                """
                INSERT INTO apk_files (file_name, file_path, user_id)
                VALUES (%s, %s, %s)
                RETURNING id, file_name, file_path, upload_time, user_id
                """,
                (filename, file_path, user_id)
            )
            result = cursor.fetchone()
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({
                'success': True,
                'message': 'File uploaded successfully',
                'filePath': result['file_path']
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid file type. Only APK files are allowed'}), 400
    except psycopg2.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    app.logger.info(f"Login request received: {data}")
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            """
            SELECT id, username, email, password FROM users WHERE username = %s
            """,
            (username,)
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
        
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}
        }), 200
    except psycopg2.Error as e:
        app.logger.error(f"Database error during login: {str(e)}")
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during login: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Register endpoint
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    app.logger.info(f"Register request received: {data}")
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not password or not email:
        return jsonify({'success': False, 'message': 'Username, email and password are required'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id, username, email",
            (username, email, hashed_password)
        )
        user = cursor.fetchone()
        conn.commit()

        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}
        }), 201
    except psycopg2.IntegrityError:
        if conn:
            conn.rollback()
        return jsonify({'success': False, 'message': 'Username or email already exists'}), 400
    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        app.logger.error(f"Database error during registration: {str(e)}")
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during registration: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    if not SECRET_KEY:
        logging.error("JWT_SECRET_KEY not found in environment variables. Please set it in your .env file.")
        exit(1)

    app.run(host='0.0.0.0', port=5000, debug=True,
            ssl_context=('certs/server.crt', 'certs/server.key'))
