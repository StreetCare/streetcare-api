from flask import Flask, request, jsonify
import pymysql
from flask_cors import CORS
import hashlib
import bcrypt
from dotenv import load_dotenv
import os

app = Flask(__name__)
CORS(app)

load_dotenv()

def get_db_connection():
    return pymysql.connect(
        host='streetcare-streetcareapps-8319.d.aivencloud.com',
        port=25496,
        user='avnadmin',
        password=os.getenv("DB_PASSWORD"),
        db='defaultdb',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor,
        ssl={'ca': 'ca.pem'}
    )

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return "API is running"

# ------------------- ENDPOINT: REGISTER USER -------------------
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = """
            INSERT INTO users 
            (nama, tgl_lahir, asal, alamat, username, email, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            data['nama'],
            data['tgl_lahir'],
            data['asal'],
            data['alamat'],
            data['username'],
            data['email'],
            hash_password(data['password'])
        )
        cursor.execute(sql, values)
        conn.commit()
        return jsonify({"message": "Registrasi berhasil"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ------------------- ENDPOINT: LOGIN ADMIN -------------------
@app.route('/admin/login', methods=['POST'])
def login_admin():
    data = request.get_json()
    login_email = data.get("email")
    password = data.get("password")
    if not login_email or not password:
        return jsonify({"success": False, "message": "Email dan password wajib diisi."}), 400
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = "SELECT * FROM admins WHERE login_email = %s"
            cursor.execute(sql, (login_email,))
            admin = cursor.fetchone()
        conn.close()
        if not admin:
            return jsonify({"success": False, "message": "Login email tidak terdaftar."}), 404
        if bcrypt.checkpw(password.encode("utf-8"), admin["password"].encode("utf-8")):
            admin.pop("password", None)
            return jsonify({"success": True, "admin": admin}), 200
        else:
            return jsonify({"success": False, "message": "Kata sandi salah."}), 401
    except Exception as e:
        print("Error login admin:", e)
        return jsonify({"success": False, "message": "Terjadi kesalahan server."}), 500

# ------------------- ENDPOINT: CEK EMAIL -------------------
@app.route('/check/email', methods=['POST'])
def check_email():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "SELECT COUNT(*) AS count FROM users WHERE email = %s"
        cursor.execute(sql, (data['email'],))
        result = cursor.fetchone()
        return jsonify({"registered": result['count'] > 0}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ------------------- ENDPOINT: CEK USERNAME -------------------
@app.route('/check/username', methods=['POST'])
def check_username():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "SELECT COUNT(*) AS count FROM users WHERE username = %s"
        cursor.execute(sql, (data['username'],))
        result = cursor.fetchone()
        return jsonify({"registered": result['count'] > 0}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ------------------- ENDPOINT: LOGIN USER -------------------
@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "SELECT * FROM users WHERE username = %s OR email = %s"
        cursor.execute(sql, (data['login_id'], data['login_id']))
        user = cursor.fetchone()
        if user:
            password_hash = user['password_hash']
            if hash_password(data['password']) == password_hash:
                return jsonify({"message": "Login berhasil", "user": user}), 200
            else:
                return jsonify({"error": "Kata sandi salah."}), 401
        else:
            return jsonify({"error": "Username atau email tidak ditemukan."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ------------------- ENDPOINT: GET USER DATA -------------------
@app.route('/user', methods=['POST'])
def get_user_data():
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "SELECT * FROM users WHERE username = %s OR email = %s"
        cursor.execute(sql, (data['login_id'], data['login_id']))
        user = cursor.fetchone()
        if user:
            if 'password_hash' in user:
                del user['password_hash']
            return jsonify({"user": user}), 200
        else:
            return jsonify({"error": "User tidak ditemukan."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
