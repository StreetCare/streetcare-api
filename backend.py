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
    data = request.json
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = """
            SELECT * FROM admins 
            WHERE username = %s AND password_hash = %s
        """
        values = (data['username'], hash_password(data['password']))
        cursor.execute(sql, values)
        result = cursor.fetchone()
        if result:
            return jsonify({"message": "Login berhasil", "admin": result}), 200
        else:
            return jsonify({"error": "Login gagal"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

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

if __name__ == '__main__':
    app.run(debug=True)
