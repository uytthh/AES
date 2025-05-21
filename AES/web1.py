from flask import Flask, request, render_template, send_file, make_response
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import shutil

app = Flask(__name__)

# Đường dẫn thư mục
UPLOAD_FOLDER = 'D:/AES/uploads'
DOWNLOAD_FOLDER = 'D:/AES/downloads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

def derive_key(key_string):
    """Tạo khóa 32 bytes từ chuỗi khóa người dùng nhập"""
    return hashlib.sha256(key_string.encode()).digest()

@app.route('/', methods=['GET'])
def index():
    response = make_response(render_template('web1.html'))
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files or 'key' not in request.form:
        response = make_response("Vui lòng cung cấp file và khóa!")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response, 400
    
    file = request.files['file']
    key_string = request.form['key']
    
    if file.filename == '':
        response = make_response("Chưa chọn file!")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response, 400
    
    # Lưu file upload
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    # Đọc dữ liệu file
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Tạo khóa và IV
    key = derive_key(key_string)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Mã hóa
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Lưu file mã hóa (IV + dữ liệu mã hóa)
    output_filename = f"encrypted_{file.filename}"
    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)
    
    return send_file(output_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files or 'key' not in request.form:
        response = make_response("Vui lòng cung cấp file và khóa!")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response, 400
    
    file = request.files['file']
    key_string = request.form['key']
    
    if file.filename == '':
        response = make_response("Chưa chọn file!")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response, 400
    
    # Lưu file upload
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    # Đọc dữ liệu file
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Tách IV và dữ liệu mã hóa
    iv = data[:AES.block_size]
    encrypted_data = data[AES.block_size:]
    
    # Tạo khóa
    key = derive_key(key_string)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Giải mã
    try:
        padded_data = cipher.decrypt(encrypted_data)
        data = unpad(padded_data, AES.block_size)
    except ValueError:
        response = make_response("Khóa không đúng hoặc file bị lỗi!")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response, 400
    
    # Lưu file giải mã với định dạng giữ nguyên
    original_ext = os.path.splitext(file.filename)[1]  # Lấy phần mở rộng (ví dụ: .jpg)
    output_filename = f"decrypted_{os.path.splitext(file.filename)[0]}{original_ext}"
    output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return send_file(output_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)