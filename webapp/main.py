from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import boto3

# Khởi tạo ứng dụng Flask và Bcrypt
app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# Khởi tạo boto3 client EC2
ec2 = boto3.client('ec2')

# Hàm khởi tạo cơ sở dữ liệu SQLite và tạo bảng nếu chưa có
def init_db():
    conn = sqlite3.connect('webapp.db')
    c = conn.cursor()

    # Bảng lưu tài khoản quản trị (password băm)
    c.execute('''CREATE TABLE IF NOT EXISTS admin (username TEXT, password TEXT)''')

    # Bảng lưu danh sách IP
    c.execute('''CREATE TABLE IF NOT EXISTS ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT)''')

    # Bảng lưu thông tin instance
    c.execute('''CREATE TABLE IF NOT EXISTS instances (id INTEGER PRIMARY KEY AUTOINCREMENT, instance_id TEXT, ip TEXT, status TEXT)''')

    # Thêm tài khoản quản trị mặc định nếu chưa có
    c.execute("SELECT * FROM admin WHERE username='admin'")
    if not c.fetchone():
        hashed_pw = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
        c.execute("INSERT INTO admin (username, password) VALUES (?, ?)", ('admin', hashed_pw))

    conn.commit()
    conn.close()

# Trang chủ hiển thị danh sách IP dành cho người dùng thường
@app.route('/')
def index():
    conn = sqlite3.connect('webapp.db')
    c = conn.cursor()
    c.execute("SELECT id, ip FROM ips")
    ips = c.fetchall()
    conn.close()
    return render_template('index.html', ips=ips)

# Trang đăng nhập cho tài khoản quản trị
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('webapp.db')
        c = conn.cursor()
        c.execute("SELECT password FROM admin WHERE username=?", (username,))
        admin = c.fetchone()

        conn.close()

        if admin and bcrypt.check_password_hash(admin[0], password):
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Sai tên đăng nhập hoặc mật khẩu!', 'danger')

    return render_template('login.html')

# Trang quản trị sau khi đăng nhập
@app.route('/admin')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('webapp.db')
    c = conn.cursor()
    c.execute("SELECT * FROM instances")
    instances = c.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', instances=instances)

# Cập nhật thông tin instances và IP
@app.route('/admin/update_instances')
def update_instances():
    if 'admin' not in session:
        return redirect(url_for('login'))

    # Lấy danh sách instances từ AWS EC2
    conn = sqlite3.connect('webapp.db')
    c = conn.cursor()

    response = ec2.describe_instances()
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            ip = instance.get('PublicIpAddress', 'None')
            status = instance['State']['Name']

            # Thêm hoặc cập nhật vào cơ sở dữ liệu
            c.execute("SELECT * FROM instances WHERE instance_id=?", (instance_id,))
            if c.fetchone():
                c.execute("UPDATE instances SET ip=?, status=? WHERE instance_id=?", (ip, status, instance_id))
            else:
                c.execute("INSERT INTO instances (instance_id, ip, status) VALUES (?, ?, ?)", (instance_id, ip, status))
            instances.append((instance_id, ip, status))

    conn.commit()
    conn.close()

    flash('Đã cập nhật danh sách instances!', 'success')
    return redirect(url_for('admin_dashboard'))

# Bật instance
@app.route('/admin/start_instance/<instance_id>')
def start_instance(instance_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    ec2.start_instances(InstanceIds=[instance_id])
    flash(f'Instance {instance_id} đã được bật!', 'success')
    return redirect(url_for('admin_dashboard'))

# Tắt instance
@app.route('/admin/stop_instance/<instance_id>')
def stop_instance(instance_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    ec2.stop_instances(InstanceIds=[instance_id])
    flash(f'Instance {instance_id} đã được tắt!', 'success')
    return redirect(url_for('admin_dashboard'))

# Xóa instance
@app.route('/admin/delete_instance/<instance_id>')
def delete_instance(instance_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('webapp.db')
    c = conn.cursor()
    c.execute("DELETE FROM instances WHERE instance_id=?", (instance_id,))
    conn.commit()
    conn.close()

    flash(f'Instance {instance_id} đã được xóa khỏi cơ sở dữ liệu!', 'success')
    return redirect(url_for('admin_dashboard'))

# Đăng xuất
@app.route('/logout')
def logout():
    session.pop('admin', None)
    flash('Đã đăng xuất!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
