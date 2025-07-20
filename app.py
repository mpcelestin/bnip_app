from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
socketio = SocketIO(app)

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Enable foreign key constraints
    c.execute("PRAGMA foreign_keys = ON")

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        salary_rate REAL DEFAULT 0
    )''')

    # Create reports table
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        morning_stock TEXT NOT NULL,
        morning_stock_value REAL NOT NULL,
        incoming_items TEXT NOT NULL,
        incoming_items_value REAL NOT NULL,
        sold_items TEXT NOT NULL,
        sold_items_value REAL NOT NULL,
        remaining_stock TEXT NOT NULL,
        remaining_stock_value REAL NOT NULL,
        report_date TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Create messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )''')

    # Create admin user if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'CEO MANAGER'")
    if c.fetchone()[0] == 0:
        hashed_pw = generate_password_hash('0220Mpc#')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                 ('CEO MANAGER', hashed_pw, 'manager'))

    conn.commit()
    conn.close()

# Call init_db when the app starts
init_db()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_id(username):
    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user['id'] if user else None

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# Add these new routes to your existing app.py

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = 'employee'  # Default role for new registrations
        
        # Validate inputs
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if username exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            conn.close()
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_pw = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                    (username, hashed_pw, role))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))




@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session['role'] == 'manager':
        return redirect(url_for('manager_dashboard'))
    
    return render_template('dashboard.html')

@app.route('/report', methods=['GET', 'POST'])
def submit_report():
    if 'username' not in session or session['role'] == 'manager':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        morning_stock = request.form['morning_stock']
        morning_stock_value = float(request.form['morning_stock_value'])
        incoming_items = request.form['incoming_items']
        incoming_items_value = float(request.form['incoming_items_value'])
        sold_items = request.form['sold_items']
        sold_items_value = float(request.form['sold_items_value'])
        remaining_stock = request.form['remaining_stock']
        remaining_stock_value = float(request.form['remaining_stock_value'])
        report_date = request.form['report_date']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn = get_db_connection()
        conn.execute('''INSERT INTO reports 
                     (user_id, morning_stock, morning_stock_value, 
                      incoming_items, incoming_items_value,
                      sold_items, sold_items_value,
                      remaining_stock, remaining_stock_value,
                      report_date, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (session['user_id'], 
                      morning_stock, morning_stock_value,
                      incoming_items, incoming_items_value,
                      sold_items, sold_items_value,
                      remaining_stock, remaining_stock_value,
                      report_date, timestamp))
        conn.commit()
        conn.close()
        
        flash('Rapport soumis avec succès!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('report.html')



@app.route('/debug/reports')
def debug_reports():
    if 'username' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    reports = conn.execute('SELECT * FROM reports').fetchall()
    conn.close()
    
    return jsonify([dict(report) for report in reports])


@app.route('/manager')
def manager_dashboard():
    if 'username' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Debug query - add this to check what's being fetched
    print("Executing reports query...")
    reports_query = conn.execute('''SELECT 
                                  reports.*, 
                                  users.username,
                                  datetime(reports.timestamp) as formatted_timestamp
                                  FROM reports JOIN users ON reports.user_id = users.id
                                  ORDER BY reports.timestamp DESC''')
    reports = reports_query.fetchall()
    print(f"Found {len(reports)} reports")
    
    employees = conn.execute('SELECT id, username, salary_rate FROM users WHERE role = "employee"').fetchall()
    conn.close()
    
    return render_template('manager.html', 
                        reports=reports, 
                        employees=employees,
                        total_sold_value=sum(r['sold_items_value'] for r in reports),
                        current_stock_value=sum(r['remaining_stock_value'] for r in reports),
                        total_incoming_value=sum(r['incoming_items_value'] for r in reports))


@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'username' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM reports WHERE id = ?', (report_id,))
    conn.commit()
    conn.close()
    
    flash('Report deleted successfully!', 'success')
    return redirect(url_for('manager_dashboard'))




@app.route('/calculate_salary/<int:user_id>')
def calculate_salary(user_id):
    if 'username' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # Get salary rate
    user = conn.execute('SELECT salary_rate FROM users WHERE id = ?', (user_id,)).fetchone()
    # Count reports (assuming salary is based on number of reports)
    report_count = conn.execute('SELECT COUNT(*) FROM reports WHERE user_id = ?', (user_id,)).fetchone()[0]
    conn.close()
    
    salary = user['salary_rate'] * report_count
    return jsonify({'salary': salary, 'report_count': report_count})



@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get the CEO MANAGER's ID
    ceo = conn.execute('SELECT id FROM users WHERE username = "CEO MANAGER"').fetchone()
    ceo_id = ceo['id'] if ceo else None
    
    if session['role'] == 'manager':
        # CEO sees all employees
        contacts = conn.execute('SELECT id, username FROM users WHERE role = "employee"').fetchall()
        default_contact = request.args.get('contact', contacts[0]['id'] if contacts else None, type=int)
    else:
        # Employees only see CEO
        contacts = [{'id': ceo_id, 'username': 'CEO MANAGER'}] if ceo_id else []
        default_contact = ceo_id
    
    # Get messages
    messages = []
    if default_contact:
        messages = conn.execute('''SELECT m.*, u.username as sender_name 
                                FROM messages m JOIN users u ON m.sender_id = u.id
                                WHERE (sender_id = ? AND receiver_id = ?) OR 
                                      (sender_id = ? AND receiver_id = ?)
                                ORDER BY timestamp''',
                                (session['user_id'], default_contact,
                                 default_contact, session['user_id'])).fetchall()
    
    # Mark messages as read
    if default_contact and session['user_id']:
        conn.execute('''UPDATE messages SET is_read = 1 
                      WHERE receiver_id = ? AND sender_id = ?''',
                   (session['user_id'], default_contact))
        conn.commit()
    
    conn.close()
    
    return render_template('chat.html', 
                         contacts=contacts,
                         messages=messages,
                         current_contact=default_contact)

# WebSocket for real-time chat
@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    
    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    message = data['message'].strip()
    
    if not message:
        return
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db_connection()
    
    # Verify receiver exists
    receiver = conn.execute('SELECT id FROM users WHERE id = ?', (receiver_id,)).fetchone()
    if not receiver:
        conn.close()
        return
    
    # Save message
    conn.execute('''INSERT INTO messages 
                  (sender_id, receiver_id, message, timestamp)
                  VALUES (?, ?, ?, ?)''',
                (sender_id, receiver_id, message, timestamp))
    conn.commit()
    
    # Prepare response data
    sender = conn.execute('SELECT username FROM users WHERE id = ?', (sender_id,)).fetchone()
    response = {
        'sender_id': sender_id,
        'sender_name': sender['username'],
        'message': message,
        'timestamp': timestamp,
        'is_read': False
    }
    
    # Emit to sender and receiver
    socketio.emit('new_message', response, room=f'user_{sender_id}')
    socketio.emit('new_message', response, room=f'user_{receiver_id}')
    
    conn.close()

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        socketio.emit('join_room', {'room': f'user_{session["user_id"]}'})

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if 'user_id' not in session:
        return
    
    sender_id = data['sender_id']
    receiver_id = session['user_id']
    
    conn = get_db_connection()
    conn.execute('''UPDATE messages SET is_read = 1 
                  WHERE sender_id = ? AND receiver_id = ?''',
                (sender_id, receiver_id))
    conn.commit()
    conn.close()


@app.route('/delete_message/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    
    # Verify the user owns the message
    message = conn.execute('SELECT sender_id FROM messages WHERE id = ?', (message_id,)).fetchone()
    if not message or message['sender_id'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    
    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    message = data['message'].strip()
    
    if not message:
        return
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db_connection()
    
    # Verify receiver exists
    receiver = conn.execute('SELECT id FROM users WHERE id = ?', (receiver_id,)).fetchone()
    if not receiver:
        conn.close()
        return
    
    # Save message and get the inserted ID
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO messages 
                    (sender_id, receiver_id, message, timestamp)
                    VALUES (?, ?, ?, ?)''',
                 (sender_id, receiver_id, message, timestamp))
    message_id = cursor.lastrowid
    conn.commit()
    
    # Get sender username
    sender = conn.execute('SELECT username FROM users WHERE id = ?', (sender_id,)).fetchone()
    conn.close()
    
    # Prepare response data with the new message ID
    response = {
        'id': message_id,
        'sender_id': sender_id,
        'sender_name': sender['username'],
        'message': message,
        'timestamp': timestamp,
        'is_read': False
    }
    
    # Emit to sender and receiver
    socketio.emit('new_message', response, room=f'user_{sender_id}')
    socketio.emit('new_message', response, room=f'user_{receiver_id}')
    
    # Create new message with same content
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('''INSERT INTO messages 
                  (sender_id, receiver_id, message, timestamp)
                  VALUES (?, ?, ?, ?)''',
                (session['user_id'], message['receiver_id'], message['message'], timestamp))
    conn.commit()
    
    # Get sender username
    sender = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    # Emit the new message
    socketio.emit('new_message', {
        'sender_id': session['user_id'],
        'sender_name': sender['username'],
        'message': message['message'],
        'timestamp': timestamp,
        'is_read': False
    }, room=f'user_{session["user_id"]}')
    
    socketio.emit('new_message', {
        'sender_id': session['user_id'],
        'sender_name': sender['username'],
        'message': message['message'],
        'timestamp': timestamp,
        'is_read': False
    }, room=f'user_{message["receiver_id"]}')


@socketio.on('typing')
def handle_typing(data):
    if 'user_id' not in session:
        return
    
    receiver_id = data.get('receiver_id')
    if not receiver_id:
        return
    
    conn = get_db_connection()
    sender = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    socketio.emit('typing', {
        'sender_id': session['user_id'],
        'sender_name': sender['username']
    }, room=f'user_{receiver_id}')

@socketio.on('stop_typing')
def handle_stop_typing(data):
    if 'user_id' not in session:
        return
    
    receiver_id = data.get('receiver_id')
    if not receiver_id:
        return
    
    socketio.emit('stop_typing', {
        'sender_id': session['user_id']
    }, room=f'user_{receiver_id}')

@app.route('/update_salary_rate/<int:user_id>', methods=['POST'])
def update_salary_rate(user_id):
    if 'username' not in session or session['role'] != 'manager':
        return jsonify({'success': False}), 403
    
    data = request.get_json()
    new_rate = data.get('rate', 0)
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET salary_rate = ? WHERE id = ?', (new_rate, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    socketio.run(app, debug=True)