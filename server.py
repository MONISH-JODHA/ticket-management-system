from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, render_template, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import sqlite3
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room

load_dotenv()

UPLOAD_FOLDER = 'uploads'
DB_PATH = './tickets.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'def@ult-Sup3r-S3cr3t-Key-P13a5e-Chang3-M3!') # Use a strong, random key
CORS(app, supports_credentials=True)

socketio = SocketIO(app, cors_allowed_origins="*") # Configure as needed for production

GEMINI_API_KEY = os.getenv('GOOGLE_API_KEY')
Password = os.getenv('PASSWORD')

EMAIL_USER_ACCOUNT = os.getenv('EMAIL_USER')
EMAIL_APP_PASSWORD_ACCOUNT = os.getenv('EMAIL_APP_PASSWORD')


if not GEMINI_API_KEY:
    print("CRITICAL WARNING: GOOGLE_API_KEY environment variable not set. Gemini AI calls will fail.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("Gemini API Key configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini API: {e}")
        GEMINI_API_KEY = None # Ensure it's None if config fails

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS tickets (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            description TEXT,
                            remedies TEXT,
                            file_path TEXT,
                            remedy_doc_path TEXT,
                            created_by TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            status TEXT DEFAULT 'Open'
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL, /* TODO: HASH THIS! */
                            otp TEXT,
                            verified INTEGER DEFAULT 0
                        )''')
        conn.commit()

def is_valid_email(email):
    return email and email.endswith('@cloudkeeper.com')

def send_otp_email(to_email, otp):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Confirm your signup – Your OTP is inside'
    msg['From'] = 'Monish Jodha <monish.jodha@cloudkeeper.com>'
    msg['To'] = to_email

    text = f"""Hi,

Thank you for signing up!

Your One-Time Password (OTP) is: {otp}

Please enter this OTP on the signup page to complete your registration.
This OTP is valid for the next 10 minutes.

If you did not initiate this request, please ignore this email.

Best regards,
Team Support
"""

    html = f"""
    <html>
      <body>
        <p>Hi,<br><br>
           Thank you for signing up!<br><br>
           <b>Your One-Time Password (OTP) is:</b> <span style="font-size:18px;color:#2E86C1;">{otp}</span><br><br>
           Please enter this OTP on the signup page to complete your registration.<br>
           This OTP is valid for the next 10 minutes.<br><br>
           If you did not initiate this request, please ignore this email.<br><br>
           Best regards,<br>
           Team Support
        </p>
      </body>
    </html>
    """

    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('monish.jodha@cloudkeeper.com', Password)
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print("OTP email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session: return redirect(url_for('form'))
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')
        if not username or not password: return render_template('login.html', error="Email and password are required.")
        if not is_valid_email(username): return render_template('login.html', error="Invalid email. Must be @cloudkeeper.com.")
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ? AND password = ? AND verified = 1", (username, password)) # TODO: HASH CHECK
            user = cur.fetchone()
            if user:
                session['username'] = user['username']
                next_url = request.args.get('next')
                return redirect(next_url or url_for('form'))
            else: return render_template('login.html', error='Invalid credentials or account not verified.')
    return render_template('login.html', success=request.args.get('success'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']

        if not is_valid_email(username):
            return render_template('signup.html', error="Only @cloudkeeper.com emails are allowed.")

        otp = str(random.randint(100000, 999999))

        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                return render_template('signup.html', error="User already exists with this email.")
            cur.execute("INSERT INTO users (username, password, otp, verified) VALUES (?, ?, ?, 0)", (username, password, otp))
        send_otp_email(username, otp)
        session['pending_user'] = username
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')




@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    pending_user = session.get('pending_user')
    if not pending_user:
        return redirect(url_for('signup'))
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if not otp_input:
            return render_template('verify.html', error="OTP is required.", email=pending_user)
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT otp FROM users WHERE username = ? AND verified = 0", (pending_user,))
            user_record = cur.fetchone()
            if user_record and user_record['otp'] == otp_input:
                cur.execute("UPDATE users SET verified = 1, otp = NULL WHERE username = ?", (pending_user,))
                conn.commit()
                session.pop('pending_user', None)
                return redirect(url_for('login', success='Your email has been verified! Please log in.'))
            else:
                return render_template('verify.html', error="Invalid OTP. Please try again.", email=pending_user)
    return render_template('verify.html', email=pending_user)


@app.route('/logout')
def logout():
    session.pop('username', None); session.pop('pending_user', None)
    return redirect(url_for('login'))


@socketio.on('connect')
def handle_socket_connect():
    if 'username' in session:
        username = session['username']
        join_room(username)
        join_room('all_authenticated_users')
        print(f"SocketIO Client '{username}' ({request.sid}) connected and joined rooms.")
    else:
        print(f"SocketIO Anonymous client ({request.sid}) connected.")

@socketio.on('disconnect')
def handle_socket_disconnect():
    if 'username' in session:
        username = session['username']
        leave_room(username)
        leave_room('all_authenticated_users')
        print(f"SocketIO Client '{username}' ({request.sid}) disconnected.")
    else:
        print(f"SocketIO Anonymous client ({request.sid}) disconnected.")


@app.route('/submit', methods=['POST'])
@login_required
def submit_ticket():
    current_user = session.get('username')
    new_ticket_id = None; title = ""; description = ""; remedies = ""; created_by = ""; created_at = ""; file_path_str = ""; remedy_doc_path = None
    if request.is_json:
        data = request.get_json()
        title = data.get('title'); description = data.get('description'); remedies = data.get('remedies')
        created_by = data.get('created_by', current_user); created_at = data.get('created_at')
    else:
        title = request.form.get('title'); description = request.form.get('description'); remedies = request.form.get('remedies', '')
        created_by = request.form.get('created_by', current_user); created_at = request.form.get('created_at')
        uploaded_files = request.files.getlist('screenshot'); saved_file_paths = []
        if uploaded_files:
            for file_obj in uploaded_files:
                if file_obj and file_obj.filename:
                    filename = secure_filename(file_obj.filename); file_save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file_obj.save(file_save_path); saved_file_paths.append(file_save_path)
        file_path_str = ";".join(saved_file_paths)
        remedy_doc = request.files.get('remedy_doc')
        if remedy_doc and remedy_doc.filename:
            remedy_filename = secure_filename(remedy_doc.filename)
            remedy_doc_path = os.path.join(app.config['UPLOAD_FOLDER'], remedy_filename)
            remedy_doc.save(remedy_doc_path)
    if not all([title, created_by, created_at]):
        if request.is_json: return jsonify({"success": False, "detail": "Title, Submitted By, and Date are required."}), 400
        else: return redirect(url_for('form', error='Required fields missing'))
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO tickets (title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (title, description, remedies, file_path_str, remedy_doc_path, created_by, created_at, 'Open')
        )
        new_ticket_id = cur.lastrowid
        conn.commit()
    if new_ticket_id:
        created_at_dt = datetime.strptime(created_at, "%Y-%m-%dT%H:%M") if created_at else datetime.now()
        socketio.emit('new_ticket_notification', {
            'id': new_ticket_id, 'title': title, 'created_by': created_by, 'status': 'Open',
            'created_at_display': created_at_dt.strftime('%x'),
            'message': f'New ticket #{new_ticket_id} ("{title}") by {created_by}.'
        }, room='all_authenticated_users')
    if request.is_json: return jsonify({"success": True, "message": "Ticket created successfully!", "ticket_id": new_ticket_id})
    else: return redirect(url_for('form', success='1'))

@app.route('/form')
@login_required
def form():
    return render_template('form.html', success_html_content="Ticket submitted successfully!" if request.args.get('success') == '1' else None, error_message=request.args.get('error'), username=session.get('username'))

@app.route('/tickets', methods=['GET'])
@login_required
def get_tickets():
    search = request.args.get('search', '')
    query = "SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE 1=1"
    params = []
    if search:
        search_term_like = f"%{search}%"
        query += " AND (title LIKE ? OR description LIKE ? OR created_by LIKE ? OR created_at LIKE ? OR id LIKE ? OR status LIKE ?)"
        params.extend([search_term_like] * 6)
    query += " ORDER BY datetime(created_at) DESC"
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row; cur = conn.cursor(); cur.execute(query, params); tickets_raw = cur.fetchall()
        tickets = []
        for row in tickets_raw:
            ticket_dict = dict(row)
            if 'file_path' in ticket_dict and ticket_dict['file_path'] and isinstance(ticket_dict['file_path'], str):
                ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
            else: ticket_dict['file_path'] = []
            tickets.append(ticket_dict)
        return jsonify(tickets)

@app.route('/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row; cur = conn.cursor()
        cur.execute("SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE id=?", (ticket_id,))
        row = cur.fetchone()
        if row:
            ticket_dict = dict(row)
            if 'file_path' in ticket_dict and ticket_dict['file_path'] and isinstance(ticket_dict['file_path'], str):
                ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
            else: ticket_dict['file_path'] = []
            return jsonify(ticket_dict)
        return jsonify({"error": "Ticket not found"}), 404

@app.route('/tickets/<int:ticket_id>', methods=['PUT'])
@login_required
def update_ticket(ticket_id):
    current_user = session.get('username'); data = request.get_json()
    title = data.get('title'); description = data.get('description'); remedies = data.get('remedies'); new_status = data.get('status')
    if not title: return jsonify({"error": "Title is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row; cur = conn.cursor()
        cur.execute("SELECT created_by, status, title, created_at FROM tickets WHERE id = ?", (ticket_id,))
        original_ticket = cur.fetchone()
        if not original_ticket: return jsonify({"error": "Ticket not found"}), 404
        allow_edit = (original_ticket['created_by'] == current_user or current_user == os.getenv("ADMIN_EMAIL", "admin@cloudkeeper.com"))
        if not allow_edit:
            app.logger.warning(f"Forbidden PUT on ticket {ticket_id} by {current_user}")
            return jsonify({"error": "Forbidden: You can only edit your own tickets or an admin must do this."}), 403
        cur.execute('''UPDATE tickets SET title = ?, description = ?, remedies = ?, status = ? WHERE id = ?''',
                     (title, description, remedies, new_status, ticket_id))
        conn.commit()
        if cur.rowcount == 0: return jsonify({'error': 'No changes made or ticket not found during update'}), 404

    msg = f'Ticket #{ticket_id} ("{title}") updated by {current_user}.'
    if new_status and new_status != original_ticket['status']: msg += f' Status: "{original_ticket["status"]}" -> "{new_status}".'
    
    created_at_obj = datetime.strptime(original_ticket['created_at'], "%Y-%m-%dT%H:%M") if original_ticket['created_at'] else datetime.now()

    if original_ticket['created_by'] and original_ticket['created_by'] != current_user:
        socketio.emit('ticket_update_notification', {'id': ticket_id, 'title': title, 'status': new_status, 'message': msg, 'created_by': original_ticket['created_by'], 'created_at_display': created_at_obj.strftime('%x') }, room=original_ticket['created_by'])
    
    socketio.emit('ticket_updated_globally', {
        'id': ticket_id, 'title': title, 'status': new_status, 
        'created_by': original_ticket['created_by'], 
        'created_at_display': created_at_obj.strftime('%x'),
        'message': msg
        }, room='all_authenticated_users')
    return jsonify({'message': 'Ticket updated successfully'})

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename): return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def home_or_main():
    if 'username' in session: return redirect(url_for('form'))
    return render_template('main.html')

@app.route('/gdoc_importer')
@login_required
def gdoc_importer_page(): return render_template('gdoc_import.html', username=session.get('username'))

@app.route('/view')
@login_required
def view_tickets_page(): return render_template('view.html', username=session.get('username'))

@app.route('/user_ticket_view')
@login_required
def user_ticket_view_page(): return render_template('users.html', username=session.get('username'))

@app.route('/counts')
@login_required
def index_counts_page():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute('SELECT created_by, COUNT(*) as ticket_count FROM tickets GROUP BY created_by ORDER BY ticket_count DESC')
        users_data = cur.fetchall()
    return render_template('index.html', users=users_data, username=session.get('username'))

@app.route('/users', methods=['GET'])
@login_required
def get_users_list():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT created_by FROM tickets WHERE created_by IS NOT NULL AND created_by != '' ORDER BY created_by")
        users = [row[0] for row in cur.fetchall()]
        return jsonify(users)

@app.route('/user_tickets/<username>', methods=['GET'])
@login_required
def get_tickets_for_user_api(username):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row; cur = conn.cursor()
        cur.execute("SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE created_by = ? ORDER BY datetime(created_at) DESC", (username,))
        tickets_raw = cur.fetchall(); tickets = []
        for row in tickets_raw:
            ticket_dict = dict(row)
            if 'file_path' in ticket_dict and ticket_dict['file_path'] and isinstance(ticket_dict['file_path'], str):
                ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
            else: ticket_dict['file_path'] = []
            tickets.append(ticket_dict)
        return jsonify(tickets)

@app.route('/extract_gdoc_content', methods=['POST'])
@login_required
def extract_gdoc_content_route():
    data = request.get_json(); gdoc_url = data.get('gdoc_url')
    if not gdoc_url: return jsonify({"success": False, "detail": "Google Doc URL is required."}), 400
    if "/pub" not in gdoc_url: return jsonify({"success": False, "detail": "Please use a 'Published to web' Google Doc link."}), 400
    try:
        response = requests.get(gdoc_url, timeout=15); response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser'); content_elements = soup.find('div', id='contents'); extracted_text = ""
        if content_elements:
            for item in content_elements(['script', 'style']): item.decompose()
            extracted_text = content_elements.get_text(separator='\n', strip=True)
        else:
            body_content = soup.find('body')
            if body_content:
                for item in body_content(['script', 'style']): item.decompose()
                extracted_text = body_content.get_text(separator='\n', strip=True)
        if not extracted_text.strip(): return jsonify({"success": False, "detail": "No text content found."}), 400
        return jsonify({"success": True, "content": extracted_text})
    except requests.exceptions.Timeout: return jsonify({"success": False, "detail": "Timeout fetching Google Doc."}), 504
    except requests.exceptions.RequestException as e: return jsonify({"success": False, "detail": f"Error fetching document: {str(e)}"}), 500
    except Exception as e: app.logger.error(f"Error parsing GDoc: {e}"); return jsonify({"success": False, "detail": "Error parsing document."}), 500

@app.route('/ai-description', methods=['POST'])
@login_required
def ai_description():
    if not GEMINI_API_KEY: return jsonify({"error": "AI service unavailable. Key not configured."}), 503
    data = request.get_json()
    if not data: app.logger.error("AI: No JSON payload."); return jsonify({"error": "Invalid payload."}), 400
    title = data.get('title', ''); description = data.get('description', '')
    if not description.strip() and not title.strip(): return jsonify({"error": "Title or description required."}), 400
    prompt = ""
    if description.strip(): prompt = f"Expertly rewrite this bug description for clarity and professionalism (output only the rewritten text):\n\nOriginal:\n```\n{description}\n```\n\nRewritten:"
    else: prompt = f"As an expert technical writer, create a detailed, professional bug description for a ticket titled: \"{title}\". Include context, steps to reproduce if logical, expected, and actual behavior. Output only the description.\n\nTitle: {title}\n\nDescription:"
    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        response = model.generate_content(prompt, generation_config=genai.types.GenerationConfig(max_output_tokens=350, temperature=0.6))
        generated_text = "".join(part.text for part in response.candidates[0].content.parts).strip() if response.candidates and response.candidates[0].content.parts else ""
        if not generated_text:
             if response.prompt_feedback and response.prompt_feedback.block_reason:
                app.logger.warning(f"Gemini blocked: {response.prompt_feedback.block_reason_message}")
                return jsonify({"error": f"AI content generation blocked: {response.prompt_feedback.block_reason_message}. Rephrase input."}), 400
             app.logger.warning(f"Gemini empty content. Prompt: {prompt[:100]}...")
             return jsonify({"generated": "AI coai_deuld not generate a description. Try rephrasing."})
        return jsonify({"generated": generated_text})
    except Exception as e:
        app.logger.error(f"Gemini API error: {str(e)}")
        return jsonify({"error": "AI service communication error."}), 500

@app.route('/api/ticket_status_counts', methods=['GET'])
@login_required
def get_ticket_status_summary():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row; cur = conn.cursor()
            cur.execute("SELECT status, COUNT(*) as count FROM tickets GROUP BY status")
            db_summary = {row['status']: row['count'] for row in cur.fetchall() if row['status']}
            config = {"Open": {"c":0,"color":"rgba(255,159,64,0.8)"},"In Progress":{"c":0,"color":"rgba(54,162,235,0.8)"},"Resolved":{"c":0,"color":"rgba(75,192,192,0.8)"},"Closed":{"c":0,"color":"rgba(150,150,150,0.8)"},"Pending User":{"c":0,"color":"rgba(201,203,207,0.8)"}}
            for s, d_val in config.items(): # Renamed 'data' to 'd_val'
                if s in db_summary: d_val["c"] = db_summary[s]
            return jsonify({"chart_labels": list(config.keys()), "chart_counts": [d_val["c"] for d_val in config.values()], "chart_colors": [d_val["color"] for d_val in config.values()], "open_tickets_count": config.get("Open",{}).get("c",0)})
    except Exception as e: app.logger.error(f"Status summary error: {e}"); return jsonify({"error":"Could not get status summary"}),500

@app.route('/api/tickets_over_time_counts', methods=['GET'])
@login_required
def get_tickets_over_time_counts():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row; cur = conn.cursor()
            cur.execute("""SELECT DATE(created_at) as creation_date, COUNT(*) as count FROM tickets WHERE DATE(created_at) >= DATE('now', '-30 days') GROUP BY DATE(created_at) ORDER BY creation_date ASC""")
            rows = cur.fetchall()
            return jsonify({"labels": [r['creation_date'] for r in rows if r['creation_date']], "counts": [r['count'] for r in rows if r['creation_date']]})
    except Exception as e: app.logger.error(f"Tickets over time error: {e}"); return jsonify({"error":"Could not get ticket trend"}),500

def query_database_for_chatbot(user_message_lower):
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; cur = conn.cursor()
    response_data = "Sorry, I couldn't find specific info. Try: 'ticket id 123', 'tickets by user@example.com', 'open tickets', 'search tickets for [keyword]', 'how many open tickets?', 'latest 3 tickets'."
    found = False
    if any(user_message_lower.startswith(p) for p in ["ticket id ", "show ticket ", "details for ticket "]):
        try:
            tid_str = next((user_message_lower[len(p):].strip() for p in ["ticket id ","show ticket ","details for ticket "] if user_message_lower.startswith(p) and user_message_lower[len(p):].strip().isdigit()), user_message_lower.split()[-1] if user_message_lower.split()[-1].isdigit() else None)
            if not tid_str: raise ValueError("No ID")
            tid = int(tid_str)
            cur.execute("SELECT * FROM tickets WHERE id = ?", (tid,)); ticket = cur.fetchone()
            if ticket:
                parts = [f"Ticket ID: {ticket['id']}", f"Title: {ticket['title']}", f"Status: {ticket['status']}", f"Desc: {ticket['description']}", f"By: {ticket['created_by']} on {ticket['created_at']}"]
                if ticket['remedies'] and ticket['remedies'].strip(): parts.append(f"Remedies: {ticket['remedies']}")
                if ticket['remedy_doc_path'] and ticket['remedy_doc_path'].strip(): parts.append(f"Doc: {os.path.basename(ticket['remedy_doc_path'])}")
                if ticket['file_path'] and ticket['file_path'].strip():
                    ss = [os.path.basename(p) for p in ticket['file_path'].split(';') if p.strip()]
                    if ss: parts.append(f"Screenshots: {', '.join(ss)}")
                response_data = "\n".join(parts); found = True
            else: response_data = f"No ticket with ID {tid}."
        except ValueError: response_data = "Valid ticket ID needed (e.g., 'ticket id 123')."
        except Exception as e: app.logger.error(f"Chatbot ticket ID error: {e}"); response_data = "Error fetching ticket details."
        found = True 
    elif any(user_message_lower.startswith(p) for p in ["tickets by ", "show tickets for "]):
        try:
            s_query = next((user_message_lower[len(p):].strip() for p in ["tickets by ", "show tickets for "] if user_message_lower.startswith(p)), None)
            if not s_query: response_data = "Specify username (e.g., 'tickets by user@example.com')."
            else:
                cur.execute("SELECT id, title, status, created_at FROM tickets WHERE created_by LIKE ? ORDER BY datetime(created_at) DESC LIMIT 5", (f"%{s_query}%",))
                tickets = cur.fetchall()
                if tickets:
                    response_data = f"Latest 5 tickets for user matching '{s_query}':\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']}, Date: {t['created_at']})" for t in tickets])
                else: response_data = f"No tickets for user matching '{s_query}'."
            found = True
        except Exception as e: app.logger.error(f"Chatbot user tickets error: {e}"); response_data = "Error fetching user tickets."
    elif any(keyword in user_message_lower for keyword in [" tickets", " status is "]) and \
         any(status_keyword in user_message_lower for status_keyword in ['open', 'resolved', 'closed', 'in progress', 'pending user']):
        status_to_find = None
        possible_statuses = {'open': 'Open', 'resolved': 'Resolved', 'closed': 'Closed', 'in progress': 'In Progress', 'pending user': 'Pending User'}
        for key_phrase, status_val in possible_statuses.items():
            if key_phrase in user_message_lower: status_to_find = status_val; break
        if status_to_find:
            cur.execute("SELECT id, title, created_by FROM tickets WHERE status = ? ORDER BY datetime(created_at) DESC LIMIT 5", (status_to_find,))
            tickets = cur.fetchall()
            if tickets:
                response_data = f"Here are the latest 5 '{status_to_find}' tickets:\n" + "\n".join([f"- ID {t['id']}: {t['title']} (By: {t['created_by']})" for t in tickets])
            else: response_data = f"No '{status_to_find}' tickets found currently."
            found = True
        else: response_data = "Which status are you interested in (e.g., open, resolved, closed)?"
    elif user_message_lower.startswith("search tickets for ") or user_message_lower.startswith("find tickets about "):
        search_term = user_message_lower.replace("search tickets for ", "").replace("find tickets about ","").strip()
        if search_term:
            cur.execute("SELECT id, title, status FROM tickets WHERE title LIKE ? OR description LIKE ? OR remedies LIKE ? ORDER BY datetime(created_at) DESC LIMIT 5", (f"%{search_term}%",)*3)
            tickets = cur.fetchall()
            if tickets:
                response_data = f"Found up to 5 tickets matching '{search_term}':\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']})" for t in tickets])
            else: response_data = f"No tickets found matching '{search_term}'."
        else: response_data = "Please specify what you want to search for (e.g., 'search tickets for login issue')."
        found = True
    elif user_message_lower.startswith("how many tickets are ") or user_message_lower.startswith("count of "):
        status_to_count = None
        possible_statuses = {'open': 'Open', 'resolved': 'Resolved', 'closed': 'Closed', 'in progress': 'In Progress', 'pending user': 'Pending User'}
        for key_phrase, status_val in possible_statuses.items():
            if key_phrase in user_message_lower: status_to_count = status_val; break
        if status_to_count:
            cur.execute("SELECT COUNT(*) FROM tickets WHERE status = ?", (status_to_count,)); count = cur.fetchone()[0]
            response_data = f"There are {count} ticket(s) with status '{status_to_count}'."
        elif "total tickets" in user_message_lower or "all tickets" in user_message_lower:
            cur.execute("SELECT COUNT(*) FROM tickets"); count = cur.fetchone()[0]
            response_data = f"There are a total of {count} ticket(s) in the system."
        else: response_data = "Which status count are you interested in (e.g., 'how many tickets are open')?"
        found = True
    elif "latest " in user_message_lower and " tickets" in user_message_lower:
        try:
            parts = user_message_lower.split(); num_tickets = None
            for i, part in enumerate(parts):
                if part == "latest" and i + 1 < len(parts) and parts[i+1].isdigit():
                    num_tickets = int(parts[i+1]); break
            if num_tickets is not None:
                num_tickets = min(num_tickets, 10)
                cur.execute("SELECT id, title, status FROM tickets ORDER BY datetime(created_at) DESC LIMIT ?", (num_tickets,))
                tickets = cur.fetchall()
                if tickets: response_data = f"Here are the latest {len(tickets)} tickets:\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']})" for t in tickets])
                else: response_data = "No tickets found."
            else: response_data = "Please specify how many latest tickets you want (e.g., 'latest 5 tickets')."
            found = True
        except ValueError: response_data = "Please specify a valid number for latest tickets."
        except Exception as e: app.logger.error(f"Chatbot latest tickets error: {e}"); response_data = "Error fetching latest tickets."
    elif any(user_message_lower.startswith(p) for p in ["who created ticket ", "creator of ticket "]):
        try:
            tid_str = next((user_message_lower[len(p):].strip() for p in ["who created ticket ","creator of ticket "] if user_message_lower.startswith(p) and user_message_lower[len(p):].strip().isdigit()), user_message_lower.split()[-1] if user_message_lower.split()[-1].isdigit() else None)
            if not tid_str: raise ValueError("No ID")
            tid = int(tid_str)
            cur.execute("SELECT created_by, title FROM tickets WHERE id = ?", (tid,)); ticket = cur.fetchone()
            if ticket: response_data = f"Ticket ID {tid} (\"{ticket['title']}\") was by: {ticket['created_by']}."
            else: response_data = f"No ticket with ID {tid}."
            found = True
        except ValueError: response_data = "Valid ticket ID needed."
        except Exception as e: app.logger.error(f"Chatbot ticket creator error: {e}"); response_data = "Error fetching creator."
        found = True
    if not found and len(user_message_lower.split()) > 1:
        cur.execute("SELECT id, title, status FROM tickets WHERE title LIKE ? OR description LIKE ? OR remedies LIKE ? OR created_by LIKE ? ORDER BY datetime(created_at) DESC LIMIT 3", (f"%{user_message_lower}%",)*4)
        tickets = cur.fetchall()
        if tickets:
            response_data = f"Found related to '{user_message_lower}':\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']})" for t in tickets])
            response_data += "\n\nMore specific?"
    conn.close()
    return response_data

def generate_ai_chat_response(user_message, db_query_result):
    if not GEMINI_API_KEY: app.logger.warning("Chatbot: Gemini key missing."); return db_query_result
    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        prompt = f"""User asked: "{user_message}"
Based *only* on this database info, give a friendly, concise answer. If it's a list, summarize. If "no ticket/s found", say so politely. If "couldn't understand", rephrase that. Don't add outside info.
Database Result: ```{db_query_result}```
Response:"""
        response = model.generate_content(prompt, generation_config=genai.types.GenerationConfig(max_output_tokens=250, temperature=0.6))
        text = "".join(part.text for part in response.candidates[0].content.parts).strip() if response.candidates and response.candidates[0].content.parts else ""
        if not text:
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                app.logger.warning(f"Gemini blocked: {response.prompt_feedback.block_reason_message}")
                return f"Response limited by filter: {response.prompt_feedback.block_reason_message}. Rephrase?"
            return "AI couldn't phrase a response. Direct info:\n" + db_query_result
        return text
    except Exception as e: app.logger.error(f"Gemini chat error: {e}"); return f"AI error. Direct info:\n{db_query_result}"

@app.route('/chat_api', methods=['POST'])
@login_required
def chat_api():
    data = request.get_json();
    if not data: return jsonify({"error": "Invalid JSON"}), 400
    msg = data.get('message','').strip()
    if not msg: return jsonify({"reply": "Type a message."})
    db_res = query_database_for_chatbot(msg.lower())
    final_reply = generate_ai_chat_response(msg, db_res)
    return jsonify({"reply": final_reply})

@app.route('/chatbot')
@login_required
def chatbot_page(): return render_template('chatbot.html', username=session.get('username'))



if __name__ == '__main__':
    init_db()
    print("DB Path:", os.path.abspath(DB_PATH))
    print("Starting SocketIO server...")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, use_reloader=True)

