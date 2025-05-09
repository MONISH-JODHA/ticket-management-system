from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, render_template, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import sqlite3
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart # Added this
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from collections import defaultdict
from datetime import datetime

load_dotenv()

UPLOAD_FOLDER = 'uploads'
DB_PATH = './tickets.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'def@ult-Sup3r-S3cr3t-Key-Chang3-M3!')
CORS(app)

Password = os.getenv('PASSWORD')

GEMINI_API_KEY = os.getenv('GOOGLE_API_KEY')
if not GEMINI_API_KEY:
    print("CRITICAL WARNING: GOOGLE_API_KEY environment variable not set. Gemini AI calls will fail.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("Gemini API Key configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini API: {e}")
        GEMINI_API_KEY = None

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
                            password TEXT NOT NULL,
                            otp TEXT,
                            verified INTEGER DEFAULT 0
                        )''')
        conn.commit()

def is_valid_email(email):
    return email.endswith('@cloudkeeper.com')



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
            server.login('monish.jodha@cloudkeeper.com', PASSWORD)
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
    if 'username' in session:
        return redirect(url_for('form'))
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')
        if not username or not password:
            return render_template('login.html', error="Email and password are required.")
        if not is_valid_email(username):
            return render_template('login.html', error="Invalid email. Must be @cloudkeeper.com.")
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ? AND password = ? AND verified = 1", (username, password))
            user = cur.fetchone()
            if user:
                session['username'] = user['username']
                next_url = request.args.get('next')
                return redirect(next_url or url_for('form'))
            else:
                return render_template('login.html', error='Invalid credentials or account not verified.')
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
    session.pop('username', None)
    session.pop('pending_user', None)
    return redirect(url_for('login'))

@app.route('/submit', methods=['POST'])
@login_required
def submit_ticket():
    current_user = session.get('username')
    if request.is_json:
        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        remedies = data.get('remedies')
        created_by = data.get('created_by', current_user)
        created_at = data.get('created_at')
        file_path_str = ""
        remedy_doc_path = None # No remedy doc if JSON (GDoc import)
    else: # Form-data
        title = request.form.get('title')
        description = request.form.get('description')
        remedies = request.form.get('remedies', '') # Get remedies, default to empty if not present
        created_by = request.form.get('created_by', current_user)
        created_at = request.form.get('created_at')
        uploaded_files = request.files.getlist('screenshot')
        saved_file_paths = []
        if uploaded_files:
            for file_obj in uploaded_files:
                if file_obj and file_obj.filename:
                    filename = secure_filename(file_obj.filename)
                    file_save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file_obj.save(file_save_path)
                    saved_file_paths.append(file_save_path)
        file_path_str = ";".join(saved_file_paths)

        remedy_doc = request.files.get('remedy_doc')
        remedy_doc_path = None
        if remedy_doc and remedy_doc.filename:
            remedy_filename = secure_filename(remedy_doc.filename)
            remedy_doc_path = os.path.join(app.config['UPLOAD_FOLDER'], remedy_filename)
            remedy_doc.save(remedy_doc_path)


    if not all([title, created_by, created_at]):
        if request.is_json:
            return jsonify({"success": False, "detail": "Title, Submitted By, and Date are required."}), 400
        else:
            return redirect(url_for('form', error='Required fields missing'))

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'INSERT INTO tickets (title, description, remedies, file_path, remedy_doc_path, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (title, description, remedies, file_path_str, remedy_doc_path, created_by, created_at)
        )
        conn.commit()

    if request.is_json:
        return jsonify({"success": True, "message": "Ticket created successfully!"})
    else:
        return redirect(url_for('form', success='1'))

@app.route('/form')
@login_required
def form():
    success_flag = request.args.get('success')
    error_message = request.args.get('error')
    success_message = "Ticket submitted successfully!" if success_flag == '1' else None
    return render_template('form.html', success_html_content=success_message, error_message=error_message, username=session.get('username'))

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
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, params)
        tickets_raw = cur.fetchall()
        tickets = []
        for row in tickets_raw:
            ticket_dict = dict(row)
            if 'file_path' in ticket_dict and ticket_dict['file_path'] is not None:
                if isinstance(ticket_dict['file_path'], str) and ticket_dict['file_path'].strip():
                    ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
                elif not isinstance(ticket_dict['file_path'], list):
                    ticket_dict['file_path'] = []
            else:
                ticket_dict['file_path'] = []
            tickets.append(ticket_dict)
        return jsonify(tickets)

@app.route('/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE id=?", (ticket_id,))
        row = cur.fetchone()
        if row:
            ticket_dict = dict(row)
            if 'file_path' in ticket_dict and ticket_dict['file_path'] is not None:
                if isinstance(ticket_dict['file_path'], str) and ticket_dict['file_path'].strip():
                    ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
                elif not isinstance(ticket_dict['file_path'], list):
                     ticket_dict['file_path'] = []
            else:
                ticket_dict['file_path'] = []
            return jsonify(ticket_dict)
        return jsonify({"error": "Ticket not found"}), 404

@app.route('/tickets/<int:ticket_id>', methods=['PUT'])
@login_required
def update_ticket(ticket_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    remedies = data.get('remedies')
    status = data.get('status', 'Open') # Default to Open if not provided
    created_by = data.get('created_by') # Get these but don't update them by default
    created_at = data.get('created_at')

    if not title:
        return jsonify({"error": "Title is required"}), 400

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute('''UPDATE tickets SET title = ?, description = ?, remedies = ?, status = ?
                       WHERE id = ?''',
                     (title, description, remedies, status, ticket_id))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({'error': 'Ticket not found or no changes made'}), 404
    return jsonify({'message': 'Ticket updated successfully'})

@app.route('/uploads/<path:filename>', methods=['GET'])
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def home_or_main():
    if 'username' in session:
        return redirect(url_for('form'))
    return render_template('main.html')



@app.route('/view')
@login_required
def view_tickets_page():
    return render_template('view.html', username=session.get('username'))

@app.route('/user_ticket_view')
@login_required
def user_ticket_view_page():
    return render_template('users.html', username=session.get('username'))

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
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE created_by = ? ORDER BY created_at DESC", (username,))
        tickets_raw = cur.fetchall()
        tickets = []
        for row in tickets_raw:
            ticket_dict = dict(row)
            if 'file_path' in ticket_dict and ticket_dict['file_path'] is not None:
                if isinstance(ticket_dict['file_path'], str) and ticket_dict['file_path'].strip():
                    ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
                elif not isinstance(ticket_dict['file_path'], list):
                    ticket_dict['file_path'] = []
            else:
                ticket_dict['file_path'] = []
            tickets.append(ticket_dict)
        return jsonify(tickets)

@app.route('/extract_gdoc_content', methods=['POST'])
@login_required
def extract_gdoc_content_route():
    data = request.get_json()
    gdoc_url = data.get('gdoc_url')
    if not gdoc_url:
        return jsonify({"success": False, "detail": "Google Doc URL is required."}), 400
    if "/pub" not in gdoc_url:
        return jsonify({"success": False, "detail": "Please provide a 'Published to web' Google Doc link."}), 400
    try:
        response = requests.get(gdoc_url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        content_elements = soup.find('div', id='contents')
        extracted_text = ""
        if content_elements:
            for script_or_style in content_elements(['script', 'style']):
                script_or_style.decompose()
            extracted_text = content_elements.get_text(separator='\n', strip=True)
        else:
            body_content = soup.find('body')
            if body_content:
                for script_or_style in body_content(['script', 'style']):
                    script_or_style.decompose()
                extracted_text = body_content.get_text(separator='\n', strip=True)
        if not extracted_text.strip():
            return jsonify({"success": False, "detail": "No text content found/extracted from the document."}), 400
        return jsonify({"success": True, "content": extracted_text})
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "detail": "Timeout fetching Google Doc."}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "detail": f"Error fetching document: {str(e)}"}), 500
    except Exception as e:
        app.logger.error(f"Error parsing GDoc: {e}")
        return jsonify({"success": False, "detail": "Error parsing document content."}), 500
    
    

@app.route('/gdoc_importer')
@login_required
def gdoc_importer_page():
    return render_template('gdoc_import.html', username=session.get('username'))

@app.route('/ai-description', methods=['POST'])
@login_required
def ai_description():
    if not GEMINI_API_KEY:
         return jsonify({"error": "AI service is currently unavailable. API key not configured."}), 503
    data = request.get_json()
    if not data:
        app.logger.error("AI Description: Received non-JSON or empty payload.")
        return jsonify({"error": "Invalid request payload. Expected JSON."}), 400
    title = data.get('title', '')
    description = data.get('description', '')
    if not description.strip() and not title.strip():
        return jsonify({"error": "Title or description is required to generate AI content."}), 400
    if description.strip():
        prompt = f"You are an expert technical writer. Rewrite the following bug description to be clearer, more professional, and suitable for a technical audience. Ensure it is well-structured. If the input is already good, you can state that or make minor improvements. Output only the rewritten description.\n\nOriginal Description:\n```\n{description}\n```\n\nRewritten Description:"
    else:
        prompt = f"You are an expert technical writer. Write a detailed, clear, and professional description for a software bug ticket titled: \"{title}\". The description should be suitable for a technical audience and provide enough context for someone to understand the issue. Include potential steps to reproduce if logical, expected behavior, and actual behavior. Output only the generated description.\n\nTicket Title: {title}\n\nDetailed Description:"
    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=300,
                temperature=0.6,
            )
        )
        generated_text = ""
        if response.candidates and response.candidates[0].content.parts:
            generated_text = "".join(part.text for part in response.candidates[0].content.parts).strip()
        if not generated_text:
             if response.prompt_feedback and response.prompt_feedback.block_reason:
                app.logger.warning(f"Gemini content generation blocked: {response.prompt_feedback.block_reason_message} for prompt: {prompt[:200]}")
                return jsonify({"error": f"Content generation blocked by AI safety filters: {response.prompt_feedback.block_reason_message}. Please rephrase your input."}), 400
             app.logger.warning(f"Gemini returned empty content for prompt: {prompt[:200]}")
             return jsonify({"generated": "AI could not generate a description for this input. Please try rephrasing or providing more detail."})
        return jsonify({"generated": generated_text})
    except Exception as e:
        app.logger.error(f"Gemini API error: {str(e)}")
        return jsonify({"error": "An error occurred while communicating with the AI service."}), 500
    
    
@app.route('/api/ticket_status_counts', methods=['GET'])
@login_required
def get_ticket_status_summary():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT status, COUNT(*) as count FROM tickets GROUP BY status")
            status_rows = cur.fetchall()

            status_summary_from_db = {row['status']: row['count'] for row in status_rows if row['status']}

            # Define the desired order and default colors
            # Ensure status names here EXACTLY match those used in your database/application
            ordered_statuses_config = {
                "Open": {"count": 0, "color": "rgba(255, 159, 64, 0.8)"},
                "In Progress": {"count": 0, "color": "rgba(54, 162, 235, 0.8)"},
                "Resolved": {"count": 0, "color": "rgba(75, 192, 192, 0.8)"},
                "Closed": {"count": 0, "color": "rgba(150, 150, 150, 0.8)"},
                "Pending User": {"count": 0, "color": "rgba(201, 203, 207, 0.8)"}
                # Add any other statuses you use
            }

            # Populate counts from DB
            for status_name, data in ordered_statuses_config.items():
                if status_name in status_summary_from_db:
                    data["count"] = status_summary_from_db[status_name]

            chart_labels = list(ordered_statuses_config.keys())
            chart_counts = [data["count"] for data in ordered_statuses_config.values()]
            chart_colors = [data["color"] for data in ordered_statuses_config.values()]
            open_tickets_count = ordered_statuses_config.get("Open", {}).get("count", 0)

            return jsonify({
                "chart_labels": chart_labels,
                "chart_counts": chart_counts,
                "chart_colors": chart_colors,
                "open_tickets_count": open_tickets_count
            })
    except Exception as e:
        app.logger.error(f"Error fetching ticket status summary: {e}")
        return jsonify({"error": "Could not fetch ticket status summary"}), 500


@app.route('/api/tickets_over_time_counts', methods=['GET'])
@login_required
def get_tickets_over_time_counts():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Query to get counts per day. SQLite date functions might vary.
            # This example extracts YYYY-MM-DD.
            # cur.execute("""
            #     SELECT DATE(created_at) as creation_date, COUNT(*) as count
            #     FROM tickets
            #     GROUP BY DATE(created_at)
            #     ORDER BY creation_date ASC
            # """)
            # For a larger dataset, you might want to limit the date range, e.g., last 30 days
            cur.execute("""
                SELECT DATE(created_at) as creation_date, COUNT(*) as count
                FROM tickets
                WHERE DATE(created_at) >= DATE('now', '-30 days')
                GROUP BY DATE(created_at)
                ORDER BY creation_date ASC
            """)
            data_rows = cur.fetchall()

            # Prepare for Chart.js
            labels = [row['creation_date'] for row in data_rows if row['creation_date']]
            counts = [row['count'] for row in data_rows if row['creation_date']]

            return jsonify({"labels": labels, "counts": counts})
    except Exception as e:
        app.logger.error(f"Error fetching tickets over time summary: {e}")
        return jsonify({"error": "Could not fetch ticket trend data"}), 500
    
    
    
    
    
    
    

# In server.py

# ... (all your existing imports: Flask, os, sqlite3, genai, etc.)
# ... (UPLOAD_FOLDER, DB_PATH, app setup, GEMINI_API_KEY config)
# ... (init_db, is_valid_email, send_otp_email, login_required, and other routes)

def query_database_for_chatbot(user_message_lower):
    """
    Processes a user message and queries the database.
    Returns a string response with factual data from the DB.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Default response if no specific intent is matched by the end
    response_data = "I'm sorry, I couldn't find specific information for that. Perhaps rephrasing or asking about ticket IDs, users, or statuses might help? You can also try a general search like 'search tickets for [keyword]'."
    found_specific_intent = False

    # Example 1: Get ticket by ID
    if user_message_lower.startswith("ticket id ") or user_message_lower.startswith("show ticket ") or user_message_lower.startswith("details for ticket "):
        try:
            ticket_id_str = ""
            # Try to find a number after common phrases
            phrases = ["ticket id ", "show ticket ", "details for ticket "]
            for phrase in phrases:
                if user_message_lower.startswith(phrase):
                    ticket_id_str = user_message_lower[len(phrase):].strip()
                    break
            
            if not ticket_id_str.isdigit(): # Check if it's purely a number
                 # Try to extract last word if it's a digit
                parts = user_message_lower.split()
                if parts and parts[-1].isdigit():
                    ticket_id_str = parts[-1]
                else:
                    raise ValueError("No valid ID found after keyword.")


            ticket_id = int(ticket_id_str)
            cur.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
            ticket = cur.fetchone()
            if ticket:
                response_parts = [
                    f"Ticket ID: {ticket['id']}",
                    f"Title: {ticket['title']}",
                    f"Status: {ticket['status']}",
                    f"Description: {ticket['description']}",
                    f"Submitted by: {ticket['created_by']}",
                    f"Submitted on: {ticket['created_at']}"
                ]
                if ticket['remedies'] and ticket['remedies'].strip():
                    response_parts.append(f"Remedies/Steps: {ticket['remedies']}")
                if ticket['remedy_doc_path'] and ticket['remedy_doc_path'].strip():
                     response_parts.append(f"Remedy Document: {os.path.basename(ticket['remedy_doc_path'])}")
                if ticket['file_path'] and ticket['file_path'].strip():
                    screenshots = [os.path.basename(p) for p in ticket['file_path'].split(';') if p.strip()]
                    if screenshots:
                        response_parts.append(f"Attached Screenshots: {', '.join(screenshots)}")
                response_data = "\n".join(response_parts)
            else:
                response_data = f"No ticket found with ID {ticket_id}."
            found_specific_intent = True
        except ValueError:
            response_data = "Please provide a valid ticket ID number (e.g., 'ticket id 123' or 'show ticket 45')."
        except Exception as e:
            app.logger.error(f"Error fetching ticket by ID for chatbot: {e}")
            response_data = "An error occurred while fetching ticket details. Please check the ID."

    # Example 2: Get tickets by user
    elif user_message_lower.startswith("tickets by ") or user_message_lower.startswith("show tickets for "):
        try:
            search_query = user_message_lower.replace("tickets by ", "").replace("show tickets for ", "").strip()
            if not search_query:
                response_data = "Please specify a username (e.g., 'tickets by user@example.com')."
            else:
                username_to_search = search_query
                cur.execute("SELECT id, title, status, created_at FROM tickets WHERE created_by LIKE ? ORDER BY created_at DESC LIMIT 5", (f"%{username_to_search}%",))
                tickets = cur.fetchall()
                if tickets:
                    response_data = f"Here are the latest 5 tickets for user matching '{username_to_search}':\n"
                    for t in tickets:
                        response_data += f"- ID {t['id']}: {t['title']} (Status: {t['status']}, Date: {t['created_at']})\n"
                else:
                    response_data = f"No tickets found for user matching '{username_to_search}'."
            found_specific_intent = True
        except Exception as e:
            app.logger.error(f"Error fetching tickets by user for chatbot: {e}")
            response_data = "An error occurred while fetching user tickets."

    # Example 3: Get tickets by status
    elif any(keyword in user_message_lower for keyword in [" tickets", " status is "]) and \
         any(status_keyword in user_message_lower for status_keyword in ['open', 'resolved', 'closed', 'in progress', 'pending user']):
        status_to_find = None
        # More precise status extraction
        possible_statuses = {'open': 'Open', 'resolved': 'Resolved', 'closed': 'Closed', 
                             'in progress': 'In Progress', 'pending user': 'Pending User'}
        for key_phrase, status_val in possible_statuses.items():
            if key_phrase in user_message_lower:
                status_to_find = status_val
                break
        
        if status_to_find:
            cur.execute("SELECT id, title, created_by FROM tickets WHERE status = ? ORDER BY created_at DESC LIMIT 5", (status_to_find,))
            tickets = cur.fetchall()
            if tickets:
                response_data = f"Here are the latest 5 '{status_to_find}' tickets:\n"
                for t in tickets:
                    response_data += f"- ID {t['id']}: {t['title']} (By: {t['created_by']})\n"
            else:
                response_data = f"No '{status_to_find}' tickets found currently."
            found_specific_intent = True
        else:
            response_data = "Which status are you interested in (e.g., open, resolved, closed)?"

    # Example 4: Search tickets for keyword
    elif user_message_lower.startswith("search tickets for ") or user_message_lower.startswith("find tickets about "):
        search_term = user_message_lower.replace("search tickets for ", "").replace("find tickets about ","").strip()
        if search_term:
            cur.execute("SELECT id, title, status FROM tickets WHERE title LIKE ? OR description LIKE ? OR remedies LIKE ? ORDER BY created_at DESC LIMIT 5",
                        (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%"))
            tickets = cur.fetchall()
            if tickets:
                response_data = f"Found up to 5 tickets matching '{search_term}':\n"
                for t in tickets:
                    response_data += f"- ID {t['id']}: {t['title']} (Status: {t['status']})\n"
            else:
                response_data = f"No tickets found matching '{search_term}'."
        else:
            response_data = "Please specify what you want to search for (e.g., 'search tickets for login issue')."
        found_specific_intent = True

    # Example 5: Count tickets by status
    elif user_message_lower.startswith("how many tickets are ") or user_message_lower.startswith("count of "):
        status_to_count = None
        possible_statuses = {'open': 'Open', 'resolved': 'Resolved', 'closed': 'Closed', 
                             'in progress': 'In Progress', 'pending user': 'Pending User'}
        for key_phrase, status_val in possible_statuses.items():
            if key_phrase in user_message_lower:
                status_to_count = status_val
                break

        if status_to_count:
            cur.execute("SELECT COUNT(*) FROM tickets WHERE status = ?", (status_to_count,))
            count = cur.fetchone()[0]
            response_data = f"There are {count} ticket(s) with status '{status_to_count}'."
        elif "total tickets" in user_message_lower or "all tickets" in user_message_lower:
            cur.execute("SELECT COUNT(*) FROM tickets")
            count = cur.fetchone()[0]
            response_data = f"There are a total of {count} ticket(s) in the system."
        else:
            response_data = "Which status count are you interested in (e.g., 'how many tickets are open')?"
        found_specific_intent = True

    # Example 6: Get latest N tickets
    elif "latest " in user_message_lower and " tickets" in user_message_lower:
        try:
            parts = user_message_lower.split()
            num_tickets = None
            for i, part in enumerate(parts):
                if part == "latest" and i + 1 < len(parts) and parts[i+1].isdigit():
                    num_tickets = int(parts[i+1])
                    break
            
            if num_tickets is not None:
                num_tickets = min(num_tickets, 10) # Limit
                cur.execute("SELECT id, title, status FROM tickets ORDER BY created_at DESC LIMIT ?", (num_tickets,))
                tickets = cur.fetchall()
                if tickets:
                    response_data = f"Here are the latest {len(tickets)} tickets:\n"
                    for t in tickets:
                        response_data += f"- ID {t['id']}: {t['title']} (Status: {t['status']})\n"
                else:
                    response_data = "No tickets found."
            else:
                response_data = "Please specify how many latest tickets you want (e.g., 'latest 5 tickets')."
            found_specific_intent = True
        except ValueError:
             response_data = "Please specify a valid number for latest tickets (e.g., 'latest 5 tickets')."
        except Exception as e:
            app.logger.error(f"Error fetching latest tickets for chatbot: {e}")
            response_data = "An error occurred while fetching latest tickets."

    # Example 7: Who created ticket X?
    elif user_message_lower.startswith("who created ticket ") or user_message_lower.startswith("creator of ticket "):
        try:
            ticket_id_str = ""
            phrases = ["who created ticket ", "creator of ticket "]
            for phrase in phrases:
                if user_message_lower.startswith(phrase):
                    ticket_id_str = user_message_lower[len(phrase):].strip()
                    break
            if not ticket_id_str.isdigit():
                parts = user_message_lower.split()
                if parts and parts[-1].isdigit():
                    ticket_id_str = parts[-1]
                else:
                    raise ValueError("No valid ID found after keyword.")

            ticket_id = int(ticket_id_str)
            cur.execute("SELECT created_by, title FROM tickets WHERE id = ?", (ticket_id,))
            ticket = cur.fetchone()
            if ticket:
                response_data = f"Ticket ID {ticket_id} (titled \"{ticket['title']}\") was created by: {ticket['created_by']}."
            else:
                response_data = f"No ticket found with ID {ticket_id}."
            found_specific_intent = True
        except ValueError:
            response_data = "Please provide a valid ticket ID number (e.g., 'who created ticket 123')."
        except Exception as e:
            app.logger.error(f"Error fetching ticket creator: {e}")
            response_data = "An error occurred while fetching ticket creator information."

    # Fallback keyword search if no specific intent matched
    if not found_specific_intent and len(user_message_lower.split()) > 1:
        search_term = user_message_lower
        cur.execute("SELECT id, title, status FROM tickets WHERE title LIKE ? OR description LIKE ? OR remedies LIKE ? OR created_by LIKE ? ORDER BY created_at DESC LIMIT 3",
                    (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%"))
        tickets = cur.fetchall()
        if tickets:
            response_data = f"I found these tickets that might be related to '{search_term}':\n"
            for t in tickets:
                response_data += f"- ID {t['id']}: {t['title']} (Status: {t['status']})\n"
            response_data += "\nIs this what you were looking for, or can I help with something more specific?"
        # If no fallback results, the initial default message is used.

    conn.close()
    return response_data

def generate_ai_chat_response(user_message, db_query_result):
    """
    Uses Gemini to formulate a more natural response based on DB query result.
    """
    if not GEMINI_API_KEY:
        app.logger.warning("Chatbot: Gemini API key not configured. Falling back to direct DB response.")
        return db_query_result

    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        # Refined prompt for better summarization and handling of "not found"
        prompt = f"""You are a friendly and helpful assistant for a ticket management system.
        A user asked the following question: "{user_message}"

        Based *only* on the database information provided below, formulate a concise, helpful, and natural-sounding response.
        - If the database information is a list of tickets, summarize it clearly. For example, instead of just listing IDs and titles, you could say "I found a few tickets related to that: Ticket 123 titled 'Login Issue', Ticket 456 titled 'Payment Error', ...".
        - If the database information indicates "No ticket found" or "No tickets found", rephrase this politely (e.g., "I couldn't find any tickets matching that criteria.").
        - If the database information is a direct answer (e.g., a count, or details for a single ticket), present that information clearly.
        - Do not add any information not present in the "Database Result".
        - If the "Database Result" is the default "I'm sorry, I couldn't quite understand that..." message, then your response should also be a polite rephrasing of not understanding, perhaps suggesting the user try a different phrasing or one of the example commands if appropriate.

        Database Result:
        ```
        {db_query_result}
        ```

        Your response to the user:"""

        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=250, # Increased for potentially more descriptive summaries
                temperature=0.6 # Slightly more creative but still factual
            )
        )
        generated_text = ""
        if response.candidates and response.candidates[0].content.parts:
            generated_text = "".join(part.text for part in response.candidates[0].content.parts).strip()

        if not generated_text: # If AI returns empty
             if response.prompt_feedback and response.prompt_feedback.block_reason:
                app.logger.warning(f"Chatbot Gemini content generation blocked: {response.prompt_feedback.block_reason_message}")
                # Return a user-friendly message about the block, not the raw DB query result
                return f"My ability to respond was limited by a content filter. Could you try rephrasing your question? (Details: {response.prompt_feedback.block_reason_message})"
             app.logger.warning(f"Chatbot Gemini returned empty content. DB result was: {db_query_result}")
             return "I found some information, but I'm having a little trouble phrasing the response right now. Here's the direct data:\n" + db_query_result # Fallback with context
        return generated_text
    except Exception as e:
        app.logger.error(f"Chatbot Gemini API error: {e}")
        # Fallback to direct DB result if AI processing fails, with a note
        return f"I encountered an issue with my AI processing. Here's the information I found directly from the database:\n{db_query_result}"


@app.route('/chat_api', methods=['POST'])
@login_required
def chat_api(): # This is the single, correct definition
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    user_message = data.get('message', '').strip()
    # The 'use_ai' flag can be removed from frontend if AI processing is always desired here.
    # If you want to keep the option, the frontend should send it.
    # Forcing AI processing for all chat replies from this endpoint:
    use_ai_processing = True

    if not user_message:
        return jsonify({"reply": "Please type a message."})

    user_message_lower = user_message.lower()
    db_query_result = query_database_for_chatbot(user_message_lower)

    if use_ai_processing:
        final_reply = generate_ai_chat_response(user_message, db_query_result)
    else: # This branch would only be hit if use_ai_processing could be false
        final_reply = db_query_result

    return jsonify({"reply": final_reply})

# ... (rest of your server.py: chatbot_page, init_db, main, etc.)


@app.route('/chatbot') # Route to serve the chatbot UI page
@login_required
def chatbot_page():
    return render_template('chatbot.html', username=session.get('username'))

if __name__ == '__main__':
    init_db()
    print("DB Path Used by Flask:", os.path.abspath(DB_PATH))
    app.run(debug=True, port=5001)