from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import random
import os
import json
import re
import sqlite3
from datetime import datetime, timedelta
import uuid
from gtts import gTTS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/audio'
app.config['DATABASE'] = 'data/db/spelling_app.db'
app.secret_key = 'your_very_secret_key_here'  # Change this to a random secret key in production

# Create required directories if they don't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data/db', exist_ok=True)

# Email settings (for password reset)
EMAIL_ADDRESS = "your_email@example.com"  # Update with your email
EMAIL_PASSWORD = "your_email_password"     # Update with your password
EMAIL_SERVER = "smtp.example.com"          # Update with your SMTP server
EMAIL_PORT = 587                           # Update with your SMTP port

# Active sessions for practice
active_sessions = {}

def get_db_connection():
    """Create a connection to the SQLite database"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row  # This enables name-based access to columns
    return conn

def init_db():
    """Initialize the database tables if they don't exist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP
    )
    ''')
    
    # Create word_lists table with user reference
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS word_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        list_name TEXT NOT NULL,
        words TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, list_name)
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database at startup
init_db()

def user_exists(username):
    """Check if a username already exists"""
    conn = get_db_connection()
    user = conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user is not None

def email_exists(email):
    """Check if an email already exists"""
    conn = get_db_connection()
    user = conn.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user is not None

def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    """Get user by email"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

def get_user_by_reset_token(token):
    """Get user by reset token"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?', 
                       (token, datetime.now())).fetchone()
    conn.close()
    return user

def create_user(username, email, password):
    """Create a new user"""
    conn = get_db_connection()
    password_hash = generate_password_hash(password)
    
    try:
        conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    
    conn.close()
    return success

def update_user_password(user_id, new_password):
    """Update user password"""
    conn = get_db_connection()
    password_hash = generate_password_hash(new_password)
    
    conn.execute(
        'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
        (password_hash, user_id)
    )
    conn.commit()
    conn.close()

def set_password_reset_token(email):
    """Generate and set a password reset token"""
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=24)  # Token expires in 24 hours
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
        (token, expiry, email)
    )
    conn.commit()
    conn.close()
    
    return token

def send_password_reset_email(email, token):
    """Send password reset email"""
    reset_link = f"{request.host_url}reset_password/{token}"
    
    message = MIMEMultipart()
    message["From"] = EMAIL_ADDRESS
    message["To"] = email
    message["Subject"] = "Password Reset Request"
    
    body = f"""
    Hello,
    
    You have requested to reset your password for the Spelling Practice App.
    Please click the link below to reset your password:
    
    {reset_link}
    
    This link will expire in 24 hours.
    
    If you did not request this, please ignore this email.
    
    Best regards,
    Spelling Practice App Team
    """
    
    message.attach(MIMEText(body, "plain"))
    
    try:
        server = smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def get_user_word_lists(user_id):
    """Get all word lists for a user"""
    conn = get_db_connection()
    lists = conn.execute('SELECT id, list_name, words FROM word_lists WHERE user_id = ?', (user_id,)).fetchall()
    
    result = {}
    for lst in lists:
        result[lst['list_name']] = json.loads(lst['words'])
    
    conn.close()
    return result

def save_user_word_list(user_id, list_name, words):
    """Save a word list for a user"""
    conn = get_db_connection()
    words_json = json.dumps(words)
    
    try:
        conn.execute(
            'INSERT INTO word_lists (user_id, list_name, words) VALUES (?, ?, ?)',
            (user_id, list_name, words_json)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        # Update existing list
        conn.execute(
            'UPDATE word_lists SET words = ? WHERE user_id = ? AND list_name = ?',
            (words_json, user_id, list_name)
        )
        conn.commit()
        success = True
    except Exception as e:
        print(f"Error saving word list: {e}")
        success = False
    
    conn.close()
    return success

def delete_user_word_list(user_id, list_name):
    """Delete a word list for a user"""
    conn = get_db_connection()
    
    conn.execute(
        'DELETE FROM word_lists WHERE user_id = ? AND list_name = ?',
        (user_id, list_name)
    )
    conn.commit()
    
    conn.close()
    return True

def scramble_word(word):
    """Scramble the letters of a word"""
    chars = list(word)
    # Make sure the scrambled word is different from the original
    while True:
        random.shuffle(chars)
        scrambled = ''.join(chars)
        if scrambled != word:
            return scrambled
    return scrambled

def generate_wrong_spellings(word, num_variants=3):
    """Generate plausible wrong spellings for a word"""
    variants = []
    operations = [
        # Double a letter
        lambda w, i: w[:i] + w[i] + w[i:] if i < len(w) else w,
        # Remove a letter
        lambda w, i: w[:i] + w[i+1:] if i < len(w) else w,
        # Swap two adjacent letters
        lambda w, i: w[:i] + w[i+1] + w[i] + w[i+2:] if i < len(w)-1 else w,
        # Replace a vowel with another vowel
        lambda w, i: w[:i] + random.choice('aeiou') + w[i+1:] if i < len(w) and w[i] in 'aeiou' else w,
        # Replace a consonant with another common consonant
        lambda w, i: w[:i] + random.choice('bcdfghjklmnpqrstvwxyz') + w[i+1:] if i < len(w) and w[i] not in 'aeiou' else w,
    ]
    
    # Try to generate unique variants
    attempts = 0
    while len(variants) < num_variants and attempts < 20:
        attempts += 1
        # Apply random operations to create a misspelling
        misspelled = word
        num_operations = random.randint(1, 2)  # Apply 1-2 operations
        
        for _ in range(num_operations):
            op = random.choice(operations)
            pos = random.randint(0, len(misspelled) - 1)
            misspelled = op(misspelled, pos)
        
        # Make sure it's different and not already in our list
        if misspelled != word and misspelled not in variants:
            variants.append(misspelled)
    
    # If we couldn't generate enough, add some simple variants
    while len(variants) < num_variants:
        pos = random.randint(0, len(word) - 1)
        variant = word[:pos] + random.choice('abcdefghijklmnopqrstuvwxyz') + word[pos+1:]
        if variant != word and variant not in variants:
            variants.append(variant)
    
    return variants

def introduce_errors(word):
    """Introduce 1-2 spelling errors in a word"""
    operations = [
        # Double a letter
        lambda w, i: w[:i] + w[i] + w[i:] if i < len(w) else w,
        # Remove a letter
        lambda w, i: w[:i] + w[i+1:] if i < len(w) else w,
        # Swap two adjacent letters
        lambda w, i: w[:i] + w[i+1] + w[i] + w[i+2:] if i < len(w)-1 else w,
        # Replace a vowel with another vowel
        lambda w, i: w[:i] + random.choice('aeiou') + w[i+1:] if i < len(w) and w[i] in 'aeiou' else w,
        # Replace a consonant with another common consonant
        lambda w, i: w[:i] + random.choice('bcdfghjklmnpqrstvwxyz') + w[i+1:] if i < len(w) and w[i] not in 'aeiou' else w,
    ]
    
    # Apply 1-2 operations to create errors
    result = word
    num_operations = random.randint(1, min(2, len(word) - 1))
    
    for _ in range(num_operations):
        op = random.choice(operations)
        pos = random.randint(0, len(result) - 1)
        result = op(result, pos)
    
    # Make sure the result is different
    return result if result != word else introduce_errors(word)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user['password_hash'], password):
            # Set user session
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('You have been logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate input
        if not username or not email or not password:
            flash('All fields are required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif user_exists(username):
            flash('Username already taken.', 'error')
        elif email_exists(email):
            flash('Email already registered.', 'error')
        else:
            # Create user
            if create_user(username, email, password):
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Error creating account. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    # Clear session
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user_by_email(email)
        
        if user:
            # Generate reset token
            token = set_password_reset_token(email)
            
            # Send reset email
            if send_password_reset_email(email, token):
                flash('Password reset instructions sent to your email.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to send reset email. Please try again later.', 'error')
        else:
            # To prevent user enumeration, still show success message
            flash('If your email is registered, you will receive reset instructions.', 'success')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify token
    user = get_user_by_reset_token(token)
    
    if not user:
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not password:
            flash('Password is required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            # Update password
            update_user_password(user['id'], password)
            flash('Password updated successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Main routes
@app.route('/')
def index():
    if 'user_id' in session:
        # Get user's word lists
        word_lists = get_user_word_lists(session['user_id'])
        return render_template('index.html', word_lists=word_lists, logged_in=True, username=session.get('username'))
    else:
        return render_template('index.html', word_lists={}, logged_in=False)

@app.route('/submit_words', methods=['POST'])
def submit_words():
    data = request.json
    words_list = data.get('words', '').split('\n')
    words_list = [word.strip() for word in words_list if word.strip()]
    
    if 'save_list' in data and data['save_list']:
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({'error': 'You must be logged in to save word lists'}), 401
        
        list_name = data.get('list_name', 'Unnamed List')
        save_user_word_list(session['user_id'], list_name, words_list)
    
    session_id = str(random.randint(1000, 9999))
    active_sessions[session_id] = {
        'words': words_list,
        'practice_type': data.get('practice_type', 'spell')
    }
    
    # Generate audio files for each word
    
    upload_folder = app.config['UPLOAD_FOLDER']

    for word in words_list:
        filename = f"{word}.mp3"
        if filename in os.listdir(upload_folder):
         continue
        else:
            try:
                tts = gTTS(text=word, lang='en', slow=False)
                file_path = os.path.join(upload_folder, filename)
                tts.save(file_path)
            except Exception as e:
                 print(f"Error generating audio for {word}: {e}")

    
    return jsonify({
        'session_id': session_id, 
        'word_count': len(words_list),
        'practice_type': data.get('practice_type', 'spell')
    })


@app.route('/practice/<session_id>')
def practice(session_id):
    if session_id not in active_sessions:
        return "Session not found", 404
    
    practice_type = active_sessions[session_id]['practice_type']
    return render_template('practice.html', 
                          session_id=session_id, 
                          practice_type=practice_type,
                          logged_in='user_id' in session,
                          username=session.get('username'))

@app.route('/get_words/<session_id>')
def get_words(session_id):
    if session_id not in active_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    # Randomize words for this session
    words = active_sessions[session_id]['words'].copy()
    random.shuffle(words)
    
    practice_type = active_sessions[session_id]['practice_type']
    response_data = {'words': words}
    
    # Prepare data for specific practice types
    if practice_type == 'fill_blank':
        blanked_words = []
        solutions = []
        
        for word in words:
            if len(word) <= 3:
                # For very short words, just blank one letter
                blank_index = random.randint(0, len(word) - 1)
                blanked_word = word[:blank_index] + '_' + word[blank_index + 1:]
            else:
                # Blank about 30% of letters (at least 1)
                num_blanks = max(1, int(len(word) * 0.3))
                blank_indices = random.sample(range(len(word)), num_blanks)
                blanked_word = ''.join('_' if i in blank_indices else letter for i, letter in enumerate(word))
            
            blanked_words.append(blanked_word)
            solutions.append(word)
        
        response_data['blanked_words'] = blanked_words
        response_data['solutions'] = solutions
    
    elif practice_type == 'scramble':
        scrambled_words = [scramble_word(word) for word in words]
        response_data['scrambled_words'] = scrambled_words
    
    elif practice_type == 'multiple_choice':
        options_list = []
        
        for word in words:
            # Generate wrong spellings
            wrong_spellings = generate_wrong_spellings(word)
            
            # Create options (correct + wrong) and shuffle
            options = [word] + wrong_spellings
            random.shuffle(options)
            
            options_list.append(options)
        
        response_data['options_list'] = options_list
    
    elif practice_type == 'word_building':
        # For word building, we'll just provide the words
        # The UI will handle the progressive reveal
        pass
    
    elif practice_type == 'error_correction':
        incorrect_words = [introduce_errors(word) for word in words]
        response_data['incorrect_words'] = incorrect_words
    
    return jsonify(response_data)

@app.route('/get_saved_list/<list_name>')
def get_saved_list(list_name):
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'error': 'You must be logged in to access word lists'}), 401
    
    word_lists = get_user_word_lists(session['user_id'])
    if list_name not in word_lists:
        return jsonify({'error': 'List not found'}), 404
    
    return jsonify({'words': word_lists[list_name]})

@app.route('/delete_word_list/<list_name>', methods=['POST'])
def delete_word_list(list_name):
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'error': 'You must be logged in to delete word lists'}), 401
    
    if delete_user_word_list(session['user_id'], list_name):
        return jsonify({'success': True})
    return jsonify({'error': 'List not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)