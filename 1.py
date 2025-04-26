import sqlite3
import os

# Create a database directory if it doesn't exist
os.makedirs('data/db', exist_ok=True)

# Initialize the database
def init_db():
    conn = sqlite3.connect('data/db/spelling_app.db')
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