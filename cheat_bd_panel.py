"""
CheatBD_Panel.BD
A single-file Flask admin panel written in Python.

Features:
- SQLite backend (file: cheatbd.db)
- Simple auth (username/password) with hashed password
- CRUD for "items" (can be used for cheats, notes, whatever)
- JSON API endpoint for items
- Minimal, responsive UI (Bulma CSS via CDN)

Run:
1. pip install flask
2. python CheatBD_Panel.BD
3. Open http://127.0.0.1:5000

This file deliberately keeps templates inline so it's a single-file app.
Use for learning and local development only.
"""

from flask import Flask, g, render_template_string, request, redirect, url_for, session, jsonify, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps

APP_SECRET = os.environ.get('CHEATBD_SECRET', 'change_this_secret_for_prod')
DB_PATH = os.environ.get('CHEATBD_DB', 'cheatbd.db')
DEFAULT_ADMIN = os.environ.get('CHEATBD_ADMIN', 'admin')
DEFAULT_PASS = os.environ.get('CHEATBD_PASS', 'admin123')

app = Flask(__name__)
app.config['SECRET_KEY'] = APP_SECRET
app.config['DATABASE'] = DB_PATH

# --- DB helpers ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT,
        tags TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    db.commit()

    # Ensure an admin user exists
    cur.execute('SELECT id FROM users WHERE username = ?', (DEFAULT_ADMIN,))
    if cur.fetchone() is None:
        cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (DEFAULT_ADMIN, generate_password_hash(DEFAULT_PASS)))
        db.commit()
        print(f"Created default admin user: {DEFAULT_ADMIN} / {DEFAULT_PASS}")

# --- Auth ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        cur = db.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user'] = {'id': user['id'], 'username': user['username']}
            db.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (user['id'], 'login'))
            db.commit()
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next') or url_for('dashboard')
            return redirect(next_url)
        flash('Invalid username or password', 'danger')
    return render_template_string(TPL_LOGIN)

@app.route('/logout')
def logout():
    user = session.pop('user', None)
    if user:
        db = get_db()
        db.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (user.get('id'), 'logout'))
        db.commit()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# --- Routes ---

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    cur = db.execute('SELECT COUNT(*) as total FROM items')
    total = cur.fetchone()['total']
    cur = db.execute('SELECT id, title, created_at FROM items ORDER BY created_at DESC LIMIT 6')
    recent = cur.fetchall()
    return render_template_string(TPL_DASHBOARD, total=total, recent=recent)

@app.route('/items')
@login_required
def items():
    q = request.args.get('q', '').strip()
    db = get_db()
    if q:
        cur = db.execute("SELECT * FROM items WHERE title LIKE ? OR content LIKE ? ORDER BY updated_at DESC", ('%'+q+'%', '%'+q+'%'))
    else:
        cur = db.execute('SELECT * FROM items ORDER BY updated_at DESC')
    rows = cur.fetchall()
    return render_template_string(TPL_ITEMS, items=rows, q=q)

@app.route('/items/add', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        tags = request.form.get('tags', '').strip()
        if not title:
            flash('Title is required', 'danger')
        else:
            db = get_db()
            db.execute('INSERT INTO items (title, content, tags) VALUES (?, ?, ?)', (title, content, tags))
            db.commit()
            flash('Item added', 'success')
            return redirect(url_for('items'))
    return render_template_string(TPL_ITEM_FORM, item=None)

@app.route('/items/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    db = get_db()
    cur = db.execute('SELECT * FROM items WHERE id = ?', (item_id,))
    item = cur.fetchone()
    if not item:
        flash('Item not found', 'danger')
        return redirect(url_for('items'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        tags = request.form.get('tags', '').strip()
        if not title:
            flash('Title is required', 'danger')
        else:
            db.execute('UPDATE items SET title=?, content=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                       (title, content, tags, item_id))
            db.commit()
            flash('Item updated', 'success')
            return redirect(url_for('items'))
    return render_template_string(TPL_ITEM_FORM, item=item)

@app.route('/items/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    db = get_db()
    db.execute('DELETE FROM items WHERE id = ?', (item_id,))
    db.commit()
    flash('Item deleted', 'info')
    return redirect(url_for('items'))

# --- API ---
@app.route('/api/items')
@login_required
def api_items():
    db = get_db()
    cur = db.execute('SELECT * FROM items ORDER BY updated_at DESC')
    rows = cur.fetchall()
    items = [dict(i) for i in rows]
    return jsonify(items)

# --- Templates (inline) ---

TPL_BASE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ title or 'CheatBD Panel' }}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
  <style> .container { max-width: 960px; margin-top: 20px; } .truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; } </style>
</head>
<body>
<section class="section">
  <div class="container">
    <nav class="level">
      <div class="level-left">
        <div class="level-item">
          <h1 class="title">CheatBD Panel</h1>
        </div>
      </div>
      <div class="level-right">
        <div class="level-item">
          {% if session.user %}
            <div class="buttons">
              <a class="button is-small" href="{{ url_for('dashboard') }}">Dashboard</a>
              <a class="button is-small" href="{{ url_for('items') }}">Items</a>
              <a class="button is-small is-light" href="{{ url_for('logout') }}">Logout</a>
            </div>
          {% else %}
            <a class="button is-small" href="{{ url_for('login') }}">Login</a>
          {% endif %}
        </div>
      </div>
    </nav>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="notification is-{{ 'danger' if cat == 'danger' else ('success' if cat == 'success' else 'info') }}">
            {{ msg }}
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}

    <footer class="footer" style="margin-top:30px">
      <div class="content has-text-centered">
        <p>CheatBD Panel — single-file Flask demo. Not for production.</p>
      </div>
    </footer>
  </div>
</section>
</body>
</html>
"""

TPL_LOGIN = """
{% extends none %}
''' + TPL_BASE + '''
{% block content %}
  <div class="box">
    <h2 class="title is-4">Login</h2>
    <form method="post">
      <div class="field">
        <label class="label">Username</label>
        <div class="control"><input class="input" name="username" required></div>
      </div>
      <div class="field">
        <label class="label">Password</label>
        <div class="control"><input class="input" type="password" name="password" required></div>
      </div>
      <div class="field">
        <div class="control"><button class="button is-primary">Login</button></div>
      </div>
    </form>
  </div>
{% endblock %}
"""

TPL_DASHBOARD = """
{% extends none %}
''' + TPL_BASE + '''
{% block content %}
  <div class="columns">
    <div class="column is-two-thirds">
      <div class="box">
        <h2 class="title is-5">Overview</h2>
        <p>Total items: <strong>{{ total }}</strong></p>
        <hr>
        <h3 class="subtitle is-6">Recent items</h3>
        <ul>
          {% for it in recent %}
            <li><a href="{{ url_for('edit_item', item_id=it['id']) }}">{{ it['title'] }}</a> — <small>{{ it['created_at'] }}</small></li>
          {% else %}
            <li>No items yet.</li>
          {% endfor %}
        </ul>
      </div>
    </div>
    <div class="column">
      <div class="box">
        <h2 class="title is-6">Quick Actions</h2>
        <a class="button is-link is-fullwidth" href="{{ url_for('add_item') }}">Add item</a>
        <a class="button is-info is-fullwidth" href="{{ url_for('items') }}" style="margin-top:6px">Manage items</a>
      </div>
    </div>
  </div>
{% endblock %}
"""

TPL_ITEMS = """
{% extends none %}
''' + TPL_BASE + '''
{% block content %}
  <div class="box">
    <div class="level">
      <div class="level-left"><h2 class="title is-5">Items</h2></div>
      <div class="level-right">
        <form method="get" action="{{ url_for('items') }}">
          <div class="field has-addons">
            <div class="control"><input class="input" name="q" placeholder="Search..." value="{{ q }}"></div>
            <div class="control"><button class="button">Search</button></div>
          </div>
        </form>
      </div>
    </div>

    <a class="button is-primary" href="{{ url_for('add_item') }}">Add new item</a>
    <table class="table is-fullwidth is-striped" style="margin-top:12px">
      <thead><tr><th>Title</th><th>Tags</th><th>Updated</th><th></th></tr></thead>
      <tbody>
        {% for it in items %}
          <tr>
            <td class="truncate" style="max-width: 350px"><a href="{{ url_for('edit_item', item_id=it['id']) }}">{{ it['title'] }}</a></td>
            <td>{{ it['tags'] or '-' }}</td>
            <td>{{ it['updated_at'] }}</td>
            <td style="white-space:nowrap">
              <a class="button is-small" href="{{ url_for('edit_item', item_id=it['id']) }}">Edit</a>
              <form method="post" action="{{ url_for('delete_item', item_id=it['id']) }}" style="display:inline" onsubmit="return confirm('Delete this item?');">
                <button class="button is-small is-danger">Delete</button>
              </form>
            </td>
          </tr>
        {% else %}
          <tr><td colspan="4">No items.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% endblock %}
"""

TPL_ITEM_FORM = """
{% extends none %}
''' + TPL_BASE + '''
{% block content %}
  <div class="box">
    <h2 class="title is-5">{{ 'Edit' if item else 'Add' }} Item</h2>
    <form method="post">
      <div class="field">
        <label class="label">Title</label>
        <div class="control"><input class="input" name="title" required value="{{ item['title'] if item else '' }}"></div>
      </div>
      <div class="field">
        <label class="label">Content</label>
        <div class="control"><textarea class="textarea" name="content">{{ item['content'] if item else '' }}</textarea></div>
      </div>
      <div class="field">
        <label class="label">Tags (comma-separated)</label>
        <div class="control"><input class="input" name="tags" value="{{ item['tags'] if item else '' }}"></div>
      </div>
      <div class="field">
        <div class="control"><button class="button is-primary">Save</button> <a class="button" href="{{ url_for('items') }}">Cancel</a></div>
      </div>
    </form>
  </div>
{% endblock %}
"""

# --- App startup ---

if __name__ == '__main__':
    # Create DB file and tables if missing
    init_db()
    print('Starting CheatBD Panel on http://127.0.0.1:5000')
    app.run(debug=True)
