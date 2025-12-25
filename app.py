from flask import Flask, render_template_string, request, redirect, url_for, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import random
import string
from datetime import datetime, date

# Initialize App
app = Flask(__name__)
app.secret_key = 'my_gitam_secret_2025'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Setup
def init_db():
    os.makedirs('instance', exist_ok=True)
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT NOT NULL,
        class_section TEXT,
        email TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        semester INTEGER NOT NULL,
        branch TEXT NOT NULL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS faculty_subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL,
        faculty_id INTEGER NOT NULL,
        section TEXT NOT NULL,
        semester INTEGER NOT NULL,
        FOREIGN KEY(subject_id) REFERENCES subjects(id),
        FOREIGN KEY(faculty_id) REFERENCES users(id),
        UNIQUE(subject_id, section, semester)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS timetable (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL,
        section TEXT NOT NULL,
        day TEXT NOT NULL,
        period INTEGER NOT NULL,
        room TEXT NOT NULL,
        FOREIGN KEY(subject_id) REFERENCES subjects(id),
        UNIQUE(section, day, period)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('Present', 'Absent')),
        FOREIGN KEY(student_id) REFERENCES users(id),
        FOREIGN KEY(subject_id) REFERENCES subjects(id),
        UNIQUE(student_id, subject_id, date)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        due_date TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(subject_id) REFERENCES subjects(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assignment_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        file_path TEXT NOT NULL,
        submitted_at TEXT NOT NULL,
        FOREIGN KEY(assignment_id) REFERENCES assignments(id),
        FOREIGN KEY(student_id) REFERENCES users(id),
        UNIQUE(assignment_id, student_id)
    )''')
    
    # Default admin
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)",
                   ('admin', generate_password_hash('admin123'), 'admin', 'Admin User'))
    
    conn.commit()
    conn.close()

init_db()

# === TEMPLATES ===

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>My-GITAM Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        :root {
            --primary: #00796B;
            --primary-light: #48A999;
            --beige: #F5F5DC;
            --light: #f9f9f9;
        }
        body {
            background-color: var(--light);
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        .navbar-brand {
            font-weight: 700;
            color: white !important;
        }
        .bg-primary {
            background-color: var(--primary) !important;
        }
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            transition: transform 0.2s;
        }
        .card:hover {
            transform: translateY(-3px);
        }
        .btn-primary {
            background-color: var(--primary);
            border-color: var(--primary);
        }
        .btn-primary:hover {
            background-color: var(--primary-light);
            border-color: var(--primary-light);
        }
        .attendance-good { color: #2e7d32; font-weight: bold; }
        .attendance-poor { color: #c62828; font-weight: bold; }
        .header-bg {
            background: linear-gradient(135deg, var(--primary), #004d40);
            color: white;
            padding: 20px 0;
        }
        .footer {
            margin-top: 40px;
            padding: 20px;
            background: var(--beige);
            text-align: center;
            font-size: 0.9em;
            color: #555;
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .table thead th {
            background-color: #e0f2f1;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-graduation-cap me-2"></i>My-GITAM
            </a>
            <div class="d-flex">
                {% if session.role %}
                <span class="navbar-text me-3">Hello, <strong>{{ session.name }}</strong> ({{ session.role }})</span>
                <a href="/logout" class="btn btn-outline-light btn-sm">Logout</a>
                {% endif %}
            </div>
        </div>
    </nav>

    <div class="container my-4">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for msg in messages %}
                    <div class="alert alert-info alert-dismissible fade show" role="alert">
                        {{ msg }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <div class="footer">
        <p>My-GITAM Portal &copy; 2025 | Gitam School of Technology, Bangalore</p>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

# === ROUTES ===

@app.route('/')
def home():
    if 'role' not in session:
        return redirect('/login')
    if session['role'] == 'student':
        return redirect('/student/dashboard')
    elif session['role'] == 'teacher':
        return redirect('/teacher/dashboard')
    else:
        return redirect('/admin/dashboard')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        un = request.form['username']
        pw = request.form['password']
        conn = sqlite3.connect('instance/school.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (un,))
        u = c.fetchone()
        conn.close()
        if u and check_password_hash(u[2], pw):
            session.update({
                'user_id': u[0],
                'username': u[1],
                'role': u[3],
                'name': u[4],
                'class_section': u[5]
            })
            return redirect('/')
        return render_template_string(BASE_TEMPLATE + '''
        <div class="row justify-content-center">
            <div class="col-md-5">
                <div class="card">
                    <div class="card-body">
                        <h3 class="text-center mb-4"><i class="fas fa-lock"></i> Login</h3>
                        <form method="post">
                            <div class="mb-3">
                                <input type="text" name="username" class="form-control" placeholder="Username" required>
                            </div>
                            <div class="mb-3">
                                <input type="password" name="password" class="form-control" placeholder="Password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Login</button>
                        </form>
                        <div class="text-center mt-3">
                            <small class="text-muted">Default Admin: <code>admin</code> / <code>admin123</code></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        ''')
    return render_template_string(BASE_TEMPLATE + '''
    <div class="row justify-content-center">
        <div class="col-md-5">
            <div class="card">
                <div class="card-body">
                    <h3 class="text-center mb-4"><i class="fas fa-lock"></i> Login</h3>
                    <form method="post">
                        <div class="mb-3">
                            <input type="text" name="username" class="form-control" placeholder="Username" required>
                        </div>
                        <div class="mb-3">
                            <input type="password" name="password" class="form-control" placeholder="Password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                    <div class="text-center mt-3">
                        <small class="text-muted">Default Admin: <code>admin</code> / <code>admin123</code></small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    ''')

# === ADMIN DASHBOARD ===
@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect('/login')
    return render_template_string(BASE_TEMPLATE + '''
    <div class="header-bg rounded mb-4">
        <div class="container">
            <h2><i class="fas fa-user-shield"></i> Admin Dashboard</h2>
            <p>Manage the entire academic ecosystem</p>
        </div>
    </div>

    <div class="dashboard-grid">
        <a href="/admin/users" class="text-decoration-none">
            <div class="card bg-primary text-white">
                <div class="card-body">
                    <h5><i class="fas fa-users me-2"></i> Manage Users</h5>
                    <p>Create teachers & students</p>
                </div>
            </div>
        </a>
        <a href="/admin/subjects" class="text-decoration-none">
            <div class="card bg-success text-white">
                <div class="card-body">
                    <h5><i class="fas fa-book me-2"></i> Subjects</h5>
                    <p>Add & manage courses</p>
                </div>
            </div>
        </a>
        <a href="/admin/assign" class="text-decoration-none">
            <div class="card bg-info text-white">
                <div class="card-body">
                    <h5><i class="fas fa-chalkboard-teacher me-2"></i> Assign Faculty</h5>
                    <p>Link teachers to subjects</p>
                </div>
            </div>
        </a>
        <a href="/admin/timetable" class="text-decoration-none">
            <div class="card bg-warning text-white">
                <div class="card-body">
                    <h5><i class="fas fa-calendar-alt me-2"></i> Timetable</h5>
                    <p>Build weekly schedule</p>
                </div>
            </div>
        </a>
    </div>
    ''')

# === USER MANAGEMENT ===
@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-users"></i> Manage Users</h2>
    <div class="row">
        <div class="col-md-5">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">Add New User</h5>
                </div>
                <div class="card-body">
                    <form method="post" action="/admin/create_user">
                        <div class="mb-3">
                            <input type="text" name="name" class="form-control" placeholder="Full Name" required>
                        </div>
                        <div class="mb-3">
                            <select name="role" class="form-select" required>
                                <option value="">Select Role</option>
                                <option value="teacher">Teacher</option>
                                <option value="student">Student</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <input type="text" name="class_section" class="form-control" placeholder="Class/Section (e.g., 1A)" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Create User</button>
                    </form>
                </div>
            </div>
        </div>
        <div class="col-md-7">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">All Users</h5>
                </div>
                <div class="card-body">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Username</th>
                                <th>Role</th>
                                <th>Class</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for u in users %}
                            <tr>
                                <td>{{ u[4] }}</td>
                                <td>{{ u[1] }}</td>
                                <td>{{ u[3].title() }}</td>
                                <td>{{ u[5] or '-' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    ''', users=users)

@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    if session.get('role') != 'admin':
        return redirect('/login')
    name = request.form['name']
    role = request.form['role']
    cls = request.form['class_section']
    un = name.strip().lower().replace(' ', '') + '@gitam.edu'
    pw = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role, name, class_section) VALUES (?, ?, ?, ?, ?)",
                  (un, generate_password_hash(pw), role, name, cls))
        conn.commit()
        session['flash'] = f"✅ User created! Username: {un}, Password: {pw}"
    except Exception as e:
        session['flash'] = "❌ Error creating user"
    conn.close()
    return redirect('/admin/users')

# === SUBJECTS ===
@app.route('/admin/subjects')
def admin_subjects():
    if session.get('role') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("SELECT * FROM subjects")
    subs = c.fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-book"></i> Manage Subjects</h2>
    <div class="row">
        <div class="col-md-5">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">Add New Subject</h5>
                </div>
                <div class="card-body">
                    <form method="post" action="/admin/create_subject">
                        <div class="mb-3">
                            <input type="text" name="code" class="form-control" placeholder="Subject Code (e.g., CS101)" required>
                        </div>
                        <div class="mb-3">
                            <input type="text" name="name" class="form-control" placeholder="Subject Name" required>
                        </div>
                        <div class="mb-3">
                            <input type="number" name="semester" class="form-control" placeholder="Semester (1-8)" min="1" max="8" required>
                        </div>
                        <div class="mb-3">
                            <input type="text" name="branch" class="form-control" placeholder="Branch (e.g., CSE)" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Add Subject</button>
                    </form>
                </div>
            </div>
        </div>
        <div class="col-md-7">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">All Subjects</h5>
                </div>
                <div class="card-body">
                    <table class t="table table-hover">
                        <thead>
                            <tr>
                                <th>Code</th>
                                <th>Name</th>
                                <th>Sem</th>
                                <th>Branch</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for s in subs %}
                            <tr>
                                <td>{{ s[1] }}</td>
                                <td>{{ s[2] }}</td>
                                <td>{{ s[3] }}</td>
                                <td>{{ s[4] }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    ''', subs=subs)

@app.route('/admin/create_subject', methods=['POST'])
def admin_create_subject():
    if session.get('role') != 'admin':
        return redirect('/login')
    code = request.form['code']
    name = request.form['name']
    sem = request.form['semester']
    branch = request.form['branch']
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO subjects (code, name, semester, branch) VALUES (?, ?, ?, ?)",
                  (code, name, sem, branch))
        conn.commit()
        session['flash'] = "✅ Subject added successfully"
    except:
        session['flash'] = "❌ Error or duplicate code"
    conn.close()
    return redirect('/admin/subjects')

# === FACULTY ASSIGNMENT ===
@app.route('/admin/assign')
def admin_assign():
    if session.get('role') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("SELECT id, code, name FROM subjects")
    subs = c.fetchall()
    c.execute("SELECT id, name FROM users WHERE role='teacher'")
    teachers = c.fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-chalkboard-teacher"></i> Assign Faculty to Subjects</h2>
    <div class="card">
        <div class="card-body">
            <form method="post" action="/admin/do_assign">
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label>Subject</label>
                        <select name="sub_id" class="form-select" required>
                            <option value="">-- Select --</option>
                            {% for s in subs %}
                            <option value="{{ s[0] }}">{{ s[1] }} - {{ s[2] }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label>Faculty</label>
                        <select name="teacher_id" class="form-select" required>
                            <option value="">-- Select --</option>
                            {% for t in teachers %}
                            <option value="{{ t[0] }}">{{ t[1] }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label>Section</label>
                        <input type="text" name="section" class="form-control" placeholder="e.g., 1A" required>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label>Semester</label>
                        <input type="number" name="semester" class="form-control" min="1" max="8" required>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Assign Faculty</button>
            </form>
        </div>
    </div>
    ''', subs=subs, teachers=teachers)

@app.route('/admin/do_assign', methods=['POST'])
def do_assign():
    if session.get('role') != 'admin':
        return redirect('/login')
    sub_id = request.form['sub_id']
    teacher_id = request.form['teacher_id']
    section = request.form['section']
    semester = request.form['semester']
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO faculty_subjects (subject_id, faculty_id, section, semester) VALUES (?, ?, ?, ?)",
                  (sub_id, teacher_id, section, semester))
        conn.commit()
        session['flash'] = "✅ Faculty assigned successfully"
    except:
        session['flash'] = "❌ Assignment failed (maybe duplicate)"
    conn.close()
    return redirect('/admin/assign')

# === TIMETABLE ===
@app.route('/admin/timetable')
def admin_timetable():
    if session.get('role') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("SELECT id, code FROM subjects")
    subs = c.fetchall()
    c.execute("""
        SELECT t.id, s.code, t.section, t.day, t.period, t.room
        FROM timetable t
        JOIN subjects s ON t.subject_id = s.id
    """)
    entries = c.fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-calendar-alt"></i> Build Timetable</h2>
    <div class="row">
        <div class="col-md-6">
            <div class="card">
                <div class="card-body">
                    <form method="post" action="/admin/add_timetable">
                        <div class="mb-3">
                            <input type="text" name="section" class="form-control" placeholder="Section (e.g., 1A)" required>
                        </div>
                        <div class="mb-3">
                            <select name="day" class="form-select" required>
                                <option value="">Select Day</option>
                                {% for day in ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'] %}
                                <option>{{ day }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="mb-3">
                            <select name="period" class="form-select" required>
                                <option value="">Select Period</option>
                                {% for p in range(1, 9) %}
                                <option>Period {{ p }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="mb-3">
                            <select name="sub_id" class="form-select" required>
                                <option value="">Select Subject</option>
                                {% for s in subs %}
                                <option value="{{ s[0] }}">{{ s[1] }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="mb-3">
                            <input type="text" name="room" class="form-control" placeholder="Room (e.g., LH-101)" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Add to Timetable</button>
                    </form>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Current Timetable</h5>
                </div>
                <div class="card-body">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Section</th>
                                <th>Day</th>
                                <th>Period</th>
                                <th>Subject</th>
                                <th>Room</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for e in entries %}
                            <tr>
                                <td>{{ e[2] }}</td>
                                <td>{{ e[3] }}</td>
                                <td>{{ e[4] }}</td>
                                <td>{{ e[1] }}</td>
                                <td>{{ e[5] }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    ''', subs=subs, entries=entries)

@app.route('/admin/add_timetable', methods=['POST'])
def add_timetable():
    if session.get('role') != 'admin':
        return redirect('/login')
    section = request.form['section']
    day = request.form['day']
    period = request.form['period'].replace('Period ', '')
    sub_id = request.form['sub_id']
    room = request.form['room']
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO timetable (subject_id, section, day, period, room) VALUES (?, ?, ?, ?, ?)",
                  (sub_id, section, day, period, room))
        conn.commit()
        session['flash'] = "✅ Timetable entry added"
    except sqlite3.IntegrityError:
        session['flash'] = "❌ Time slot already booked"
    conn.close()
    return redirect('/admin/timetable')

# === ATTENDANCE MODULE (TEACHER) ===
@app.route('/teacher/attendance')
def teacher_attendance():
    if session.get('role') != 'teacher':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("""
        SELECT s.id, s.code, s.name, fs.section
        FROM faculty_subjects fs
        JOIN subjects s ON fs.subject_id = s.id
        WHERE fs.faculty_id = ?
    """, (session['user_id'],))
    subjects = c.fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-check-circle"></i> Mark Attendance</h2>
    <div class="card">
        <div class="card-body">
            <p>Select a subject to mark attendance:</p>
            <div class="list-group">
                {% for subj in subjects %}
                <a href="/teacher/attendance_form?subject_id={{ subj[0] }}" class="list-group-item list-group-item-action">
                    <strong>{{ subj[1] }}</strong> - {{ subj[2] }} (Section: {{ subj[3] }})
                </a>
                {% endfor %}
            </div>
        </div>
    </div>
    ''', subjects=subjects)

@app.route('/teacher/attendance_form')
def teacher_attendance_form():
    if session.get('role') != 'teacher':
        return redirect('/login')
    subject_id = request.args.get('subject_id')
    today = date.today().isoformat()
    
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("""
        SELECT s.code, s.name, fs.section
        FROM subjects s
        JOIN faculty_subjects fs ON s.id = fs.subject_id
        WHERE s.id = ? AND fs.faculty_id = ?
    """, (subject_id, session['user_id']))
    subj = c.fetchone()
    if not subj:
        conn.close()
        return redirect('/teacher/attendance')
    
    c.execute("SELECT id, name FROM users WHERE class_section = ? AND role = 'student'", (subj[2],))
    students = c.fetchall()
    
    # Check if already marked today
    c.execute("SELECT student_id, status FROM attendance WHERE subject_id = ? AND date = ?", (subject_id, today))
    existing = {row[0]: row[1] for row in c.fetchall()}
    conn.close()
    
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-clipboard-check"></i> Mark Attendance: {{ subj[1] }} - {{ subj[2] }}</h2>
    <p class="text-muted">Date: {{ today }} | Section: {{ subj[2] }}</p>
    
    <form method="post" action="/teacher/submit_attendance">
        <input type="hidden" name="subject_id" value="{{ subject_id }}">
        <input type="hidden" name="date" value="{{ today }}">
        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Student</th>
                                <th>Present</th>
                                <th>Absent</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for s in students %}
                            <tr>
                                <td>{{ s[1] }}</td>
                                <td>
                                    <input type="radio" name="status_{{ s[0] }}" value="Present" 
                                        {% if existing.get(s[0]) == 'Present' %}checked{% endif %}>
                                </td>
                                <td>
                                    <input type="radio" name="status_{{ s[0] }}" value="Absent" 
                                        {% if existing.get(s[0]) != 'Present' %}checked{% endif %}>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                <button type="submit" class="btn btn-success mt-3">Save Attendance</button>
            </div>
        </div>
    </form>
    <a href="/teacher/attendance" class="btn btn-outline-secondary mt-3">← Back</a>
    ''', subject_id=subject_id, today=today, subj=subj, students=students, existing=existing)

@app.route('/teacher/submit_attendance', methods=['POST'])
def submit_attendance():
    if session.get('role') != 'teacher':
        return redirect('/login')
    subject_id = request.form['subject_id']
    attendance_date = request.form['date']
    
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("SELECT id, name FROM users WHERE class_section = (SELECT section FROM faculty_subjects WHERE subject_id = ? AND faculty_id = ?)", (subject_id, session['user_id']))
    students = c.fetchall()
    
    for student in students:
        status = request.form.get(f"status_{student[0]}", "Absent")
        try:
            c.execute("INSERT OR REPLACE INTO attendance (student_id, subject_id, date, status) VALUES (?, ?, ?, ?)",
                      (student[0], subject_id, attendance_date, status))
        except:
            pass  # Skip if error
    
    conn.commit()
    conn.close()
    session['flash'] = "✅ Attendance saved for today!"
    return redirect('/teacher/attendance')

# === ASSIGNMENTS (TEACHER) ===
@app.route('/teacher/assignments')
def teacher_assignments():
    if session.get('role') != 'teacher':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("""
        SELECT s.id, s.code, s.name, fs.section
        FROM faculty_subjects fs
        JOIN subjects s ON fs.subject_id = s.id
        WHERE fs.faculty_id = ?
    """, (session['user_id'],))
    subjects = c.fetchall()
    c.execute("""
        SELECT a.id, a.title, a.due_date, s.code
        FROM assignments a
        JOIN subjects s ON a.subject_id = s.id
        WHERE a.subject_id IN ({})
        ORDER BY a.due_date DESC
    """.format(','.join('?' * len(subjects))), [s[0] for s in subjects])
    assignments = c.fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-tasks"></i> Manage Assignments</h2>
    
    <div class="card mb-4">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0">Create New Assignment</h5>
        </div>
        <div class="card-body">
            <form method="post" action="/teacher/create_assignment">
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label>Subject</label>
                        <select name="subject_id" class="form-select" required>
                            {% for s in subjects %}
                            <option value="{{ s[0] }}">{{ s[1] }} - {{ s[2] }} ({{ s[3] }})</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label>Due Date</label>
                        <input type="datetime-local" name="due_date" class="form-control" required>
                    </div>
                </div>
                <div class="mb-3">
                    <label>Title</label>
                    <input type="text" name="title" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label>Description</label>
                    <textarea name="description" class="form-control" rows="3"></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Create Assignment</button>
            </form>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header">
            <h5 class="mb-0">Your Assignments</h5>
        </div>
        <div class="card-body">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Subject</th>
                        <th>Title</th>
                        <th>Due Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for a in assignments %}
                    <tr>
                        <td>{{ a[3] }}</td>
                        <td>{{ a[1] }}</td>
                        <td>{{ a[2] }}</td>
                        <td>
                            <a href="/assignment/{{ a[0] }}/submissions" class="btn btn-sm btn-outline-info">View Submissions</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    ''', subjects=subjects, assignments=assignments)

@app.route('/teacher/create_assignment', methods=['POST'])
def create_assignment():
    if session.get('role') != 'teacher':
        return redirect('/login')
    subject_id = request.form['subject_id']
    title = request.form['title']
    desc = request.form.get('description', '')
    due = request.form['due_date']
    created = datetime.now().isoformat()
    
    # Format due date for SQLite
    if 'T' not in due:
        due += "T23:59"
    
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("INSERT INTO assignments (subject_id, title, description, due_date, created_at) VALUES (?, ?, ?, ?, ?)",
              (subject_id, title, desc, due, created))
    conn.commit()
    conn.close()
    session['flash'] = "✅ Assignment created successfully"
    return redirect('/teacher/assignments')

# === STUDENT DASHBOARD (WITH ATTENDANCE % & ASSIGNMENTS) ===
@app.route('/student/dashboard')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect('/login')
    section = session.get('class_section', 'Unknown')
    
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    
    # Get subjects
    c.execute("""
        SELECT s.id, s.code, s.name, u.name as faculty
        FROM faculty_subjects fs
        JOIN subjects s ON fs.subject_id = s.id
        JOIN users u ON fs.faculty_id = u.id
        WHERE fs.section = ?
    """, (section,))
    subjects = c.fetchall()
    
    # Calculate attendance %
    attendance_data = {}
    for subj in subjects:
        c.execute("SELECT COUNT(*) FROM attendance WHERE subject_id = ? AND student_id = ?", (subj[0], session['user_id']))
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM attendance WHERE subject_id = ? AND student_id = ? AND status = 'Present'", (subj[0], session['user_id']))
        present = c.fetchone()[0]
        perc = round((present / total * 100), 1) if total > 0 else 0
        attendance_data[subj[0]] = perc
    
    # Get timetable
    c.execute("""
        SELECT t.day, t.period, s.code
        FROM timetable t
        JOIN subjects s ON t.subject_id = s.id
        WHERE t.section = ?
        ORDER BY t.day, t.period
    """, (section,))
    tt = {}
    days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
    for day in days:
        tt[day] = {}
        for p in range(1, 9):
            tt[day][p] = "--"
    for row in c.fetchall():
        tt[row[0]][row[1]] = row[2]
    
    # Get assignments
    c.execute("""
        SELECT a.id, a.title, a.due_date, s.code
        FROM assignments a
        JOIN subjects s ON a.subject_id = s.id
        JOIN faculty_subjects fs ON s.id = fs.subject_id
        WHERE fs.section = ?
        ORDER BY a.due_date
    """, (section,))
    assignments = c.fetchall()
    conn.close()
    
    return render_template_string(BASE_TEMPLATE + '''
    <div class="header-bg rounded mb-4">
        <div class="container">
            <h2><i class="fas fa-user-graduate"></i> Student Dashboard</h2>
            <p>Welcome, <strong>{{ session.name }}</strong> | Class: <strong>{{ section }}</strong></p>
        </div>
    </div>

    <!-- Subjects & Attendance -->
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-book"></i> My Subjects (Attendance %)</h5>
        </div>
        <div class="card-body">
            <div class="row">
                {% for s in subjects %}
                <div class="col-md-6 mb-3">
                    <div class="card border-left-primary">
                        <div class="card-body">
                            <h6>{{ s[1] }} - {{ s[2] }}</h6>
                            <p class="mb-1">Faculty: {{ s[3] }}</p>
                            <p class="mb-0">
                                Attendance: 
                                <span class="{% if attendance_data[s[0]] >= 75 %}attendance-good{% else %}attendance-poor{% endif %}">
                                    {{ attendance_data[s[0]] }}%
                                </span>
                            </p>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>

    <!-- Timetable -->
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-calendar"></i> Weekly Timetable</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>Period</th>
                            {% for day in days %}
                            <th>{{ day }}</th>
                            {% endfor %}
                        </tr>
                    </thead>
                    <tbody>
                        {% for p in range(1, 9) %}
                        <tr>
                            <td>Period {{ p }}</td>
                            {% for day in days %}
                            <td>{{ tt[day][p] }}</td>
                            {% endfor %}
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Assignments -->
    <div class="card">
        <div class="card-header">
            <h5 class="mb-0"><i class="fas fa-file-alt"></i> My Assignments</h5>
        </div>
        <div class="card-body">
            {% if assignments %}
            <div class="list-group">
                {% for a in assignments %}
                <a href="/student/assignment/{{ a[0] }}" class="list-group-item list-group-item-action">
                    <div class="d-flex justify-content-between">
                        <strong>{{ a[3] }}: {{ a[1] }}</strong>
                        <small>Due: {{ a[2] }}</small>
                    </div>
                </a>
                {% endfor %}
            </div>
            {% else %}
            <p class="text-muted">No assignments yet.</p>
            {% endif %}
        </div>
    </div>
    ''', section=section, subjects=subjects, attendance_data=attendance_data, tt=tt, days=days, assignments=assignments)

# === STUDENT ASSIGNMENT VIEW & SUBMIT ===
@app.route('/student/assignment/<int:assignment_id>')
def student_assignment(assignment_id):
    if session.get('role') != 'student':
        return redirect('/login')
    conn = sqlite3.connect('instance/school.db')
    c = conn.cursor()
    c.execute("""
        SELECT a.title, a.description, a.due_date, s.code
        FROM assignments a
        JOIN subjects s ON a.subject_id = s.id
        WHERE a.id = ?
    """, (assignment_id,))
    assignment = c.fetchone()
    if not assignment:
        conn.close()
        return redirect('/student/dashboard')
    
    c.execute("SELECT file_path FROM submissions WHERE assignment_id = ? AND student_id = ?", (assignment_id, session['user_id']))
    submission = c.fetchone()
    conn.close()
    
    due_dt = datetime.fromisoformat(assignment[2].replace('Z', '+00:00'))
    is_due = datetime.now() > due_dt
    
    return render_template_string(BASE_TEMPLATE + '''
    <h2><i class="fas fa-file-alt"></i> {{ assignment[3] }}: {{ assignment[0] }}</h2>
    
    <div class="card mb-4">
        <div class="card-body">
            <p>{{ assignment[1] or 'No description' }}</p>
            <p><strong>Due Date:</strong> {{ assignment[2] }}</p>
            {% if is_due %}
            <div class="alert alert-warning">⚠️ Deadline has passed. Submissions may not be accepted.</div>
            {% endif %}
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <h5 class="mb-0">Submission</h5>
        </div>
        <div class="card-body">
            {% if submission %}
            <p><strong>Status:</strong> Submitted</p>
            <a href="/download/{{ submission[0] }}" class="btn btn-success">Download Your File</a>
            {% if not is_due %}
            <form method="post" action="/student/submit_assignment/{{ assignment_id }}" enctype="multipart/form-data" class="mt-3">
                <div class="mb-3">
                    <label>Resubmit File</label>
                    <input type="file" name="file" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-primary">Resubmit</button>
            </form>
            {% endif %}
            {% else %}
            {% if not is_due %}
            <form method="post" action="/student/submit_assignment/{{ assignment_id }}" enctype="multipart/form-data">
                <div class="mb-3">
                    <label>Upload Your Assignment</label>
                    <input type="file" name="file" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-primary">Submit</button>
            </form>
            {% else %}
            <p class="text-danger">❌ Deadline passed. No submission allowed.</p>
            {% endif %}
            {% endif %}
        </div>
    </div>
    <a href="/student/dashboard" class="btn btn-outline-secondary mt-3">← Back to Dashboard</a>
    ''', assignment=assignment, submission=submission, is_due=is_due)

@app.route('/student/submit_assignment/<int:assignment_id>', methods=['POST'])
def submit_assignment(assignment_id):
    if session.get('role') != 'student':
        return redirect('/login')
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_name = f"{session['user_id']}_{assignment_id}_{timestamp}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], save_name))
        
        conn = sqlite3.connect('instance/school.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO submissions (assignment_id, student_id, file_path, submitted_at) VALUES (?, ?, ?, ?)",
                      (assignment_id, session['user_id'], save_name, datetime.now().isoformat()))
        except:
            c.execute("UPDATE submissions SET file_path = ?, submitted_at = ? WHERE assignment_id = ? AND student_id = ?",
                      (save_name, datetime.now().isoformat(), assignment_id, session['user_id']))
        conn.commit()
        conn.close()
        session['flash'] = "✅ Assignment submitted successfully!"
    return redirect(f'/student/assignment/{assignment_id}')

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# Run
if __name__ == '__main__':
    app.run(debug=True)