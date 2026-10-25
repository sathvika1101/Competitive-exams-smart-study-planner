from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, os, hashlib, hmac
from functools import wraps
from datetime import date

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-for-your-project")
DB_PATH = os.path.join(os.path.dirname(__file__), "planner.db")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$")
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200000)
        return hmac.compare_digest(check.hex(), digest_hex)
    except (ValueError, TypeError):
        return False

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT,
            target_exam TEXT NOT NULL, target_year TEXT, daily_goal REAL DEFAULT 3,
            password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, description TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            subject_id INTEGER, title TEXT NOT NULL, topic TEXT DEFAULT '',
            task_date TEXT NOT NULL, start_time TEXT DEFAULT '', duration REAL DEFAULT 1,
            status TEXT DEFAULT 'Pending'
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            title TEXT NOT NULL, subject TEXT DEFAULT '', body TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS mock_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            title TEXT NOT NULL, subject TEXT DEFAULT '', test_date TEXT DEFAULT '',
            score REAL, total REAL DEFAULT 100
        );
        """)

init_db()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def current_user():
    with db() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        exam = request.form.get("target_exam", "").strip()
        year = request.form.get("target_year", "").strip()
        goal = request.form.get("daily_goal", "3").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not all([name, email, exam, password]):
            flash("Please fill in all required fields.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            try:
                with db() as con:
                    cur = con.execute("""INSERT INTO users
                    (full_name,email,phone,target_exam,target_year,daily_goal,password_hash)
                    VALUES (?,?,?,?,?,?,?)""",
                    (name,email,phone,exam,year,float(goal or 3),hash_password(password)))
                    uid = cur.lastrowid
                    for subject in ["Quantitative Aptitude", "Reasoning Ability", "English Language", "General Awareness", "Computer Knowledge"]:
                        con.execute("INSERT INTO subjects(user_id,name) VALUES (?,?)", (uid, subject))
                session["user_id"] = uid
                flash("Account created! Your study planner is ready.", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("That email is already registered. Please log in.", "error")
            except ValueError:
                flash("Daily study goal must be a number.", "error")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    today = date.today().isoformat()
    with db() as con:
        subjects = con.execute("""SELECT s.*, COUNT(t.id) total,
            SUM(CASE WHEN t.status='Completed' THEN 1 ELSE 0 END) completed
            FROM subjects s LEFT JOIN tasks t ON t.subject_id=s.id AND t.user_id=s.user_id
            WHERE s.user_id=? GROUP BY s.id ORDER BY s.id""", (user["id"],)).fetchall()
        tasks = con.execute("""SELECT t.*, s.name subject FROM tasks t LEFT JOIN subjects s ON s.id=t.subject_id
            WHERE t.user_id=? AND t.task_date=? ORDER BY t.start_time""", (user["id"],today)).fetchall()
        totals = con.execute("""SELECT COUNT(*) total,
            SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) done FROM tasks WHERE user_id=?""", (user["id"],)).fetchone()
    total = totals["total"] or 0
    done = totals["done"] or 0
    progress = round(done * 100 / total) if total else 0
    return render_template("dashboard.html", user=user, subjects=subjects, tasks=tasks,
                           total_tasks=total, done=done, progress=progress, today=today)

@app.route("/subjects", methods=["GET", "POST"])
@login_required
def subjects():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if name:
            with db() as con:
                con.execute("INSERT INTO subjects(user_id,name,description) VALUES (?,?,?)",
                            (session["user_id"], name, description))
            flash("Subject added.", "success")
        return redirect(url_for("subjects"))
    with db() as con:
        items = con.execute("""SELECT s.*, COUNT(t.id) total,
            SUM(CASE WHEN t.status='Completed' THEN 1 ELSE 0 END) done
            FROM subjects s LEFT JOIN tasks t ON t.subject_id=s.id AND t.user_id=s.user_id
            WHERE s.user_id=? GROUP BY s.id ORDER BY s.id""", (session["user_id"],)).fetchall()
    return render_template("subjects.html", subjects=items, user=current_user())

@app.route("/subjects/delete/<int:sid>", methods=["POST"])
@login_required
def delete_subject(sid):
    with db() as con:
        con.execute("DELETE FROM subjects WHERE id=? AND user_id=?", (sid, session["user_id"]))
        con.execute("UPDATE tasks SET subject_id=NULL WHERE subject_id=? AND user_id=?", (sid, session["user_id"]))
    return redirect(url_for("subjects"))

@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if title:
            with db() as con:
                con.execute("""INSERT INTO tasks(user_id,subject_id,title,topic,task_date,start_time,duration)
                    VALUES (?,?,?,?,?,?,?)""", (
                    session["user_id"], request.form.get("subject_id") or None, title,
                    request.form.get("topic","").strip(), request.form.get("task_date") or date.today().isoformat(),
                    request.form.get("start_time",""), float(request.form.get("duration") or 1)))
            flash("Task added to your plan.", "success")
        return redirect(url_for("tasks"))
    with db() as con:
        subjects = con.execute("SELECT * FROM subjects WHERE user_id=? ORDER BY name", (session["user_id"],)).fetchall()
        items = con.execute("""SELECT t.*,s.name subject FROM tasks t LEFT JOIN subjects s ON t.subject_id=s.id
            WHERE t.user_id=? ORDER BY t.task_date DESC,t.start_time""", (session["user_id"],)).fetchall()
    return render_template("tasks.html", tasks=items, subjects=subjects, user=current_user(), today=date.today().isoformat())

@app.route("/tasks/status/<int:tid>", methods=["POST"])
@login_required
def task_status(tid):
    with db() as con:
        row = con.execute("SELECT status FROM tasks WHERE id=? AND user_id=?", (tid,session["user_id"])).fetchone()
        if row:
            new_status = "Completed" if row["status"] != "Completed" else "Pending"
            con.execute("UPDATE tasks SET status=? WHERE id=? AND user_id=?", (new_status,tid,session["user_id"]))
    return redirect(request.referrer or url_for("tasks"))

@app.route("/tasks/delete/<int:tid>", methods=["POST"])
@login_required
def delete_task(tid):
    with db() as con:
        con.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (tid,session["user_id"]))
    return redirect(url_for("tasks"))

@app.route("/study-plan")
@login_required
def study_plan():
    with db() as con:
        items = con.execute("""SELECT t.*,s.name subject FROM tasks t LEFT JOIN subjects s ON t.subject_id=s.id
            WHERE t.user_id=? ORDER BY t.task_date,t.start_time""", (session["user_id"],)).fetchall()
    return render_template("study_plan.html", tasks=items, user=current_user())

@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if title:
            with db() as con:
                con.execute("INSERT INTO notes(user_id,title,subject,body) VALUES (?,?,?,?)",
                            (session["user_id"],title,request.form.get("subject","").strip(),request.form.get("body","").strip()))
        return redirect(url_for("notes"))
    with db() as con:
        items = con.execute("SELECT * FROM notes WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    return render_template("notes.html", notes=items, user=current_user())

@app.route("/notes/delete/<int:nid>", methods=["POST"])
@login_required
def delete_note(nid):
    with db() as con:
        con.execute("DELETE FROM notes WHERE id=? AND user_id=?", (nid,session["user_id"]))
    return redirect(url_for("notes"))

@app.route("/mock-tests", methods=["GET", "POST"])
@login_required
def mock_tests():
    if request.method == "POST":
        title = request.form.get("title","").strip()
        if title:
            score = request.form.get("score","").strip()
            with db() as con:
                con.execute("INSERT INTO mock_tests(user_id,title,subject,test_date,score,total) VALUES (?,?,?,?,?,?)",
                    (session["user_id"],title,request.form.get("subject","").strip(),
                     request.form.get("test_date",""),float(score) if score else None,
                     float(request.form.get("total") or 100)))
        return redirect(url_for("mock_tests"))
    with db() as con:
        tests = con.execute("SELECT * FROM mock_tests WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    return render_template("mock_tests.html", tests=tests, user=current_user(), today=date.today().isoformat())

@app.route("/progress")
@login_required
def progress():
    with db() as con:
        subjects = con.execute("""SELECT s.name, COUNT(t.id) total,
            SUM(CASE WHEN t.status='Completed' THEN 1 ELSE 0 END) done
            FROM subjects s LEFT JOIN tasks t ON t.subject_id=s.id AND t.user_id=s.user_id
            WHERE s.user_id=? GROUP BY s.id""", (session["user_id"],)).fetchall()
        total = con.execute("SELECT COUNT(*) total FROM tasks WHERE user_id=?", (session["user_id"],)).fetchone()["total"]
        done = con.execute("SELECT COUNT(*) total FROM tasks WHERE user_id=? AND status='Completed'", (session["user_id"],)).fetchone()["total"]
    return render_template("progress.html", subjects=subjects, user=current_user(), total=total, done=done,
                           progress=round(done*100/total) if total else 0)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = current_user()
    if request.method == "POST":
        with db() as con:
            con.execute("""UPDATE users SET full_name=?, phone=?, target_exam=?, target_year=?, daily_goal=?
                WHERE id=?""", (request.form.get("full_name","").strip(),request.form.get("phone","").strip(),
                request.form.get("target_exam","").strip(),request.form.get("target_year","").strip(),
                float(request.form.get("daily_goal") or 3),session["user_id"]))
        flash("Profile updated.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", user=user)

if __name__ == "__main__":
    app.run(debug=True)
