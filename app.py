
import os
import sqlite3
from datetime import date
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session, g
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "change-this-secret-key"
)

app.config["DATABASE"] = "attendance.db"

CSRFProtect(app)


#DATABASE

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_code TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT,
            department TEXT NOT NULL,
            designation TEXT,
            phone TEXT,
            joining_date TEXT,
            status TEXT DEFAULT 'Active'
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL,
            check_in TEXT,
            check_out TEXT,
            notes TEXT,

            FOREIGN KEY(employee_id)
                REFERENCES employees(id)
                ON DELETE CASCADE,

            UNIQUE(employee_id, attendance_date)
        );
    """)

    db.commit()


@app.before_request
def setup_database():
    init_db()


@app.context_processor
def template_variables():
    return {
        "now_date": date.today().strftime("%d %b %Y"),
        "current_year": date.today().year
    }


#LOGIN REQUIRED

def login_required(view):

    @wraps(view)
    def wrapper(*args, **kwargs):

        if "admin_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapper


# HOME

@app.route("/")
def index():

    if "admin_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ADMIN LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():

    if "admin_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        admin = db.execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,)
        ).fetchone()

        if admin and check_password_hash(
            admin["password_hash"], password
        ):

            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]

            flash("Login successful.", "success")

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


# LOGOUT

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    flash("You have logged out.", "success")

    return redirect(url_for("login"))


# DASHBOARD

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()

    today = date.today().isoformat()

    total = db.execute("""
        SELECT COUNT(*)
        FROM employees
        WHERE status = 'Active'
    """).fetchone()[0]

    rows = db.execute("""
        SELECT status, COUNT(*) AS total
        FROM attendance
        WHERE attendance_date = ?
        GROUP BY status
    """, (today,)).fetchall()

    counts = {
        row["status"]: row["total"]
        for row in rows
    }

    marked = sum(counts.values())

    recent = db.execute("""
        SELECT a.*, e.full_name, e.employee_code,
               e.department
        FROM attendance a
        JOIN employees e ON e.id = a.employee_id
        ORDER BY a.attendance_date DESC, a.id DESC
        LIMIT 7
    """).fetchall()

    return render_template(
        "dashboard.html",
        total=total,
        counts=counts,
        unmarked=max(total - marked, 0),
        recent=recent,
        today=today
    )


# EMPLOYEES

@app.route("/employees")
@login_required
def employees():

    q = request.args.get("q", "").strip()

    db = get_db()

    employees = db.execute("""
        SELECT * FROM employees
        WHERE employee_code LIKE ?
        OR full_name LIKE ?
        OR department LIKE ?
        ORDER BY id DESC
    """, (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()

    return render_template(
        "employees.html",
        employees=employees,
        q=q
    )


# ADD EMPLOYEE

@app.route("/employees/add", methods=["GET", "POST"])
@login_required
def add_employee():

    if request.method == "POST":

        data = (
            request.form.get("employee_code", "").strip(),
            request.form.get("full_name", "").strip(),
            request.form.get("email", "").strip(),
            request.form.get("department", "").strip(),
            request.form.get("designation", "").strip(),
            request.form.get("phone", "").strip(),
            request.form.get("joining_date", "").strip(),
            request.form.get("status", "Active")
        )

        if not data[0] or not data[1] or not data[3]:
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("add_employee"))

        try:
            db = get_db()

            db.execute("""
                INSERT INTO employees (
                    employee_code, full_name, email,
                    department, designation, phone,
                    joining_date, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, data)

            db.commit()

            flash("Employee added successfully.", "success")

            return redirect(url_for("employees"))

        except sqlite3.IntegrityError:
            flash("Employee ID already exists.", "danger")

    return render_template(
        "employee_form.html",
        employee=None,
        page_title="Add Employee"
    )


# EDIT EMPLOYEE

@app.route("/employees/<int:id>/edit",
           methods=["GET", "POST"])
@login_required
def edit_employee(id):

    db = get_db()

    employee = db.execute(
        "SELECT * FROM employees WHERE id = ?",
        (id,)
    ).fetchone()

    if not employee:
        flash("Employee not found.", "danger")
        return redirect(url_for("employees"))

    if request.method == "POST":

        data = (
            request.form.get("employee_code", "").strip(),
            request.form.get("full_name", "").strip(),
            request.form.get("email", "").strip(),
            request.form.get("department", "").strip(),
            request.form.get("designation", "").strip(),
            request.form.get("phone", "").strip(),
            request.form.get("joining_date", "").strip(),
            request.form.get("status", "Active"),
            id
        )

        try:
            db.execute("""
                UPDATE employees SET
                    employee_code = ?,
                    full_name = ?,
                    email = ?,
                    department = ?,
                    designation = ?,
                    phone = ?,
                    joining_date = ?,
                    status = ?
                WHERE id = ?
            """, data)

            db.commit()

            flash("Employee updated successfully.", "success")

            return redirect(url_for("employees"))

        except sqlite3.IntegrityError:
            flash("Employee ID already exists.", "danger")

    return render_template(
        "employee_form.html",
        employee=employee,
        page_title="Edit Employee"
    )


# DELETE EMPLOYEE

@app.route("/employees/<int:id>/delete", methods=["POST"])
@login_required
def delete_employee(id):

    db = get_db()

    db.execute(
        "DELETE FROM employees WHERE id = ?",
        (id,)
    )

    db.commit()

    flash("Employee deleted successfully.", "success")

    return redirect(url_for("employees"))


# ATTENDANCE

@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():

    db = get_db()

    selected_date = request.values.get(
        "attendance_date",
        date.today().isoformat()
    )

    try:
        date.fromisoformat(selected_date)
    except ValueError:
        selected_date = date.today().isoformat()

    if request.method == "POST":

        employees = db.execute("""
            SELECT id FROM employees
            WHERE status = 'Active'
        """).fetchall()

        for employee in employees:

            eid = employee["id"]

            status = request.form.get(
                f"status_{eid}", ""
            )

            if status not in [
                "Present", "Absent", "Half Day", "Leave"
            ]:
                continue

            check_in = request.form.get(
                f"check_in_{eid}", ""
            ) or None

            check_out = request.form.get(
                f"check_out_{eid}", ""
            ) or None

            notes = request.form.get(
                f"notes_{eid}", ""
            ).strip() or None

            if status != "Present":
                check_in = None
                check_out = None

            db.execute("""
                INSERT INTO attendance (
                    employee_id, attendance_date,
                    status, check_in, check_out, notes
                )
                VALUES (?, ?, ?, ?, ?, ?)

                ON CONFLICT(employee_id, attendance_date)
                DO UPDATE SET
                    status = excluded.status,
                    check_in = excluded.check_in,
                    check_out = excluded.check_out,
                    notes = excluded.notes
            """, (
                eid, selected_date, status,
                check_in, check_out, notes
            ))

        db.commit()

        flash("Attendance saved successfully.", "success")

        return redirect(url_for(
            "attendance",
            attendance_date=selected_date
        ))

    employees = db.execute("""
        SELECT e.*,
               a.status AS attendance_status,
               a.check_in,
               a.check_out,
               a.notes

        FROM employees e

        LEFT JOIN attendance a
        ON e.id = a.employee_id
        AND a.attendance_date = ?

        WHERE e.status = 'Active'

        ORDER BY e.full_name
    """, (selected_date,)).fetchall()

    return render_template(
        "attendance.html",
        employees=employees,
        selected_date=selected_date
    )


# REPORTS

@app.route("/reports")
@login_required
def reports():

    month = request.args.get(
        "month",
        date.today().strftime("%Y-%m")
    )

    try:
        date.fromisoformat(month + "-01")
    except ValueError:
        month = date.today().strftime("%Y-%m")

    db = get_db()

    rows = db.execute("""
        SELECT
            e.employee_code,
            e.full_name,
            e.department,

            SUM(CASE WHEN a.status='Present'
                THEN 1 ELSE 0 END) AS present,

            SUM(CASE WHEN a.status='Absent'
                THEN 1 ELSE 0 END) AS absent,

            SUM(CASE WHEN a.status='Half Day'
                THEN 1 ELSE 0 END) AS half_day,

            SUM(CASE WHEN a.status='Leave'
                THEN 1 ELSE 0 END) AS leave_days,

            COUNT(a.id) AS recorded

        FROM employees e

        LEFT JOIN attendance a
        ON e.id = a.employee_id
        AND substr(a.attendance_date, 1, 7) = ?

        GROUP BY e.id
        ORDER BY e.full_name
    """, (month,)).fetchall()

    return render_template(
        "reports.html",
        rows=rows,
        month=month
    )


# CREATE ADMIN

@app.cli.command("create-admin")
def create_admin():

    username = input("Enter admin username: ").strip()
    password = input("Enter admin password: ")

    if not username or len(password) < 8:
        print("Username is required and password must be at least 8 characters.")
        return

    db = get_db()

    try:
        db.execute("""
            INSERT INTO admins (username, password_hash)
            VALUES (?, ?)
        """, (
            username,
            generate_password_hash(password)
        ))

        db.commit()

        print("Admin account created successfully.")

    except sqlite3.IntegrityError:
        print("Username already exists.")

        
if __name__ == "__main__":
    app.run(debug=True)
