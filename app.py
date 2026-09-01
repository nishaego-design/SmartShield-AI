from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "smartshield_secret_key"


# ================= DATABASE =================

def get_db_connection():
    conn = sqlite3.connect("smartshield.db")
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    conn = get_db_connection()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Analysis history table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            detected_words TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


create_database()


# ================= HOME / DASHBOARD =================

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        name=session["user_name"]
    )


# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return render_template(
                "register.html",
                error="Please fill all fields!"
            )

        conn = get_db_connection()

        try:

            conn.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, password)
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return render_template(
                "register.html",
                error="Email already registered! Please login."
            )

        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ? AND password = ?",
            (email, password)
        ).fetchone()

        conn.close()

        if user:

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid Email or Password!"
        )

    return render_template("login.html")


# ================= ANALYZE =================

@app.route("/analyze", methods=["POST"])
def analyze():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    data = request.get_json()

    if not data:

        return jsonify({
            "success": False,
            "message": "No input received."
        })

    text = data.get("text", "").lower()

    suspicious_words = [

        "urgent",
        "click here",
        "free money",
        "winner",
        "password",
        "verify account",
        "bank account",
        "otp",
        "prize",
        "limited offer",
        "claim now",
        "bit.ly",

        "congratulations",
        "account blocked",
        "send money",
        "pay now",
        "gift card",
        "bitcoin"

    ]

    detected_words = []

    for word in suspicious_words:

        if word in text:
            detected_words.append(word)

    risk_score = min(len(detected_words) * 20, 100)

    if risk_score >= 60:

        risk_level = "HIGH RISK"

    elif risk_score >= 30:

        risk_level = "SUSPICIOUS"

    else:

        risk_level = "LOW RISK"


    # ================= SAVE HISTORY =================

    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO history
        (user_id, message, risk_score, risk_level, detected_words, created_at)

        VALUES (?, ?, ?, ?, ?, ?)
        """,

        (
            session["user_id"],
            text,
            risk_score,
            risk_level,
            ", ".join(detected_words),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()

    conn.close()


    # ================= RETURN RESULT =================

    return jsonify({

        "success": True,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "detected_words": detected_words

    })


# ================= HISTORY =================

@app.route("/history")
def history():

    if "user_id" not in session:

        return redirect(url_for("login"))

    conn = get_db_connection()

    records = conn.execute(
        """
        SELECT *
        FROM history

        WHERE user_id = ?

        ORDER BY id DESC
        """,

        (session["user_id"],)

    ).fetchall()

    conn.close()

    return render_template(
        "history.html",
        records=records,
        name=session["user_name"]
    )


# ================= SAFETY TIPS =================

@app.route("/safety")
def safety():

    if "user_id" not in session:

        return redirect(url_for("login"))

    return render_template(
        "safety.html",
        name=session["user_name"]
    )


# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ================= RUN APPLICATION =================

if __name__ == "__main__":

    app.run(debug=True)