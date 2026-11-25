"""
app.py
------
SecureBank-AI : an INTENTIONALLY VULNERABLE web app for a Web App Pentesting
course project. The twist is an AI chatbot that acts as a new input channel
into classic web vulnerabilities.

Run locally only:
    pip install -r requirements.txt
    python database.py        # create + seed the DB
    python app.py             # start the vulnerable app
    SECURE_MODE=1 python app.py   # start the PATCHED app (before/after demo)

Then open http://127.0.0.1:5000
"""

import os
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, jsonify,
)
from markupsafe import Markup
from database import get_db, init_db, DB_PATH
import chatbot

app = Flask(__name__)
app.secret_key = "lab-insecure-key"  # fine for a local lab
SECURE_MODE = os.environ.get("SECURE_MODE", "0") == "1"


@app.context_processor
def inject_mode():
    return {"secure_mode": SECURE_MODE}


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        # Parameterized here so the LOGIN is not the vulnerable part -- the
        # project focuses on the chatbot channel.
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()
        if row:
            session["user_id"] = row["id"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# APP PAGES
# ---------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    conn = get_db()
    txns = conn.execute(
        "SELECT amount, note FROM transactions WHERE user_id = ?", (user["id"],)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, txns=txns)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        bio = request.form.get("bio", "")
        conn = get_db()
        conn.execute(
            "UPDATE users SET full_name = ?, bio = ? WHERE id = ?",
            (full_name, bio, user["id"]),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("profile"))

    # [VULN #3 - Stored XSS | OWASP A03 | LLM02]
    # In vulnerable mode the bio is marked safe and rendered without escaping.
    safe_bio = Markup(user["bio"]) if not SECURE_MODE else user["bio"]
    return render_template("profile.html", user=user, safe_bio=safe_bio)


# ---------------------------------------------------------------------------
# CHATBOT API
# ---------------------------------------------------------------------------
@app.route("/api/chat", methods=["POST"])
def chat():
    user = current_user()
    if not user:
        return jsonify({"error": "not logged in"}), 401
    message = request.json.get("message", "")
    reply, allow_html = chatbot.run_agent(message, user)
    return jsonify({"reply": reply, "allow_html": allow_html})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    mode = "SECURE (patched)" if SECURE_MODE else "VULNERABLE"
    print("=" * 60)
    print(f"  SecureBank-AI  ::  running in {mode} mode")
    print("  http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
