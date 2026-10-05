# ==========================================
# CYBERSENTINEL
# LIVE ENDPOINT SECURITY MONITORING SYSTEM
# ==========================================

from flask import (
    Flask,
    jsonify,
    render_template,
    redirect,
    url_for,
    request,
    flash
)

from flask_cors import CORS

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user
)

from werkzeug.security import check_password_hash

from database import (
    db,
    User,
    SecurityEvent,
    create_default_data
)

from detection import detect_threat

from datetime import datetime, timedelta

import os


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(__name__)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "cybersentinel-development-secret"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///cybersentinel.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# ==========================================
# ENABLE CORS
# ==========================================

CORS(app)


# ==========================================
# INITIALIZE DATABASE
# ==========================================

db.init_app(app)


# ==========================================
# LOGIN MANAGER
# ==========================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = (
    "Please login to access the dashboard."
)


# ==========================================
# LOGIN USER CLASS
# ==========================================

class LoginUser(UserMixin):

    def __init__(self, user):

        self.id = user.id
        self.username = user.username


# ==========================================
# LOAD USER
# ==========================================

@login_manager.user_loader
def load_user(user_id):

    try:

        user = db.session.get(
            User,
            int(user_id)
        )

        if user:

            return LoginUser(user)

    except Exception:

        return None

    return None


# ==========================================
# HOME
# ==========================================

@app.route("/")
def index():

    return redirect(
        url_for("dashboard")
    )


# ==========================================
# LOGIN
# ==========================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            username=username
        ).first()

        if user:

            if check_password_hash(
                user.password_hash,
                password
            ):

                login_user(
                    LoginUser(user)
                )

                return redirect(
                    url_for("dashboard")
                )

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "index.html"
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("login")
    )


# ==========================================
# SYSTEM STATUS API
# ==========================================

@app.route("/api/status")
@login_required
def status():

    event_count = SecurityEvent.query.count()

    high_count = SecurityEvent.query.filter_by(
        severity="High"
    ).count()

    medium_count = SecurityEvent.query.filter_by(
        severity="Medium"
    ).count()

    low_count = SecurityEvent.query.filter_by(
        severity="Low"
    ).count()

    all_events = SecurityEvent.query.all()

    devices = set()

    for event in all_events:

        devices.add(event.device)

    return jsonify({

        "status": "online",

        "system": "CyberSentinel",

        "total_events": event_count,

        "monitored_devices": len(devices),

        "high_threats": high_count,

        "medium_threats": medium_count,

        "low_events": low_count,

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    })


# ==========================================
# GET SECURITY EVENTS
# ==========================================

@app.route(
    "/api/events",
    methods=["GET"]
)
@login_required
def events():

    all_events = SecurityEvent.query.order_by(
        SecurityEvent.id.desc()
    ).all()

    result = []

    for event in all_events:

        result.append({

            "id": event.id,

            "device": event.device,

            "event": event.event,

            "source_ip": event.source_ip,

            "severity": event.severity,

            "time": event.time

        })

    return jsonify(result)


# ==========================================
# RECEIVE SECURITY EVENT
# ==========================================

@app.route(
    "/api/events",
    methods=["POST"]
)
def add_event():

    # ======================================
    # API KEY AUTHENTICATION
    # ======================================

    api_key = request.headers.get(
        "X-API-Key"
    )

    expected_api_key = os.environ.get(
        "CYBERSENTINEL_API_KEY",
        "CYBERSENTINEL-DEMO-KEY-2026"
    )

    if api_key != expected_api_key:

        return jsonify({

            "error": "Unauthorized",

            "message":
                "Invalid API key"

        }), 401


    # ======================================
    # READ JSON
    # ======================================

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({

            "error": "Invalid JSON",

            "message":
                "JSON request body is required"

        }), 400


    # ======================================
    # EXTRACT DATA
    # ======================================

    device = data.get(
        "device"
    )

    event = data.get(
        "event"
    )

    source_ip = data.get(
        "source_ip"
    )


    # ======================================
    # VALIDATION
    # ======================================

    if not device:

        return jsonify({
            "error": "Device is required"
        }), 400

    if not event:

        return jsonify({
            "error": "Event is required"
        }), 400

    if not source_ip:

        return jsonify({
            "error": "Source IP is required"
        }), 400


    # ======================================
    # BRUTE FORCE WINDOW
    # ======================================

    current_time = datetime.now()

    five_minutes_ago = (
        current_time -
        timedelta(minutes=5)
    )


    # ======================================
    # COUNT RECENT FAILED LOGINS
    # FROM SAME SOURCE IP
    # ======================================

    recent_events = SecurityEvent.query.filter_by(
        source_ip=source_ip
    ).order_by(
        SecurityEvent.id.desc()
    ).all()


    recent_failed_attempts = 0


    for previous_event in recent_events:

        try:

            event_time = datetime.strptime(
                previous_event.time,
                "%Y-%m-%d %H:%M:%S"
            )

        except ValueError:

            # Older demo events may only
            # contain HH:MM:SS.
            continue


        if event_time < five_minutes_ago:

            break


        previous_event_name = (
            previous_event.event
            .lower()
        )


        if (
            "failed login"
            in previous_event_name
            or
            "login attempt"
            in previous_event_name
            or
            "authentication failure"
            in previous_event_name
            or
            "authentication failed"
            in previous_event_name
        ):

            recent_failed_attempts += 1


    # ======================================
    # INCLUDE CURRENT EVENT
    # ======================================

    current_event = event.lower()

    if (
        "failed login"
        in current_event
        or
        "login attempt"
        in current_event
        or
        "authentication failure"
        in current_event
        or
        "authentication failed"
        in current_event
    ):

        recent_failed_attempts += 1


    # ======================================
    # DETECTION ENGINE
    # ======================================

    detection = detect_threat(

        event_name=event,

        source_ip=source_ip,

        recent_failed_attempts=
            recent_failed_attempts
    )


    # ======================================
    # AUTOMATIC SEVERITY
    # ======================================

    severity = detection[
        "severity"
    ]

    detection_reason = detection[
        "reason"
    ]

    detection_rule = detection[
        "rule"
    ]


    # ======================================
    # CREATE DATABASE EVENT
    # ======================================

    new_event = SecurityEvent(

        device=device,

        event=event,

        source_ip=source_ip,

        severity=severity,

        time=current_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    )


    # ======================================
    # SAVE TO DATABASE
    # ======================================

    db.session.add(
        new_event
    )

    db.session.commit()


    # ======================================
    # SECURITY LOG
    # ======================================

    print()
    print(
        "------------------------------------------"
    )

    print(
        "[SECURITY EVENT DETECTED]"
    )

    print(
        "Device              :",
        device
    )

    print(
        "Event               :",
        event
    )

    print(
        "Source IP           :",
        source_ip
    )

    print(
        "Recent Failed Login :",
        recent_failed_attempts
    )

    print(
        "Severity             :",
        severity
    )

    print(
        "Detection Rule       :",
        detection_rule
    )

    print(
        "Detection Reason     :",
        detection_reason
    )

    print(
        "------------------------------------------"
    )


    # ======================================
    # API RESPONSE
    # ======================================

    return jsonify({

        "success": True,

        "message":
            "Security event analyzed and stored",

        "event_id":
            new_event.id,

        "device":
            device,

        "event":
            event,

        "source_ip":
            source_ip,

        "severity":
            severity,

        "recent_failed_attempts":
            recent_failed_attempts,

        "detection_rule":
            detection_rule,

        "detection_reason":
            detection_reason,

        "timestamp":
            new_event.time

    }), 201


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

with app.app_context():

    create_default_data(app)


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    print()

    print(
        "=========================================="
    )

    print(
        "       CYBERSENTINEL SECURITY SYSTEM"
    )

    print(
        "=========================================="
    )

    print(
        "[+] Detection Engine : ACTIVE"
    )

    print(
        "[+] Brute Force      : ACTIVE"
    )

    print(
        "[+] Database         : CONNECTED"
    )

    print(
        "[+] REST API         : ACTIVE"
    )

    print(
        "[+] Dashboard        : ACTIVE"
    )

    print(
        "[+] Server           : 0.0.0.0:5000"
    )

    print(
        "=========================================="
    )

    print()

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )