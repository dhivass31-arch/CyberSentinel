from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device = db.Column(db.String(100), nullable=False)
    event = db.Column(db.String(200), nullable=False)
    source_ip = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(30), nullable=False)


def create_default_data(app):
    with app.app_context():

        db.create_all()

        # Create default admin user
        if User.query.filter_by(username="admin").first() is None:
            admin = User(
                username="admin",
                password_hash=generate_password_hash("Cyber@12345")
            )

            db.session.add(admin)

        # Add demo security events only if database is empty
        if SecurityEvent.query.count() == 0:

            events = [
                SecurityEvent(
                    device="Kali-Lab",
                    event="SSH Login Attempt",
                    source_ip="10.0.2.15",
                    severity="Medium",
                    time="10:30:21"
                ),
                SecurityEvent(
                    device="Kali-Lab",
                    event="Multiple Failed Login Attempts",
                    source_ip="10.0.2.15",
                    severity="High",
                    time="10:32:45"
                ),
                SecurityEvent(
                    device="Windows-PC",
                    event="Port Scan Detected",
                    source_ip="192.168.1.20",
                    severity="High",
                    time="10:35:12"
                )
            ]

            db.session.add_all(events)

        db.session.commit()