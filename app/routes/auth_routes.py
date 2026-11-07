from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db
from app.models.user import User
from app.models.scan import AuditLog
from app.utils.validators import validate_email_address, validate_password_strength

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation
        if not username or len(username) < 3 or len(username) > 50:
            flash("Username must be between 3 and 50 characters.", "danger")
            return render_template("register.html", username=username, email=email)

        if not validate_email_address(email):
            flash("Please provide a valid email address.", "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email)

        valid_pw, pw_err = validate_password_strength(password)
        if not valid_pw:
            flash(pw_err, "danger")
            return render_template("register.html", username=username, email=email)

        # Check existing user
        if User.query.filter_by(username=username).first():
            flash("Username already taken. Please choose another.", "danger")
            return render_template("register.html", username=username, email=email)

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists. Please log in.", "danger")
            return render_template("register.html", username=username, email=email)

        # Create user
        try:
            new_user = User(username=username, email=email, role="user")
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.flush()

            # Audit log
            audit = AuditLog(
                user_id=new_user.id,
                action="USER_REGISTER",
                details=f"New user registered: {username}",
                ip_address=request.remote_addr,
            )
            db.session.add(audit)
            db.session.commit()

            flash("Registration successful! You may now log in.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Registration failed: {str(e)}", "danger")

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("login.html")

        # Support login by username or email
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash("Your account has been deactivated. Please contact support.", "danger")
                return render_template("login.html")

            login_user(user, remember=remember)

            # Audit log
            try:
                audit = AuditLog(
                    user_id=user.id,
                    action="USER_LOGIN",
                    details="Successful authentication",
                    ip_address=request.remote_addr,
                )
                db.session.add(audit)
                db.session.commit()
            except Exception:
                db.session.rollback()

            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.dashboard"))

        flash("Invalid username/email or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    try:
        audit = AuditLog(
            user_id=current_user.id,
            action="USER_LOGOUT",
            details="User logged out",
            ip_address=request.remote_addr,
        )
        db.session.add(audit)
        db.session.commit()
    except Exception:
        db.session.rollback()

    logout_user()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("dashboard.index"))
