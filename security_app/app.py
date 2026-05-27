import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, Account, Log
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secure-hardcoded-fallback-key')

# CRITICAL: Use Railway Internal Private Network Domain here
# Example: postgresql://postgres:password@postgresql.railway.internal:5432/railway
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_PRIVATE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

# Helper function to create standardized audit trails
def log_security_event(event_type, description, status):
    new_log = Log(type=event_type, description=description, date=datetime.now(), status=status)
    db.session.add(new_log)
    db.session.commit()

# Application Initialization Route (Seeds an admin user safely if missing)
@app.before_request
def create_tables():
    db.create_all()
    if not Account.query.filter_by(username="Renz").first():
        admin = Account(username="Renz", is_online=False)
        admin.set_password("SecurePassword123!") # Change on first run
        db.session.add(admin)
        db.session.commit()

# --- ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = Account.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            user.is_online = True
            db.session.commit()
            login_user(user)
            log_security_event('Login', f'User {username} logged in successfully', 'Success')
            return redirect(url_for('dashboard'))
        else:
            # Audit log for failed authentication attempts
            log_security_event('Login', f'Failed login attempt for username: {username}', 'Failed')
            flash('Invalid username or password.', 'error')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Calculate key metrics matching your card updates
    failed_logins = Log.query.filter_by(type='Login', status='Failed').count()
    camera_breaches = Log.query.filter_by(type='Camera', status='Failed').count()
    network_threats = Log.query.filter_by(type='Network', status='Failed').count()
    
    return render_template('dashboard.html', 
                           failed_logins=failed_logins, 
                           camera_breaches=camera_breaches, 
                           network_threats=network_threats)

@app.route('/video_feed')
@login_required
def video_feed():
    """Simulated production access protection check."""
    # If unauthorized parameter signatures or headers match systemic scanners, tag them
    if request.headers.get('X-Scanner-Heuristic'):
        log_security_event('Camera', 'Unauthorized hardware parsing vector detected', 'Failed')
        abort(403)
    
    # Simulate a healthy feed authorization check
    log_security_event('Camera', 'Validated interface container video initialization', 'Success')
    return "Camera Stream Active"

@app.route('/notifications')
@login_required
def notifications():
    logs = Log.query.order_by(Log.date.desc()).all()
    return render_template('notifications.html', logs=logs)

@app.route('/admins')
@login_required
def admins():
    admins_list = Account.query.all()
    return render_template('admins.html', admins=admins_list)

@app.route('/logout')
@login_required
def logout():
    user = Account.query.get(current_user.id)
    if user:
        user.is_online = False
        db.session.commit()
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)