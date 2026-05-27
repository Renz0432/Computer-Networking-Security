import os
import cv2
import numpy as np
import time
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Global variable to hold the active camera index
# 0 is usually the built-in webcam. 1 or 2 is typically Iriun/External webcams.
CURRENT_CAMERA_INDEX = 0

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secure-hardcoded-fallback-key')

# Connection variables reading from dynamic environments
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_PRIVATE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS (Defined directly here to prevent import errors) ---

class Account(UserMixin, db.Model):
    __tablename__ = 'account'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_online = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Log(db.Model):
    __tablename__ = 'log'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)        
    description = db.Column(db.String(255), nullable=False) 
    date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)      
    ip_address = db.Column(db.String(50), nullable=True)   # Explicitly matched definition

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

# Helper function to create standardized audit trails
def log_security_event(event_type, description, status):
    user_ip = request.remote_addr if request else "System"
    new_log = Log(
        type=event_type, 
        description=description, 
        date=datetime.now(), 
        status=status,
        ip_address=user_ip
    )
    db.session.add(new_log)
    db.session.commit()

# Clean initialization: Creates empty tables if missing
with app.app_context():
    db.create_all()

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
            log_security_event('Login', f'Failed login attempt for username: {username}', 'Failed')
            flash('Invalid username or password.', 'error')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    failed_logins = Log.query.filter_by(type='Login', status='Failed').count()
    camera_breaches = Log.query.filter_by(type='Camera', status='Failed').count()
    network_threats = Log.query.filter_by(type='Network', status='Failed').count()
    
    return render_template('dashboard.html', 
                           failed_logins=failed_logins, 
                           camera_breaches=camera_breaches, 
                           network_threats=network_threats)

@app.route('/change_camera', methods=['POST'])
@login_required
def change_camera():
    global CURRENT_CAMERA_INDEX
    camera_choice = request.form.get('camera_source')
    if camera_choice == 'iriun':
        CURRENT_CAMERA_INDEX = 1  
        log_security_event('Camera', 'Switched feed profile to Iriun Virtual Camera', 'Success')
    else:
        CURRENT_CAMERA_INDEX = 0  
        log_security_event('Camera', 'Switched feed profile to Integrated Webcam', 'Success')
    return redirect(url_for('dashboard'))

def generate_live_frames():
    global CURRENT_CAMERA_INDEX
    
    # Try opening the physical device capture engine
    camera = cv2.VideoCapture(CURRENT_CAMERA_INDEX)
    
    # Check if the hardware camera actually exists
    if not camera.isOpened():
        print(f"⚠️ Camera index {CURRENT_CAMERA_INDEX} not found. Launching cloud interface simulation...")
        camera.release()
        
        # SIMULATION LOOP: Generates an animated matrix screen for cloud runtimes
        frame_count = 0
        while True:
            # Create a dark slate dashboard background (360 height, 640 width, 3 color channels)
            img = np.zeros((360, 640, 3), dtype=np.uint8)
            img[:] = (24, 28, 20)  # Dark charcoal slate fill
            
            # Draw a subtle high-tech scanning grid matrix
            for x in range(0, 640, 40):
                cv2.line(img, (x, 0), (x, 360), (35, 45, 30), 1)
            for y in range(0, 360, 40):
                cv2.line(img, (0, y), (640, y), (35, 45, 30), 1)
                
            # Animated sweeping scanner line tracking down the screen
            scan_y = (frame_count * 3) % 360
            cv2.line(img, (0, scan_y), (640, scan_y), (74, 180, 100), 2)
            
            # FIX: Swapped out the incorrect monospace font constant names
            status_text = f"STREAM CHANNEL ACTIVE [INDEX {CURRENT_CAMERA_INDEX}]"
            cv2.putText(img, "🔴 LIVE SECURE FEED", (30, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (80, 80, 240), 2)
            cv2.putText(img, status_text, (30, 85), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (180, 180, 180), 1)
            cv2.putText(img, f"FPS: 24.0 // SYS_TIME: {time.strftime('%H:%M:%S')}", (30, 320), cv2.FONT_HERSHEY_PLAIN, 0.9, (120, 120, 120), 1)
            
            # Encode frame to JPEG
            ret, buffer = cv2.imencode('.jpg', img)
            frame_bytes = buffer.tobytes()
            
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            time.sleep(0.04) # Lock frame intervals to roughly 24FPS
            frame_count += 1
    else:
        # HARDWARE LOOP: Runs if the code is executed locally on your laptop
        while True:
            success, frame = camera.read()
            if not success:
                break
            else:
                # Resize physical camera image to fit your dashboard layout cleanly
                frame = cv2.resize(frame, (640, 360))
                ret, buffer = cv2.imencode('.jpg', frame)
                frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        camera.release()

@app.route('/video_feed')
@login_required
def video_feed():
    from flask import Response
    return Response(generate_live_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')
    
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
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
