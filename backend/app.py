from flask import Flask, render_template, request, redirect, url_for, flash, send_file, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from functools import wraps
import uuid
import csv
import io
from flask_migrate import Migrate
import click

# Default admin credentials - Change these for production use
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_PASSWORD = 'admin123'
DEFAULT_ADMIN_EMAIL = 'admin@skillswap.com'

app = Flask(__name__)
# Use environment variable for secret key, with a fallback for development
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-development-only')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skillswap.db'  # Using SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Add these constants near the top of the file
UPLOAD_FOLDER = 'uploads/verification'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    skills = db.relationship('Skill', backref='user', lazy=True)
    verification_requests = db.relationship('VerificationRequest', backref='user', lazy=True)

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(50), nullable=False, default='graduation-cap')
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class VerificationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill_id = db.Column(db.Integer, db.ForeignKey('skill.id'), nullable=True)
    document_filename = db.Column(db.String(255), nullable=False)
    document_path = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AdminActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 addresses can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    admin = db.relationship('User', backref='admin_actions', foreign_keys=[admin_id])

class VerificationFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('verification_request.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    request = db.relationship('VerificationRequest', backref='feedback', foreign_keys=[request_id])
    admin = db.relationship('User', backref='admin_feedback', foreign_keys=[admin_id])

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='activities', foreign_keys=[user_id])

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    data_type = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy='dynamic'))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_messages', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} to {self.recipient_id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Sample Categories
CATEGORIES = [
    {'name': 'Programming', 'icon': 'code', 'count': 15},
    {'name': 'Design', 'icon': 'palette', 'count': 10},
    {'name': 'Languages', 'icon': 'language', 'count': 8},
    {'name': 'Music', 'icon': 'music', 'count': 12},
    {'name': 'Cooking', 'icon': 'utensils', 'count': 9},
    {'name': 'Photography', 'icon': 'camera', 'count': 7},
    {'name': 'Fitness', 'icon': 'dumbbell', 'count': 11},
    {'name': 'Technology', 'icon': 'laptop', 'count': 14},
    {'name': 'Art', 'icon': 'paint-brush', 'count': 6},
    {'name': 'Finance', 'icon': 'chart-line', 'count': 5}
]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function for admin decorator
def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return decorated_view

def log_admin_action(action, details=None):
    """Log an action performed by an admin user."""
    if current_user.is_authenticated and current_user.is_admin:
        log_entry = AdminActionLog(
            admin_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None
        )
        db.session.add(log_entry)
        db.session.commit()

def log_user_activity(user_id, description, category):
    """Log user activity for audit trails."""
    activity = UserActivity(
        user_id=user_id,
        description=description,
        category=category,
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

def get_system_setting(key, default=None):
    """Get a system setting by key with an optional default value."""
    setting = SystemSettings.query.filter_by(key=key).first()
    if not setting:
        return default
    
    if setting.data_type == 'boolean':
        return setting.value.lower() in ('true', '1', 'yes')
    elif setting.data_type == 'integer':
        return int(setting.value) if setting.value else 0
    elif setting.data_type == 'float':
        return float(setting.value) if setting.value else 0.0
    elif setting.data_type == 'json':
        import json
        return json.loads(setting.value) if setting.value else {}
    else:  # string or text
        return setting.value

def set_system_setting(key, value, data_type='string', description=None):
    """Set a system setting, creating it if it doesn't exist."""
    setting = SystemSettings.query.filter_by(key=key).first()
    
    if not setting:
        setting = SystemSettings(key=key, data_type=data_type, description=description)
    
    if data_type == 'json':
        import json
        setting.value = json.dumps(value)
    else:
        setting.value = str(value)
    
    db.session.add(setting)
    db.session.commit()
    return setting

# Routes
@app.route('/')
def index():
    total_users = User.query.count()
    total_skills = Skill.query.count()
    total_exchanges = 25  # Placeholder for now
    featured_skills = Skill.query.order_by(Skill.created_at.desc()).limit(6).all()
    return render_template('index.html', 
                         total_users=total_users,
                         total_skills=total_skills,
                         total_exchanges=total_exchanges,
                         featured_skills=featured_skills,
                         categories=CATEGORIES)

@app.route('/users')
def users_list():
    # Exclude admin users from public listing
    users = User.query.filter_by(is_admin=False).all()
    return render_template('users_list.html', users=users)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)

@app.route('/skills')
def skills_list():
    skills = Skill.query.all()
    return render_template('skills_list.html', skills=skills)

@app.route('/skill/<int:skill_id>')
def skill_detail(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    return render_template('skill_detail.html', skill=skill)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        # Check if user already exists
        user_by_email = User.query.filter_by(email=email).first()
        user_by_username = User.query.filter_by(username=username).first()
        
        if user_by_email:
            flash('Email address already exists.', 'danger')
            return redirect(url_for('register'))
            
        if user_by_username:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        # Add user to database
        db.session.add(new_user)
        db.session.commit()
        
        # Log in the new user
        login_user(new_user)
        
        flash('Registration successful!', 'success')
        return redirect(url_for('index'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_id = request.form.get('login_id')  # This will be either email or username
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Try to find user by email or username
        user = User.query.filter(
            db.or_(
                User.email == login_id,
                User.username == login_id
            )
        ).first()
        
        # Check if user exists and password is correct
        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('login'))
            
        # If user exists and password is correct, log them in
        login_user(user, remember=remember)
        
        # Log user activity
        log_user_activity(
            user.id,
            'User logged in',
            'authentication'
        )
        
        flash('Login successful!', 'success')
        
        # Redirect to the page they were trying to access or homepage
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Log user activity before logout
    if current_user.is_authenticated:
        log_user_activity(
            current_user.id,
            'User logged out',
            'authentication'
        )
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/add_skill', methods=['GET', 'POST'])
@login_required
def add_skill():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        icon = next((cat['icon'] for cat in CATEGORIES if cat['name'] == category), 'graduation-cap')
        
        # Validate inputs
        if not name or not description or not category:
            flash('All fields are required', 'danger')
            return redirect(url_for('add_skill'))
        
        # Create new skill
        new_skill = Skill(
            name=name,
            description=description,
            category=category,
            icon=icon,
            teacher_id=current_user.id
        )
        
        # Add to database
        db.session.add(new_skill)
        db.session.commit()
        
        flash('Skill added successfully!', 'success')
        return redirect(url_for('skills_list'))
        
    return render_template('add_skill.html', categories=[cat['name'] for cat in CATEGORIES])

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Check if username already exists (if it was changed)
        if username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists.', 'danger')
                return redirect(url_for('edit_profile'))
        
        # Check if email already exists (if it was changed)
        if email != current_user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already exists.', 'danger')
                return redirect(url_for('edit_profile'))
        
        # Update username and email
        current_user.username = username
        current_user.email = email
        
        # Update password if provided
        if current_password and new_password and confirm_password:
            # Verify current password
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('edit_profile'))
            
            # Check if new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('edit_profile'))
            
            # Update password
            current_user.password_hash = generate_password_hash(new_password)
            flash('Password updated successfully.', 'success')
        
        # Save changes
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    return render_template('edit_profile.html')

@app.route('/edit_skill/<int:skill_id>', methods=['GET', 'POST'])
@login_required
def edit_skill(skill_id):
    # Get the skill
    skill = Skill.query.get_or_404(skill_id)
    
    # Check if the current user is the owner of the skill
    if skill.teacher_id != current_user.id:
        flash('You do not have permission to edit this skill.', 'danger')
        return redirect(url_for('skills_list'))
    
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        
        # Validate inputs
        if not name or not description or not category:
            flash('All fields are required', 'danger')
            return redirect(url_for('edit_skill', skill_id=skill_id))
        
        # Update the skill
        skill.name = name
        skill.description = description
        skill.category = category
        skill.icon = next((cat['icon'] for cat in CATEGORIES if cat['name'] == category), 'graduation-cap')
        
        # Save changes
        db.session.commit()
        
        flash('Skill updated successfully!', 'success')
        return redirect(url_for('user_profile', user_id=current_user.id))
    
    return render_template('edit_skill.html', skill=skill, categories=[cat['name'] for cat in CATEGORIES])

@app.route('/delete_skill/<int:skill_id>', methods=['POST'])
@login_required
def delete_skill(skill_id):
    # Get the skill
    skill = Skill.query.get_or_404(skill_id)
    
    # Check if the current user is the owner of the skill
    if skill.teacher_id != current_user.id:
        flash('You do not have permission to delete this skill.', 'danger')
        return redirect(url_for('skills_list'))
    
    # Delete the skill
    db.session.delete(skill)
    db.session.commit()
    
    flash('Skill deleted successfully!', 'success')
    return redirect(url_for('user_profile', user_id=current_user.id))

@app.route('/manage_skills')
@login_required
def manage_skills():
    # Get all skills for the current user
    skills = Skill.query.filter_by(teacher_id=current_user.id).all()
    return render_template('manage_skills.html', skills=skills)

@app.route('/verification')
@login_required
def verification():
    verification_requests = VerificationRequest.query.filter_by(user_id=current_user.id).order_by(VerificationRequest.created_at.desc()).all()
    return render_template('verification.html', verification_requests=verification_requests)

@app.route('/verification/upload', methods=['POST'])
@login_required
def upload_verification():
    if 'document' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('verification'))
    
    file = request.files['document']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('verification'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Create a unique filename
        unique_filename = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{filename}"
        
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Create verification request
        verification_request = VerificationRequest(
            user_id=current_user.id,
            document_filename=filename,
            document_path=file_path,
            status='pending'
        )
        db.session.add(verification_request)
        db.session.commit()
        
        flash('Verification document uploaded successfully', 'success')
    else:
        flash('Invalid file type', 'error')
    
    return redirect(url_for('verification'))

def create_sample_data():
    # Create admin user
    admin_exists = User.query.filter_by(username=DEFAULT_ADMIN_USERNAME).first()
    if not admin_exists:
        admin = User(
            username=DEFAULT_ADMIN_USERNAME,
            email=DEFAULT_ADMIN_EMAIL,
            password_hash=generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            is_admin=True,
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user created: {DEFAULT_ADMIN_USERNAME}")
        
    # Create sample users
    if User.query.count() == 1:  # Only admin exists
        users = [
            {'username': 'john_doe', 'email': 'john@example.com', 'password': 'password123'},
            {'username': 'jane_smith', 'email': 'jane@example.com', 'password': 'password123'}
        ]
        for user_data in users:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=generate_password_hash(user_data['password'])
            )
            db.session.add(user)
        
        db.session.commit()

    # Create sample skills
    if Skill.query.count() == 0:
        skills = [
            {
                'name': 'Python Programming',
                'description': 'Learn Python from basics to advanced concepts',
                'category': 'Programming',
                'icon': 'code'
            },
            {
                'name': 'UI/UX Design',
                'description': 'Master the principles of user interface design',
                'category': 'Design',
                'icon': 'palette'
            },
            {
                'name': 'Spanish Language',
                'description': 'Learn conversational Spanish',
                'category': 'Languages',
                'icon': 'language'
            }
        ]
        
        user = User.query.first()
        for skill_data in skills:
            skill = Skill(
                name=skill_data['name'],
                description=skill_data['description'],
                category=skill_data['category'],
                icon=skill_data['icon'],
                teacher_id=user.id
            )
            db.session.add(skill)
        
        db.session.commit()

# Admin Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    total_skills = Skill.query.count()
    total_verifications = VerificationRequest.query.count()
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    new_users_today = User.query.filter(
        User.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()
    new_skills_today = Skill.query.filter(
        Skill.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()
    
    # Package statistics
    stats = {
        'total_users': total_users,
        'total_skills': total_skills,
        'total_verifications': total_verifications,
        'pending_verifications': pending_verifications,
        'new_users_today': new_users_today,
        'new_skills_today': new_skills_today
    }
    
    # Get recent activity
    recent_activity = UserActivity.query.order_by(UserActivity.timestamp.desc()).limit(10).all()
    
    # Get recent verification requests
    pending_verification_requests = VerificationRequest.query.filter_by(status='pending').order_by(VerificationRequest.created_at.desc()).limit(5).all()
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template(
        'admin/dashboard.html',
        stats=stats,
        recent_activity=recent_activity,
        pending_verification_requests=pending_verification_requests,
        recent_users=recent_users,
        pending_verifications=pending_verifications
    )

@app.route('/admin/verification-requests')
@login_required
@admin_required
def admin_verification_requests():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    status_filter = request.args.get('status', 'all')
    date_range = request.args.get('date_range', 'all')
    search = request.args.get('search', '')
    
    # Build query based on filters
    query = VerificationRequest.query
    
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if date_range and date_range != 'all':
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        if date_range == 'today':
            query = query.filter(VerificationRequest.created_at >= today)
        elif date_range == 'week':
            week_ago = today - timedelta(days=7)
            query = query.filter(VerificationRequest.created_at >= week_ago)
        elif date_range == 'month':
            month_ago = today - timedelta(days=30)
            query = query.filter(VerificationRequest.created_at >= month_ago)
    
    if search:
        # Join with User model to search by username
        query = query.join(User).filter(User.username.ilike(f'%{search}%'))
    
    # Order by newest first
    query = query.order_by(VerificationRequest.created_at.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    verification_requests = pagination.items
    
    # Get verification statistics
    stats = {
        'total_verifications': VerificationRequest.query.count(),
        'pending_verifications': VerificationRequest.query.filter_by(status='pending').count(),
        'approved_verifications': VerificationRequest.query.filter_by(status='approved').count(),
        'rejected_verifications': VerificationRequest.query.filter_by(status='rejected').count()
    }
    
    return render_template(
        'admin/verification_requests.html',
        verification_requests=verification_requests,
        stats=stats,
        page=page,
        pages=pagination.pages
    )

@app.route('/admin/verification/<int:request_id>')
@login_required
@admin_required
def admin_verification_detail(request_id):
    verification_request = VerificationRequest.query.get_or_404(request_id)
    
    # Get feedback if it exists
    feedback = VerificationFeedback.query.filter_by(request_id=request_id).order_by(VerificationFeedback.timestamp.desc()).first()
    
    # Get admin history for this request
    admin_history = AdminActionLog.query.filter(
        AdminActionLog.details.like(f'%request_id: {request_id}%')
    ).order_by(AdminActionLog.timestamp.desc()).first()
    
    return render_template(
        'admin/verification_detail.html',
        request=verification_request,
        feedback=feedback.message if feedback else '',
        admin_history=admin_history
    )

@app.route('/admin/verification/<int:request_id>/approve')
@login_required
@admin_required
def admin_approve_verification(request_id):
    verification_request = VerificationRequest.query.get_or_404(request_id)
    
    # Update request status
    verification_request.status = 'approved'
    verification_request.updated_at = datetime.utcnow()
    
    # Update user's verification status
    user = User.query.get(verification_request.user_id)
    user.is_verified = True
    
    # Log the action
    log_admin_action(
        'approve_verification',
        f'Approved verification request_id: {request_id} for user: {user.username}'
    )
    
    # Log user activity
    log_user_activity(
        user.id,
        'Your account has been verified',
        'verification'
    )
    
    db.session.commit()
    
    flash('Verification request approved successfully!', 'success')
    return redirect(url_for('admin_verification_detail', request_id=request_id))

@app.route('/admin/verification/<int:request_id>/reject')
@login_required
@admin_required
def admin_reject_verification(request_id):
    verification_request = VerificationRequest.query.get_or_404(request_id)
    
    # Update request status
    verification_request.status = 'rejected'
    verification_request.updated_at = datetime.utcnow()
    
    # Log the action
    user = User.query.get(verification_request.user_id)
    log_admin_action(
        'reject_verification',
        f'Rejected verification request_id: {request_id} for user: {user.username}'
    )
    
    # Log user activity
    log_user_activity(
        user.id,
        'Your verification request was rejected',
        'verification'
    )
    
    db.session.commit()
    
    flash('Verification request rejected!', 'success')
    return redirect(url_for('admin_verification_detail', request_id=request_id))

@app.route('/admin/verification/<int:request_id>/reset')
@login_required
@admin_required
def admin_reset_verification(request_id):
    verification_request = VerificationRequest.query.get_or_404(request_id)
    
    # Update request status
    verification_request.status = 'pending'
    verification_request.updated_at = datetime.utcnow()
    
    # Log the action
    user = User.query.get(verification_request.user_id)
    log_admin_action(
        'reset_verification',
        f'Reset verification request_id: {request_id} for user: {user.username} to pending'
    )
    
    db.session.commit()
    
    flash('Verification request status reset to pending!', 'success')
    return redirect(url_for('admin_verification_detail', request_id=request_id))

@app.route('/admin/verification/<int:request_id>/document')
@login_required
@admin_required
def admin_view_document(request_id):
    verification_request = VerificationRequest.query.get_or_404(request_id)
    
    # Check if file exists
    if not os.path.exists(verification_request.document_path):
        flash('Document file not found', 'error')
        return redirect(url_for('admin_verification_detail', request_id=request_id))
    
    # Log the action
    log_admin_action(
        'view_document',
        f'Viewed document for verification request_id: {request_id}'
    )
    
    # Get file extension
    _, ext = os.path.splitext(verification_request.document_filename)
    ext = ext.lower()
    
    if ext in ['.jpg', '.jpeg', '.png']:
        # Return image file
        return send_file(verification_request.document_path, mimetype=f'image/{ext[1:]}')
    elif ext == '.pdf':
        # Return PDF file
        return send_file(verification_request.document_path, mimetype='application/pdf')
    else:
        # Default to octet-stream for other file types
        return send_file(verification_request.document_path, mimetype='application/octet-stream')

@app.route('/admin/verification/<int:request_id>/notes', methods=['POST'])
@login_required
@admin_required
def admin_update_verification_notes(request_id):
    verification_request = VerificationRequest.query.get_or_404(request_id)
    
    # Update administrative notes
    notes = request.form.get('notes', '')
    verification_request.notes = notes
    
    # Update user feedback if provided
    feedback_message = request.form.get('feedback', '')
    if feedback_message:
        # Check if feedback already exists
        feedback = VerificationFeedback.query.filter_by(request_id=request_id).first()
        if feedback:
            feedback.message = feedback_message
            feedback.admin_id = current_user.id
            feedback.timestamp = datetime.utcnow()
        else:
            feedback = VerificationFeedback(
                request_id=request_id,
                admin_id=current_user.id,
                message=feedback_message
            )
            db.session.add(feedback)
    
    # Log the action
    log_admin_action(
        'update_verification_notes',
        f'Updated notes for verification request_id: {request_id}'
    )
    
    # Handle notification if requested
    notify_user = request.form.get('notify_user') == '1'
    if notify_user:
        # In a real application, you would send an email here
        # For now, we'll just log it
        user = User.query.get(verification_request.user_id)
        log_user_activity(
            user.id,
            'Your verification request has been updated',
            'notification'
        )
    
    db.session.commit()
    
    flash('Verification notes updated successfully!', 'success')
    return redirect(url_for('admin_verification_detail', request_id=request_id))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    verified_filter = request.args.get('verified', 'all')
    role_filter = request.args.get('role', 'all')
    date_joined_filter = request.args.get('date_joined', 'all')
    search = request.args.get('search', '')
    
    # Build query based on filters
    query = User.query
    
    if verified_filter and verified_filter != 'all':
        is_verified = verified_filter == 'verified'
        query = query.filter_by(is_verified=is_verified)
    
    if role_filter and role_filter != 'all':
        is_admin = role_filter == 'admin'
        query = query.filter_by(is_admin=is_admin)
    
    if date_joined_filter and date_joined_filter != 'all':
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        if date_joined_filter == 'today':
            query = query.filter(User.created_at >= today)
        elif date_joined_filter == 'week':
            week_ago = today - timedelta(days=7)
            query = query.filter(User.created_at >= week_ago)
        elif date_joined_filter == 'month':
            month_ago = today - timedelta(days=30)
            query = query.filter(User.created_at >= month_ago)
        elif date_joined_filter == 'year':
            year_ago = today - timedelta(days=365)
            query = query.filter(User.created_at >= year_ago)
    
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    # Order by newest first
    query = query.order_by(User.created_at.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    
    # Get user statistics
    stats = {
        'total_users': User.query.count(),
        'verified_users': User.query.filter_by(is_verified=True).count(),
        'admin_users': User.query.filter_by(is_admin=True).count(),
        'new_users_today': User.query.filter(
            User.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        ).count(),
        'pending_verifications': VerificationRequest.query.filter_by(status='pending').count()
    }
    
    return render_template(
        'admin/users.html',
        users=users,
        stats=stats,
        page=page,
        pages=pagination.pages
    )

@app.route('/admin/settings')
@login_required
@admin_required
def admin_settings():
    # Fetch all system settings
    settings = SystemSettings.query.all()
    
    # Group settings by category
    categorized_settings = {}
    for setting in settings:
        # Extract category from key (assuming format: 'category.setting_name')
        parts = setting.key.split('.', 1)
        category = parts[0] if len(parts) > 1 else 'general'
        
        if category not in categorized_settings:
            categorized_settings[category] = []
        
        categorized_settings[category].append(setting)
    
    # Get verification stats for sidebar
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    
    return render_template(
        'admin/settings.html',
        categorized_settings=categorized_settings,
        pending_verifications=pending_verifications
    )

@app.route('/admin/settings/update', methods=['POST'])
@login_required
@admin_required
def admin_settings_update():
    # Process form data
    for key, value in request.form.items():
        if key.startswith('setting_'):
            setting_key = key[8:]  # Remove 'setting_' prefix
            setting = SystemSettings.query.filter_by(key=setting_key).first()
            
            if setting:
                setting.value = value
                db.session.add(setting)
    
    db.session.commit()
    
    # Log the action
    log_admin_action(
        'update_settings',
        'Updated system settings'
    )
    
    flash('Settings updated successfully!', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin/export/verifications')
@login_required
@admin_required
def admin_export_verifications():
    import csv
    from io import StringIO
    
    # Query all verification requests
    verification_requests = VerificationRequest.query.all()
    
    # Create a CSV string
    output = StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow([
        'ID', 'User ID', 'Username', 'Document Filename', 
        'Status', 'Created At', 'Updated At', 'Notes'
    ])
    
    # Write data rows
    for req in verification_requests:
        user = User.query.get(req.user_id)
        writer.writerow([
            req.id, req.user_id, user.username, req.document_filename,
            req.status, req.created_at, req.updated_at, req.notes
        ])
    
    # Log the action
    log_admin_action(
        'export_verifications',
        'Exported verification requests data'
    )
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=verification_requests.csv'
    response.headers['Content-type'] = 'text/csv'
    
    return response

@app.route('/admin/export/users')
@login_required
@admin_required
def admin_export_users():
    import csv
    from io import StringIO
    
    # Query all users
    users = User.query.all()
    
    # Create a CSV string
    output = StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow([
        'ID', 'Username', 'Email', 'Verified', 'Admin',
        'Created At', 'Skills Count', 'Verification Requests'
    ])
    
    # Write data rows
    for user in users:
        skills_count = Skill.query.filter_by(teacher_id=user.id).count()
        verification_count = VerificationRequest.query.filter_by(user_id=user.id).count()
        
        writer.writerow([
            user.id, user.username, user.email, user.is_verified, 
            user.is_admin, user.created_at, skills_count, verification_count
        ])
    
    # Log the action
    log_admin_action(
        'export_users',
        'Exported users data'
    )
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=users.csv'
    response.headers['Content-type'] = 'text/csv'
    
    return response

@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    
    # Get user's skills
    skills = Skill.query.filter_by(teacher_id=user_id).all()
    
    # Get user's verification requests
    verification_requests = VerificationRequest.query.filter_by(user_id=user_id).order_by(VerificationRequest.created_at.desc()).all()
    
    # Get user's recent activity
    recent_activity = UserActivity.query.filter_by(user_id=user_id).order_by(UserActivity.timestamp.desc()).limit(10).all()
    
    # Get verification stats for sidebar
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    
    return render_template(
        'admin/user_detail.html',
        user=user,
        skills=skills,
        verification_requests=verification_requests,
        recent_activity=recent_activity,
        pending_verifications=pending_verifications
    )

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Update user data
        username = request.form.get('username')
        email = request.form.get('email')
        is_verified = request.form.get('is_verified') == '1'
        is_admin = request.form.get('is_admin') == '1'
        new_password = request.form.get('new_password')
        
        # Check if username already exists (if changed)
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('admin_user_edit', user_id=user_id))
        
        # Check if email already exists (if changed)
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('admin_user_edit', user_id=user_id))
        
        # Update user
        user.username = username
        user.email = email
        user.is_verified = is_verified
        user.is_admin = is_admin
        
        # Update password if provided
        if new_password:
            user.password_hash = generate_password_hash(new_password)
        
        # Log the action
        log_admin_action(
            'edit_user',
            f'Edited user {user.username} (ID: {user.id})'
        )
        
        db.session.commit()
        
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    
    # Get verification stats for sidebar
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    
    return render_template(
        'admin/user_edit.html',
        user=user,
        pending_verifications=pending_verifications
    )

@app.route('/admin/user/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users_create():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_verified = request.form.get('is_verified') == '1'
        is_admin = request.form.get('is_admin') == '1'
        
        # Validate required fields
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('admin_users_create'))
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('admin_users_create'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('admin_users_create'))
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_verified=is_verified,
            is_admin=is_admin
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log the action
        log_admin_action(
            'create_user',
            f'Created new user {new_user.username} (ID: {new_user.id})'
        )
        
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    # Get verification stats for sidebar
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    
    return render_template(
        'admin/user_create.html',
        pending_verifications=pending_verifications
    )

@app.route('/admin/user/<int:user_id>/delete')
@login_required
@admin_required
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent self-deletion
    if user.id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin_users'))
    
    # Log the action before deletion
    log_admin_action(
        'delete_user',
        f'Deleted user {user.username} (ID: {user.id})'
    )
    
    # Delete associated records
    VerificationRequest.query.filter_by(user_id=user_id).delete()
    UserActivity.query.filter_by(user_id=user_id).delete()
    Skill.query.filter_by(teacher_id=user_id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    flash('User and all associated data deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/skills')
@login_required
@admin_required
def admin_skills():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    category_filter = request.args.get('category', 'all')
    search = request.args.get('search', '')
    
    # Build query based on filters
    query = Skill.query
    
    if category_filter and category_filter != 'all':
        query = query.filter_by(category=category_filter)
    
    if search:
        query = query.filter(
            db.or_(
                Skill.name.ilike(f'%{search}%'),
                Skill.description.ilike(f'%{search}%')
            )
        )
    
    # Order by newest first
    query = query.order_by(Skill.created_at.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    skills = pagination.items
    
    # Get categories for filter
    categories = set([cat['name'] for cat in CATEGORIES])
    
    # Get statistics
    skills_count = Skill.query.count()
    skills_by_category = {}
    for category in categories:
        skills_by_category[category] = Skill.query.filter_by(category=category).count()
    
    # Get verification stats for sidebar
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    
    return render_template(
        'admin/skills.html',
        skills=skills,
        categories=sorted(categories),
        skills_count=skills_count,
        skills_by_category=skills_by_category,
        page=page,
        pages=pagination.pages,
        pending_verifications=pending_verifications
    )

@app.route('/admin/activity-log')
@login_required
@admin_required
def admin_activity_log():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    user_id = request.args.get('user_id', type=int)
    category = request.args.get('category')
    date_range = request.args.get('date_range', 'all')
    
    # Build query based on filters
    query = UserActivity.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if category:
        query = query.filter_by(category=category)
    
    if date_range and date_range != 'all':
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        if date_range == 'today':
            query = query.filter(UserActivity.timestamp >= today)
        elif date_range == 'week':
            week_ago = today - timedelta(days=7)
            query = query.filter(UserActivity.timestamp >= week_ago)
        elif date_range == 'month':
            month_ago = today - timedelta(days=30)
            query = query.filter(UserActivity.timestamp >= month_ago)
    
    # Order by timestamp descending
    query = query.order_by(UserActivity.timestamp.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    activities = pagination.items
    
    # Get categories for filter
    categories = db.session.query(UserActivity.category).distinct().all()
    categories = [c[0] for c in categories]
    
    # Get users for filter
    users = User.query.all()
    
    # Get verification stats for sidebar
    pending_verifications = VerificationRequest.query.filter_by(status='pending').count()
    
    return render_template(
        'admin/activity_log.html',
        activities=activities,
        categories=categories,
        users=users,
        page=page,
        pages=pagination.pages,
        pending_verifications=pending_verifications
    )

@app.route('/admin/skills/delete/<int:skill_id>')
@login_required
@admin_required
def admin_skill_delete(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    skill_name = skill.name
    
    # Log admin action
    log_admin_action(
        current_user.id,
        f'Deleted skill: {skill_name} (ID: {skill_id})',
        'skill'
    )
    
    # Delete enrollments related to this skill
    Enrollment.query.filter_by(skill_id=skill_id).delete()
    
    # Delete skill
    db.session.delete(skill)
    db.session.commit()
    
    flash(f'Skill "{skill_name}" has been deleted successfully', 'success')
    return redirect(url_for('admin_skills'))

@app.route('/admin/export/skills')
@login_required
@admin_required
def admin_export_skills():
    # Get all skills with teacher information
    skills = db.session.query(
        Skill, User.username.label('teacher_name')
    ).join(User, Skill.teacher_id == User.id).all()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Name', 'Description', 'Category', 'Teacher', 'Created', 'Icon'])
    
    # Write data
    for skill, teacher_name in skills:
        writer.writerow([
            skill.id,
            skill.name,
            skill.description,
            skill.category,
            teacher_name,
            skill.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            skill.icon
        ])
    
    # Prepare response
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Log admin action
    log_admin_action(
        current_user.id,
        f'Exported skills data',
        'export'
    )
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=skillswap_skills_{timestamp}.csv'}
    )

# Add admin link in navbar for admins
@app.context_processor
def utility_processor():
    def is_admin():
        if current_user.is_authenticated:
            return current_user.is_admin
        return False
    return dict(is_admin=is_admin)

# Add unread messages count to all templates
@app.context_processor
def unread_messages_count():
    count = 0
    if current_user.is_authenticated:
        count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
    return dict(unread_messages_count=count)

# Create CLI commands
@app.cli.command("create-admin")
@click.option("--username", default=DEFAULT_ADMIN_USERNAME, help="Admin username")
@click.option("--password", default=DEFAULT_ADMIN_PASSWORD, help="Admin password")
@click.option("--email", default=DEFAULT_ADMIN_EMAIL, help="Admin email")
def create_admin_command(username, password, email):
    """Create or reset admin user."""
    admin = User.query.filter_by(username=username).first()
    
    if admin:
        admin.email = email
        admin.password_hash = generate_password_hash(password)
        admin.is_admin = True
        admin.is_verified = True
        click.echo(f"Admin user '{username}' has been updated")
    else:
        admin = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=True,
            is_verified=True
        )
        db.session.add(admin)
        click.echo(f"Admin user '{username}' has been created")
    
    db.session.commit()
    click.echo("Admin credentials:")
    click.echo(f"  Username: {username}")
    click.echo(f"  Password: {password}")
    click.echo(f"  Email: {email}")

# Messaging routes
@app.route('/messages')
@login_required
def messages_inbox():
    # Get all received messages, newest first
    messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    unread_count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
    
    return render_template('messages/inbox.html', 
                          messages=messages, 
                          unread_count=unread_count,
                          active_tab='inbox')

@app.route('/messages/sent')
@login_required
def messages_sent():
    # Get all sent messages, newest first
    messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()
    unread_count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
    
    return render_template('messages/sent.html', 
                          messages=messages,
                          unread_count=unread_count,
                          active_tab='sent')

@app.route('/messages/view/<int:message_id>')
@login_required
def message_view(message_id):
    # Get the message
    message = Message.query.get_or_404(message_id)
    
    # Security check: only the sender or recipient can view the message
    if message.sender_id != current_user.id and message.recipient_id != current_user.id:
        flash('You do not have permission to view this message.', 'danger')
        return redirect(url_for('messages_inbox'))
    
    # Mark as read if the current user is the recipient
    if message.recipient_id == current_user.id and not message.read:
        message.read = True
        db.session.commit()
    
    # Get conversation history between these two users
    conversation = Message.query.filter(
        db.or_(
            db.and_(Message.sender_id == message.sender_id, Message.recipient_id == message.recipient_id),
            db.and_(Message.sender_id == message.recipient_id, Message.recipient_id == message.sender_id)
        )
    ).order_by(Message.timestamp.asc()).all()
    
    unread_count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
    
    return render_template('messages/view.html', 
                          message=message,
                          conversation=conversation,
                          unread_count=unread_count)

@app.route('/messages/compose', methods=['GET', 'POST'])
@login_required
def message_compose():
    recipient_id = request.args.get('recipient_id', type=int)
    recipient = None
    
    if recipient_id:
        recipient = User.query.get_or_404(recipient_id)
    
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id', type=int)
        subject = request.form.get('subject')
        content = request.form.get('content')
        
        if not all([recipient_id, subject, content]):
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('message_compose', recipient_id=recipient_id))
        
        # Create the message
        message = Message(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            subject=subject,
            content=content
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Log user activity
        log_user_activity(
            current_user.id,
            f'Sent a message to {message.recipient.username}',
            'message'
        )
        
        flash('Your message has been sent!', 'success')
        return redirect(url_for('messages_inbox'))
    
    unread_count = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
    
    return render_template('messages/compose.html', 
                          recipient=recipient,
                          User=User,
                          unread_count=unread_count)

# Add custom filter for handling newlines in messages
@app.template_filter('nl2br')
def nl2br(value):
    if value:
        return value.replace('\n', '<br>')
    return ''

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_data()
    app.run(debug=True, port=5001) 