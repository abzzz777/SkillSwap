from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///skillswap.db'  # Using SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    skills = db.relationship('Skill', backref='user', lazy=True)

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(50), nullable=False, default='graduation-cap')
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Sample Categories
CATEGORIES = [
    {'name': 'Programming', 'icon': 'code', 'count': 15},
    {'name': 'Design', 'icon': 'palette', 'count': 10},
    {'name': 'Languages', 'icon': 'language', 'count': 8},
    {'name': 'Music', 'icon': 'music', 'count': 12}
]

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
    users = User.query.all()
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
        # Add registration logic here
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Add login logic here
        flash('Login successful!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/add_skill', methods=['GET', 'POST'])
@login_required
def add_skill():
    if request.method == 'POST':
        # Add skill creation logic here
        flash('Skill added successfully!', 'success')
        return redirect(url_for('skills_list'))
    return render_template('add_skill.html')

def create_sample_data():
    # Create sample users
    if User.query.count() == 0:
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_data()
    app.run(debug=True) 