from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from forms import LoginForm, RegisterForm, SkillForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-please-change')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/skillswap'
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
    skills_offered = db.relationship('Skill', backref='teacher', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html', form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html', form=form)
        
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Skill routes
@app.route('/')
def index():
    skills = Skill.query.order_by(Skill.created_at.desc()).all()
    return render_template('index.html', skills=skills)

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
    selected_categories = request.args.getlist('category')
    query = Skill.query
    
    if selected_categories:
        query = query.filter(Skill.category.in_(selected_categories))
    
    skills = query.order_by(Skill.created_at.desc()).all()
    categories = [choice[0] for choice in SkillForm.category.kwargs['choices']]
    return render_template('skills_list.html', skills=skills, categories=categories, selected_categories=selected_categories)

@app.route('/skill/<int:skill_id>')
def skill_detail(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    return render_template('skill_detail.html', skill=skill)

@app.route('/skill/add', methods=['GET', 'POST'])
@login_required
def add_skill():
    form = SkillForm()
    if form.validate_on_submit():
        skill = Skill(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            teacher_id=current_user.id
        )
        db.session.add(skill)
        db.session.commit()
        flash('Skill added successfully!', 'success')
        return redirect(url_for('skill_detail', skill_id=skill.id))
    return render_template('skill_form.html', form=form)

@app.route('/skill/<int:skill_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_skill(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    if skill.teacher_id != current_user.id:
        flash('You can only edit your own skills.', 'danger')
        return redirect(url_for('skill_detail', skill_id=skill.id))
    
    form = SkillForm(obj=skill)
    if form.validate_on_submit():
        skill.title = form.title.data
        skill.description = form.description.data
        skill.category = form.category.data
        db.session.commit()
        flash('Skill updated successfully!', 'success')
        return redirect(url_for('skill_detail', skill_id=skill.id))
    return render_template('skill_form.html', form=form, skill=skill)

@app.route('/skill/<int:skill_id>/delete', methods=['POST'])
@login_required
def delete_skill(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    if skill.teacher_id != current_user.id:
        flash('You can only delete your own skills.', 'danger')
        return redirect(url_for('skill_detail', skill_id=skill.id))
    
    db.session.delete(skill)
    db.session.commit()
    flash('Skill deleted successfully!', 'success')
    return redirect(url_for('skills_list'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
