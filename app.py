from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_bootstrap import Bootstrap
import os

app = Flask(__name__)
Bootstrap(app) # Initialize Flask-Bootstrap
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cmms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='technician') # e.g., admin, technician, manager

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    asset_type = db.Column(db.String(100))
    location = db.Column(db.String(100))
    asset_id_tag = db.Column(db.String(100), unique=True) # Physical ID tag
    status = db.Column(db.String(50)) # e.g., Operational, Down, Maintenance
    installation_date = db.Column(db.Date)
    # Add relationships if needed, e.g., to WorkOrder
    work_orders = db.relationship('WorkOrder', backref='asset', lazy=True)

class WorkOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='Open') # Open, In Progress, Done
    priority = db.Column(db.String(50), default='Medium') # Low, Medium, High
    creation_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    due_date = db.Column(db.DateTime)
    assigned_to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'))
    # Relationships
    assigned_to = db.relationship('User', backref='assigned_work_orders')

    # For attachments - this is a simplified example.
    # A more robust solution might involve a separate table for attachments.
    attachments = db.Column(db.String(500)) # Store paths to files, comma-separated, or use a dedicated model

class ConditionMonitoring(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    vibration_level = db.Column(db.Float)
    oil_condition = db.Column(db.String(100)) # e.g., Normal, Low, Contaminated
    temperature = db.Column(db.Float)
    # Add other relevant parameters

    asset_monitored = db.relationship('Asset', backref='condition_logs')

class WorkOrderComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    work_order_id = db.Column(db.Integer, db.ForeignKey('work_order.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    comment_text = db.Column(db.Text, nullable=False)

    work_order = db.relationship('WorkOrder', backref=db.backref('comments', lazy='dynamic'))
    user = db.relationship('User', backref='comments')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('technician', 'Technician'), ('manager', 'Manager'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional

class WorkOrderForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = StringField('Description') # Using StringField for now, can be TextAreaField
    priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')], validators=[DataRequired()])
    asset_id = SelectField('Asset', coerce=int, validators=[Optional()]) # Made Optional
    assigned_to_user_id = SelectField('Assign To', coerce=int, validators=[Optional()]) # Made Optional
    status = SelectField('Status', choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Done', 'Done')], validators=[DataRequired()])
    # due_date = DateField('Due Date', format='%Y-%m-%d', validators=[Optional()]) # Add DateField later if WTForms supports it easily or use StringField
    submit = SubmitField('Save Work Order')

    # Choices for asset_id and assigned_to_user_id will be populated in the routes


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/work_orders')
@login_required
def work_orders():
    page = request.args.get('page', 1, type=int)
    wo_query = WorkOrder.query.order_by(WorkOrder.creation_date.desc())
    work_orders_list = wo_query.paginate(page=page, per_page=10) # Paginate
    return render_template('work_orders.html', work_orders_list=work_orders_list, title="Work Orders")

@app.route('/work_order/new', methods=['GET', 'POST'])
@login_required
def new_work_order():
    form = WorkOrderForm()
    # Dynamically populate choices here is better if Asset/User list can change frequently
    form.asset_id.choices = [(0, 'Select Asset')] + [(asset.id, asset.name) for asset in Asset.query.order_by(Asset.name).all()]
    # form.asset_id.choices.insert(0, (0, 'Select Asset')) # Optional: Add a default choice
    form.assigned_to_user_id.choices = [(0, 'Unassigned')] + [(user.id, user.username) for user in User.query.filter(User.role.in_(['technician', 'manager'])).order_by(User.username).all()]
    # form.assigned_to_user_id.choices.insert(0, (0, 'Unassigned'))


    if form.validate_on_submit():
        # Ensure 0 is treated as None for ForeignKey fields
        asset_id_val = form.asset_id.data if form.asset_id.data and form.asset_id.data != 0 else None
        assigned_to_user_id_val = form.assigned_to_user_id.data if form.assigned_to_user_id.data and form.assigned_to_user_id.data != 0 else None

        wo = WorkOrder(
            title=form.title.data,
            description=form.description.data,
            priority=form.priority.data,
            status=form.status.data,
            asset_id=asset_id_val,
            assigned_to_user_id=assigned_to_user_id_val
            # created_by_user_id=current_user.id # Add this if you have such a field
        )
        db.session.add(wo)
        db.session.commit()
        flash('Work Order created successfully!', 'success')
        return redirect(url_for('work_orders'))
    return render_template('work_order_form.html', title='New Work Order', form=form, legend='New Work Order')

@app.route('/work_order/<int:work_order_id>')
@login_required
def view_work_order(work_order_id):
    wo = WorkOrder.query.get_or_404(work_order_id)
    return render_template('view_work_order.html', title=wo.title, work_order=wo)


@app.route('/work_order/<int:work_order_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_work_order(work_order_id):
    wo = WorkOrder.query.get_or_404(work_order_id)
    # Add authorization: only admin, manager, or assigned user can edit
    # if not (current_user.role in ['admin', 'manager'] or wo.assigned_to_user_id == current_user.id):
    #     flash('You do not have permission to edit this work order.', 'danger')
    #     return redirect(url_for('work_orders'))

    form = WorkOrderForm(obj=wo) # Pre-populate form with work order data
    form.asset_id.choices = [(0, 'Select Asset')] + [(asset.id, asset.name) for asset in Asset.query.order_by(Asset.name).all()]
    # form.asset_id.choices.insert(0, (0, 'Select Asset'))
    form.assigned_to_user_id.choices = [(0, 'Unassigned')] + [(user.id, user.username) for user in User.query.filter(User.role.in_(['technician', 'manager'])).order_by(User.username).all()]
    # form.assigned_to_user_id.choices.insert(0, (0, 'Unassigned'))


    if form.validate_on_submit():
        # Ensure 0 is treated as None for ForeignKey fields
        asset_id_val = form.asset_id.data if form.asset_id.data and form.asset_id.data != 0 else None
        assigned_to_user_id_val = form.assigned_to_user_id.data if form.assigned_to_user_id.data and form.assigned_to_user_id.data != 0 else None

        wo.title = form.title.data
        wo.description = form.description.data
        wo.priority = form.priority.data
        wo.status = form.status.data
        wo.asset_id = asset_id_val
        wo.assigned_to_user_id = assigned_to_user_id_val
        # wo.due_date = form.due_date.data # if using DateField
        db.session.commit()
        flash('Work Order updated successfully!', 'success')
        return redirect(url_for('view_work_order', work_order_id=wo.id))

    # Ensure current values are selected in dropdowns if they exist
    if request.method == 'GET':
        form.asset_id.data = wo.asset_id
        form.assigned_to_user_id.data = wo.assigned_to_user_id

    return render_template('work_order_form.html', title='Edit Work Order', form=form, legend=f'Edit Work Order: {wo.title}', work_order=wo)


@app.route('/assets')
@login_required
def assets():
    # Placeholder - will be developed further
    return "Assets Page - TBD"

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # This creates the tables based on the models
    app.run(debug=True)
