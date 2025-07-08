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

# Association table for Asset and MaintenanceStrategy (Many-to-Many)
asset_maintenance_strategies = db.Table('asset_maintenance_strategies',
    db.Column('asset_id', db.Integer, db.ForeignKey('asset.id'), primary_key=True),
    db.Column('strategy_id', db.Integer, db.ForeignKey('maintenance_strategy.id'), primary_key=True)
)

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
    name = db.Column(db.String(100), nullable=False) # Made non-nullable
    # asset_type = db.Column(db.String(100)) # Replaced by asset_type_id
    # location = db.Column(db.String(100)) # Replaced by location_id
    asset_id_tag = db.Column(db.String(100), unique=True, nullable=True) # Physical ID tag - made nullable as tag_number will be primary. Or remove this.
    status = db.Column(db.String(50)) # e.g., Operational, Down, Maintenance
    installation_date = db.Column(db.Date)
    description = db.Column(db.Text, nullable=True) # Adding general description field

    # Add relationships if needed, e.g., to WorkOrder
    work_orders = db.relationship('WorkOrder', backref='asset', lazy=True) # Existing one
    condition_logs = db.relationship('ConditionMonitoring', backref='asset_monitored', lazy='dynamic') # Changed lazy loading

    # New fields for Asset Management
    tag_number = db.Column(db.String(100), unique=True, nullable=False) # This will be the primary business identifier
    document_link = db.Column(db.String(500), nullable=True)

    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=True)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'), nullable=True)
    asset_priority_id = db.Column(db.Integer, db.ForeignKey('asset_priority.id'), nullable=True)
    asset_type_id = db.Column(db.Integer, db.ForeignKey('asset_type.id'), nullable=True)

    # Relationships to new lookup tables
    location = db.relationship('Location', backref=db.backref('assets', lazy='dynamic'))
    unit = db.relationship('Unit', backref=db.backref('assets', lazy='dynamic'))
    asset_priority = db.relationship('AssetPriority', backref=db.backref('assets', lazy='dynamic'))
    asset_type = db.relationship('AssetType', backref=db.backref('assets', lazy='dynamic'))

    # Many-to-Many relationship with MaintenanceStrategy
    strategies = db.relationship('MaintenanceStrategy', secondary=asset_maintenance_strategies,
                                 backref=db.backref('assets', lazy='dynamic'), lazy='dynamic')


class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<Location {self.name}>'

class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<Unit {self.name}>'

class AssetPriority(db.Model): # To distinguish from WorkOrder priority levels
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False) # e.g., Critical, High, Medium, Low

    def __repr__(self):
        return f'<AssetPriority {self.name}>'

class AssetType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False) # e.g., Rotating, Static, Electrical, Instrument

    def __repr__(self):
        return f'<AssetType {self.name}>'

class MaintenanceStrategy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<MaintenanceStrategy {self.name}>'


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

    # The relationship to Asset is now primarily managed via Asset.condition_logs backref
    # asset_monitored = db.relationship('Asset', backref='condition_logs')

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

from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional

# ... (other imports remain the same)

# Choices for asset_id and assigned_to_user_id will be populated in the routes

# Asset Form
class AssetForm(FlaskForm):
    name = StringField('Asset Name', validators=[DataRequired(), Length(max=100)])
    tag_number = StringField('Tag Number', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    asset_id_tag = StringField('Physical ID Tag (Optional)', validators=[Optional(), Length(max=100)]) # Secondary Tag
    status = StringField('Status', validators=[Optional(), Length(max=50)]) # Or SelectField if predefined statuses
    # installation_date = DateField('Installation Date', validators=[Optional()]) # Add later if DateField is easily available
    document_link = StringField('Document Link (URL)', validators=[Optional(), Length(max=500)])

    location_id = SelectField('Location', coerce=int, validators=[Optional()])
    unit_id = SelectField('Unit', coerce=int, validators=[Optional()])
    asset_priority_id = SelectField('Asset Priority', coerce=int, validators=[Optional()])
    asset_type_id = SelectField('Asset Type', coerce=int, validators=[Optional()])

    strategies = SelectMultipleField('Maintenance Strategies', coerce=int, validators=[Optional()])

    submit = SubmitField('Save Asset')

    # Choices for SelectFields will be populated in the routes that use this form.

    def validate_tag_number(self, tag_number_field):
        query = Asset.query.filter_by(tag_number=tag_number_field.data)
        if hasattr(self, 'obj_id') and self.obj_id: # If editing
            query = query.filter(Asset.id != self.obj_id)
        if query.first():
            raise ValidationError('This tag number is already in use. Please choose a different one.')

    def validate_asset_id_tag(self, asset_id_tag_field):
        if asset_id_tag_field.data: # Only validate if field is not empty
            query = Asset.query.filter_by(asset_id_tag=asset_id_tag_field.data)
            if hasattr(self, 'obj_id') and self.obj_id: # If editing
                query = query.filter(Asset.id != self.obj_id)
            if query.first():
                raise ValidationError('This physical ID tag is already in use.')


# Settings Forms
class LocationForm(FlaskForm):
    name = StringField('Location Name', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Save Location')

    def validate_name(self, name):
        # Check if location name already exists, excluding current if editing
        query = Location.query.filter_by(name=name.data)
        if hasattr(self, 'obj_id') and self.obj_id: # If editing
            query = query.filter(Location.id != self.obj_id)
        if query.first():
            raise ValidationError('This location name already exists. Please choose a different one.')

class UnitForm(FlaskForm):
    name = StringField('Unit Name', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Save Unit')

    def validate_name(self, name):
        query = Unit.query.filter_by(name=name.data)
        if hasattr(self, 'obj_id') and self.obj_id:
            query = query.filter(Unit.id != self.obj_id)
        if query.first():
            raise ValidationError('This unit name already exists.')

class AssetPriorityForm(FlaskForm):
    name = StringField('Priority Name', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Save Priority')

    def validate_name(self, name):
        query = AssetPriority.query.filter_by(name=name.data)
        if hasattr(self, 'obj_id') and self.obj_id:
            query = query.filter(AssetPriority.id != self.obj_id)
        if query.first():
            raise ValidationError('This asset priority name already exists.')

class AssetTypeForm(FlaskForm):
    name = StringField('Asset Type Name', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Save Asset Type')

    def validate_name(self, name):
        query = AssetType.query.filter_by(name=name.data)
        if hasattr(self, 'obj_id') and self.obj_id:
            query = query.filter(AssetType.id != self.obj_id)
        if query.first():
            raise ValidationError('This asset type name already exists.')

class MaintenanceStrategyForm(FlaskForm):
    name = StringField('Strategy Name', validators=[DataRequired(), Length(max=100)])
    description = StringField('Description') # Can be TextAreaField later
    submit = SubmitField('Save Strategy')

    def validate_name(self, name):
        query = MaintenanceStrategy.query.filter_by(name=name.data)
        if hasattr(self, 'obj_id') and self.obj_id:
            query = query.filter(MaintenanceStrategy.id != self.obj_id)
        if query.first():
            raise ValidationError('This maintenance strategy name already exists.')


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
    form.asset_id.choices = [(0, 'Select Asset')] + [(asset.id, f"{asset.tag_number} - {asset.name}") for asset in Asset.query.order_by(Asset.tag_number).all()]
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
    form.asset_id.choices = [(0, 'Select Asset')] + [(asset.id, f"{asset.tag_number} - {asset.name}") for asset in Asset.query.order_by(Asset.tag_number).all()]
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
    page = request.args.get('page', 1, type=int)
    filter_name = request.args.get('filter_name', '').strip()
    filter_tag = request.args.get('filter_tag', '').strip()

    assets_query = Asset.query
    if filter_name:
        assets_query = assets_query.filter(Asset.name.ilike(f'%{filter_name}%'))
    if filter_tag:
        assets_query = assets_query.filter(Asset.tag_number.ilike(f'%{filter_tag}%'))

    assets_query = assets_query.order_by(Asset.name)
    assets_list = assets_query.paginate(page=page, per_page=10)
    return render_template('assets.html', assets_list=assets_list, title="Assets", filter_name=filter_name, filter_tag=filter_tag)

def populate_asset_form_choices(form):
    form.location_id.choices = [(0, '--- Select Location ---')] + [(loc.id, loc.name) for loc in Location.query.order_by(Location.name).all()]
    form.unit_id.choices = [(0, '--- Select Unit ---')] + [(u.id, u.name) for u in Unit.query.order_by(Unit.name).all()]
    form.asset_priority_id.choices = [(0, '--- Select Priority ---')] + [(p.id, p.name) for p in AssetPriority.query.order_by(AssetPriority.name).all()]
    form.asset_type_id.choices = [(0, '--- Select Type ---')] + [(t.id, t.name) for t in AssetType.query.order_by(AssetType.name).all()]
    form.strategies.choices = [(s.id, s.name) for s in MaintenanceStrategy.query.order_by(MaintenanceStrategy.name).all()]

@app.route('/asset/new', methods=['GET', 'POST'])
@login_required
def new_asset():
    form = AssetForm()
    populate_asset_form_choices(form)

    if form.validate_on_submit():
        asset = Asset(
            name=form.name.data,
            tag_number=form.tag_number.data,
            description=form.description.data,
            asset_id_tag=form.asset_id_tag.data or None,
            status=form.status.data,
            document_link=form.document_link.data or None,
            location_id=form.location_id.data if form.location_id.data != 0 else None,
            unit_id=form.unit_id.data if form.unit_id.data != 0 else None,
            asset_priority_id=form.asset_priority_id.data if form.asset_priority_id.data != 0 else None,
            asset_type_id=form.asset_type_id.data if form.asset_type_id.data != 0 else None
        )
        # Handle many-to-many for strategies
        selected_strategies = MaintenanceStrategy.query.filter(MaintenanceStrategy.id.in_(form.strategies.data)).all()
        asset.strategies = selected_strategies

        db.session.add(asset)
        db.session.commit()
        flash('Asset created successfully!', 'success')
        return redirect(url_for('assets'))
    return render_template('asset_form.html', title='New Asset', form=form, legend='New Asset')

@app.route('/asset/<int:asset_id>')
@login_required
def view_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    return render_template('view_asset.html', title=f"Asset: {asset.name}", asset=asset)

@app.route('/asset/<int:asset_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    form = AssetForm(obj=asset)
    form.obj_id = asset_id # For validation unique checks
    populate_asset_form_choices(form)

    if form.validate_on_submit():
        asset.name = form.name.data
        asset.tag_number = form.tag_number.data
        asset.description = form.description.data
        asset.asset_id_tag = form.asset_id_tag.data or None
        asset.status = form.status.data
        asset.document_link = form.document_link.data or None

        asset.location_id = form.location_id.data if form.location_id.data != 0 else None
        asset.unit_id = form.unit_id.data if form.unit_id.data != 0 else None
        asset.asset_priority_id = form.asset_priority_id.data if form.asset_priority_id.data != 0 else None
        asset.asset_type_id = form.asset_type_id.data if form.asset_type_id.data != 0 else None

        # Handle many-to-many for strategies
        selected_strategies = MaintenanceStrategy.query.filter(MaintenanceStrategy.id.in_(form.strategies.data)).all()
        asset.strategies = selected_strategies

        db.session.commit()
        flash('Asset updated successfully!', 'success')
        return redirect(url_for('view_asset', asset_id=asset.id))

    # Pre-select strategies for multi-select field on GET request
    if request.method == 'GET':
        form.strategies.data = [strategy.id for strategy in asset.strategies]

    return render_template('asset_form.html', title=f'Edit Asset: {asset.name}', form=form, legend=f'Edit Asset: {asset.name}', asset=asset)

@app.route('/asset/<int:asset_id>/delete', methods=['POST'])
@login_required
def delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    # Add check: if asset is linked to work orders, prevent deletion or ask for confirmation?
    if asset.work_orders:
         flash('Cannot delete asset. It is currently linked to one or more work orders. Please reassign or delete those first.', 'danger')
         return redirect(url_for('assets'))

    # Also consider condition monitoring logs if they should prevent deletion
    if asset.condition_logs.first(): # Using .first() to check existence
        flash('Cannot delete asset. It has condition monitoring history. Consider archiving instead.', 'danger')
        return redirect(url_for('assets'))

    db.session.delete(asset)
    db.session.commit()
    flash('Asset deleted successfully!', 'success')
    return redirect(url_for('assets'))


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin_users.html', users=users, title="User Management")

# --- Generic CRUD Helper Function (Optional, for reducing boilerplate) ---
# This is a more advanced refactoring. For now, I'll implement routes directly.

# --- Locations Routes ---
@app.route('/admin/locations', methods=['GET', 'POST'])
@login_required
def admin_locations():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    form = LocationForm()
    if form.validate_on_submit():
        new_location = Location(name=form.name.data)
        db.session.add(new_location)
        db.session.commit()
        flash('Location added successfully!', 'success')
        return redirect(url_for('admin_locations'))

    locations = Location.query.order_by(Location.name).all()
    return render_template('admin_settings_list.html', items=locations, form=form, title="Manage Locations", item_type="Location", endpoint_base="admin_locations")

@app.route('/admin/locations/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_admin_location(item_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    location = Location.query.get_or_404(item_id)
    form = LocationForm(obj=location)
    form.obj_id = item_id # For validation check

    if form.validate_on_submit():
        location.name = form.name.data
        db.session.commit()
        flash('Location updated successfully!', 'success')
        return redirect(url_for('admin_locations'))

    return render_template('admin_setting_form.html', form=form, title=f"Edit Location: {location.name}", item=location, item_type="Location", list_url=url_for('admin_locations'))

@app.route('/admin/locations/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_admin_location(item_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    location = Location.query.get_or_404(item_id)
    if location.assets.first(): # Check if in use
        flash('Cannot delete location. It is currently assigned to one or more assets.', 'danger')
        return redirect(url_for('admin_locations'))
    db.session.delete(location)
    db.session.commit()
    flash('Location deleted successfully!', 'success')
    return redirect(url_for('admin_locations'))

# --- Units Routes ---
@app.route('/admin/units', methods=['GET', 'POST'])
@login_required
def admin_units():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    form = UnitForm()
    if form.validate_on_submit():
        db.session.add(Unit(name=form.name.data))
        db.session.commit()
        flash('Unit added successfully!', 'success')
        return redirect(url_for('admin_units'))
    items = Unit.query.order_by(Unit.name).all()
    return render_template('admin_settings_list.html', items=items, form=form, title="Manage Units", item_type="Unit", endpoint_base="admin_units")

@app.route('/admin/units/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_units_edit(item_id): # Renamed to avoid conflict
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = Unit.query.get_or_404(item_id)
    form = UnitForm(obj=item); form.obj_id = item_id
    if form.validate_on_submit():
        item.name = form.name.data
        db.session.commit()
        flash('Unit updated successfully!', 'success')
        return redirect(url_for('admin_units'))
    return render_template('admin_setting_form.html', form=form, title=f"Edit Unit: {item.name}", item=item, item_type="Unit", list_url=url_for('admin_units'))

@app.route('/admin/units/delete/<int:item_id>', methods=['POST'])
@login_required
def admin_units_delete(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = Unit.query.get_or_404(item_id)
    if item.assets.first():
        flash('Cannot delete unit. It is currently assigned to one or more assets.', 'danger')
        return redirect(url_for('admin_units'))
    db.session.delete(item); db.session.commit()
    flash('Unit deleted successfully!', 'success')
    return redirect(url_for('admin_units'))

# --- AssetPriorities Routes ---
@app.route('/admin/asset_priorities', methods=['GET', 'POST'])
@login_required
def admin_asset_priorities():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    form = AssetPriorityForm()
    if form.validate_on_submit():
        db.session.add(AssetPriority(name=form.name.data))
        db.session.commit()
        flash('Asset Priority added successfully!', 'success')
        return redirect(url_for('admin_asset_priorities'))
    items = AssetPriority.query.order_by(AssetPriority.name).all()
    return render_template('admin_settings_list.html', items=items, form=form, title="Manage Asset Priorities", item_type="Asset Priority", endpoint_base="admin_asset_priorities")

@app.route('/admin/asset_priorities/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_asset_priorities_edit(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = AssetPriority.query.get_or_404(item_id)
    form = AssetPriorityForm(obj=item); form.obj_id = item_id
    if form.validate_on_submit():
        item.name = form.name.data
        db.session.commit()
        flash('Asset Priority updated successfully!', 'success')
        return redirect(url_for('admin_asset_priorities'))
    return render_template('admin_setting_form.html', form=form, title=f"Edit Asset Priority: {item.name}", item=item, item_type="Asset Priority", list_url=url_for('admin_asset_priorities'))

@app.route('/admin/asset_priorities/delete/<int:item_id>', methods=['POST'])
@login_required
def admin_asset_priorities_delete(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = AssetPriority.query.get_or_404(item_id)
    if item.assets.first():
        flash('Cannot delete asset priority. It is currently assigned to assets.', 'danger')
        return redirect(url_for('admin_asset_priorities'))
    db.session.delete(item); db.session.commit()
    flash('Asset Priority deleted successfully!', 'success')
    return redirect(url_for('admin_asset_priorities'))

# --- AssetTypes Routes ---
@app.route('/admin/asset_types', methods=['GET', 'POST'])
@login_required
def admin_asset_types():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    form = AssetTypeForm()
    if form.validate_on_submit():
        db.session.add(AssetType(name=form.name.data))
        db.session.commit()
        flash('Asset Type added successfully!', 'success')
        return redirect(url_for('admin_asset_types'))
    items = AssetType.query.order_by(AssetType.name).all()
    return render_template('admin_settings_list.html', items=items, form=form, title="Manage Asset Types", item_type="Asset Type", endpoint_base="admin_asset_types")

@app.route('/admin/asset_types/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_asset_types_edit(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = AssetType.query.get_or_404(item_id)
    form = AssetTypeForm(obj=item); form.obj_id = item_id
    if form.validate_on_submit():
        item.name = form.name.data
        db.session.commit()
        flash('Asset Type updated successfully!', 'success')
        return redirect(url_for('admin_asset_types'))
    return render_template('admin_setting_form.html', form=form, title=f"Edit Asset Type: {item.name}", item=item, item_type="Asset Type", list_url=url_for('admin_asset_types'))

@app.route('/admin/asset_types/delete/<int:item_id>', methods=['POST'])
@login_required
def admin_asset_types_delete(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = AssetType.query.get_or_404(item_id)
    if item.assets.first():
        flash('Cannot delete asset type. It is currently assigned to assets.', 'danger')
        return redirect(url_for('admin_asset_types'))
    db.session.delete(item); db.session.commit()
    flash('Asset Type deleted successfully!', 'success')
    return redirect(url_for('admin_asset_types'))

# --- MaintenanceStrategies Routes ---
@app.route('/admin/maintenance_strategies', methods=['GET', 'POST'])
@login_required
def admin_maintenance_strategies():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    form = MaintenanceStrategyForm()
    if form.validate_on_submit():
        db.session.add(MaintenanceStrategy(name=form.name.data, description=form.description.data))
        db.session.commit()
        flash('Maintenance Strategy added successfully!', 'success')
        return redirect(url_for('admin_maintenance_strategies'))
    items = MaintenanceStrategy.query.order_by(MaintenanceStrategy.name).all()
    return render_template('admin_settings_list.html', items=items, form=form, title="Manage Maintenance Strategies", item_type="Maintenance Strategy", endpoint_base="admin_maintenance_strategies")

@app.route('/admin/maintenance_strategies/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_maintenance_strategies_edit(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = MaintenanceStrategy.query.get_or_404(item_id)
    form = MaintenanceStrategyForm(obj=item); form.obj_id = item_id
    if form.validate_on_submit():
        item.name = form.name.data
        item.description = form.description.data
        db.session.commit()
        flash('Maintenance Strategy updated successfully!', 'success')
        return redirect(url_for('admin_maintenance_strategies'))
    return render_template('admin_setting_form.html', form=form, title=f"Edit Maintenance Strategy: {item.name}", item=item, item_type="Maintenance Strategy", list_url=url_for('admin_maintenance_strategies'))

@app.route('/admin/maintenance_strategies/delete/<int:item_id>', methods=['POST'])
@login_required
def admin_maintenance_strategies_delete(item_id): # Renamed
    if current_user.role != 'admin':
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    item = MaintenanceStrategy.query.get_or_404(item_id)
    if item.assets.first(): # Check if in use by any asset
        flash('Cannot delete strategy. It is currently assigned to one or more assets.', 'danger')
        return redirect(url_for('admin_maintenance_strategies'))
    db.session.delete(item); db.session.commit()
    flash('Maintenance Strategy deleted successfully!', 'success')
    return redirect(url_for('admin_maintenance_strategies'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # This creates the tables based on the models
    app.run(debug=True)
