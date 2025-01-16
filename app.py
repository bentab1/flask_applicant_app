from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
import pytz
from flask import send_from_directory, current_app
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
from datetime import datetime, timedelta
import random
import string
import re

# Initialize Flask app
app = Flask(__name__)
load_dotenv()  # Load environment variables from .env file

# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:deployment1234@154.53.42.12/deployment')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:1234Abcd@154.53.42.12/deployment')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup folder to save CV and Cover Letter
base_dir = os.path.abspath(os.path.dirname(__file__))  # Get the absolute path of the current file
app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'file')  # Join base directory with 'Files'

# Allowed file extensions
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx'}

# Set maximum content length (2MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

# Configure your upload folder
app.config['UPLOAD_FOLDER'] = 'static/job_description_files'  # Update this path to where you want to store the uploaded files
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}  # Only allow PDF files
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit for file uploads


# Set session lifetime (optional, ensures consistency)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=20)
# Secret key for session management (flash messages)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_default_secret_key')
# Initialize province_folder as None to handle state_province

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)
# Set the Nigerian timezone (West Africa Time)
nigerian_tz = pytz.timezone('Africa/Lagos')

# Default status values (These can be updated by admin in the backend)
FORM_OPEN = True  # True if form is open, False if closed

class FileUploadForm(FlaskForm):
    file = FileField('Upload File', validators=[DataRequired()])
    
    # Allow file_type_name to accept up to 255 characters, including spaces
    file_type_name = StringField(
        'File Type Name',
        validators=[
            DataRequired(message="File type name is required."),
            Length(max=255, message="File type name cannot exceed 255 characters.")
        ]
    )
    
    # Allow file_description to accept up to 400 characters, including spaces
    file_description = TextAreaField(
        'File Description',
        validators=[
            DataRequired(message="File description is required."),
            Length(max=400, message="Description must be 400 characters or less.")
        ]
    )
    submit = SubmitField('Upload')


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_type_name = db.Column(db.String(100), nullable=False)  # Name of the file type
    file_description = db.Column(db.String(400), nullable=False)  # Description of the file, up to 400 characters
    filename = db.Column(db.String(200), nullable=False)  # Actual file path/name
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for upload


class RoleStatus(db.Model):
    __tablename__ = 'role_status'

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(100), nullable=False, unique=True)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<RoleStatus {self.role_name}>'
    

class AccessCode(db.Model):
    __tablename__ = 'access_codes'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.Integer, nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created at field

    def __init__(self, code, expiration_date):
        self.code = code
        self.expiration_date = expiration_date


# Define the Applicants model (table)
class Applicants(db.Model):
    __tablename__ = 'applicants'

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)  # New field for country
    state_province = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(100), nullable=False)
    lga = db.Column(db.String(100), nullable=False)
    ward = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text, nullable=False)
    salary_expectation = db.Column(db.Text, nullable=False)  # if you need it to store strings like "$50,000"
    occupation = db.Column(db.String(100), nullable=False)
    cv_file = db.Column(db.String(200), nullable=False)
    cover_letter_file = db.Column(db.String(200), nullable=False)
    # Create the model field with the Nigerian time zone
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(nigerian_tz))  # New field for date and time

    def __repr__(self):
        return f'<Applicants {self.name}>'


# Helper function to check allowed file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper function to check allowed file types
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'DOCX'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Error handler for file size exceeding the 2MB limit
@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_error(error):
    flash("File size exceeds the 2MB limit. Please upload a smaller file.", "danger")
    return redirect(url_for('index'))


# Mock login check
def is_admin():
    return 'is_admin' in session and session['is_admin']


# Decorator for admin login required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            return redirect(url_for('login'))  # Redirect to login if not admin
        return f(*args, **kwargs)

    return decorated_function


# Function to generate a random access code
def generate_random_code(length=6):
    """
    Generate a random integer code with the specified number of digits.

    Args:
        length (int): The number of digits in the generated code.

    Returns:
        int: A random integer code.
    """
    if length < 1:
        raise ValueError("Length must be at least 1")

    # Generate a random integer with the specified number of digits
    start = 6 ** (length - 1)  # Smallest number with the specified length
    end = (6 ** length) - 1  # Largest number with the specified length

    return random.randint(start, end)


@app.route('/application-form', methods=['GET', 'POST'])
def index():
    error_message = None
    role = None
   
    # Filter the active roles based on the database
    active_roles = [role_name for role_name, in db.session.query(RoleStatus.role_name).filter_by(is_active=True).all()]

    if request.method == 'POST':
        role = request.form.get('role')
        access_code = request.form.get('accesscode')

        valid_code = AccessCode.query.filter_by(code=access_code).first()
        if valid_code and valid_code.expiration_date > datetime.now():
            if role not in active_roles:
                error_message = "This role is closed, please check back some other time."

        else:
            error_message = "Invalid or expired access code. Please try again later."

    return render_template('index.html', error_message=error_message, role=role, active_roles=active_roles)


      #to route the job description
@app.route('/job-descriptions')
def job_descriptions():
    # Fetch all uploaded files from the database
    files = File.query.all()
    return render_template('job_descriptions.html', files=files)


# Route to handle form submission
@app.route('/submit', methods=['POST'])
def submit():
    role = request.form.get('role')
    access_code = request.form.get('accesscode')

    # Check if the form is open based on the access code and FORM_OPEN status
    valid_code = AccessCode.query.filter_by(code=access_code).first()
    if not valid_code or valid_code.expiration_date < datetime.now() or not FORM_OPEN:
        flash("This application has closed or you have entered the wrong access code. Please double-check your access code or come back some other time.", "danger")
        return redirect(url_for('index'))
    
    # Check if the role is open in the database
    role_status = RoleStatus.query.filter_by(role_name=role).first()
    if not role_status or not role_status.is_active:
        flash("This role is closed, please check back some other time.", "danger")
        return redirect(url_for('index'))
   

    # Collect other form data
    name = request.form.get('name')
    phone = request.form.get('phone')
    email = request.form.get('email')
    address = request.form.get('address')
    country_code = request.form.get('countryCode')
    state_province= request.form.get('state_province', None)  # Capture state/province field
    occupation = request.form.get('occupation')
    salary_expectation = request.form.get('salary_expectation',None)
    country = request.form.get('country')  # Capture country field
    state = request.form.get('state', None)
    city = request.form.get('city')
    lga = request.form.get('lga')
    ward = request.form.get('ward')

    # Combine country code and phone number
    full_phone = f"{country_code}{phone}"

    # Handle file uploads for CV and Cover Letter
    cv_file = request.files.get('cv')
    cover_letter_file = request.files.get('coverLetter')

    # Check if files are allowed
    if not allowed_file(cv_file.filename) or not allowed_file(cover_letter_file.filename):
        flash('Invalid file type. Only PDF, DOC, DOCX are allowed.', 'danger')
        return redirect(url_for('index'))

    # Securely save file and get file path
    cv_filename = secure_filename(cv_file.filename)
    cover_letter_filename = secure_filename(cover_letter_file.filename)

    # Create folder structure
    role_folder = os.path.join(app.config['UPLOAD_FOLDER'], role)
    state_or_state_province_folder = os.path.join(role_folder, state or state_province)  # Use state_province as folder
    city_folder = os.path.join(state_or_state_province_folder, city)
    applicant_folder = os.path.join(city_folder, name)

    # Check if the role folder exists, if not create it
    if not os.path.exists(role_folder):
        os.makedirs(role_folder)

    # Check if the state/province folder exists, if not create it
    if not os.path.exists(state_or_state_province_folder):
        os.makedirs(state_or_state_province_folder)

    # Ensure city_folder is created if it doesn't exist
    if not os.path.exists(city_folder):
        os.makedirs(city_folder)

    # Check if the applicant's folder exists, if not create it
    if not os.path.exists(applicant_folder):
        os.makedirs(applicant_folder)

    # Paths for saving the files
    cv_path = os.path.join(applicant_folder, cv_filename)
    cover_letter_path = os.path.join(applicant_folder, cover_letter_filename)

    # Save files to the server (uploads folder)
    cv_file.save(cv_path)
    cover_letter_file.save(cover_letter_path)

    # Check if the phone number or email already exists
    existing_applicant = Applicants.query.filter((Applicants.phone == full_phone) | (Applicants.email == email)).first()
    if existing_applicant:
        flash("You have already applied for this role! Thank you!.", "danger")
        return redirect(url_for('index', already_applied=True))
        
        # Clean the salary input by removing non-numeric characters
    salary_expectation = re.sub(r'[^\d.]', '', salary_expectation)

    # Try to convert the salary to a float, default to 0.0 if conversion fails
    try:
        salary_expectation = float(salary_expectation)
    except ValueError:
        salary_expectation = 0.0  # In case the value is not a valid number
    # Create new applicant and save to the database
    new_applicant = Applicants(
        role=role,  # Added role/job field
        country=country,  # Save country to the database
        state=state,
        city=city,
        state_province=state_province,
        lga=lga,
        ward=ward,
        name=name,
        phone=full_phone,
        email=email,
        address=address,
        occupation=occupation,
        salary_expectation=salary_expectation,
        cv_file=cv_path,
        cover_letter_file=cover_letter_path
    )

    # Add to the database session and commit to save
    db.session.add(new_applicant)
    db.session.commit()

    flash("Your application has been submitted successfully!", "success")
    # Redirect to the home page with success message
    return redirect(url_for('index', success=True))
    
# Your existing route for the admin panel
@app.route('/admin', methods=['GET', 'POST'])
@admin_required  # Assuming you have an admin_required decorator to protect the admin panel
def admin_panel():
    FORM_OPEN = 'form_open' in request.form

    if request.method == 'POST':
        # Handle file upload if a file is submitted
        if 'file' in request.files:
            file = request.files.get('file')
            file_type_name = request.form.get('file_type_name', 'Untitled')
            file_description = request.form.get('file_description', '')

            if file and file_type_name and file_description:
                # Check if the file is a PDF
                if not file.filename.endswith('.pdf'):
                    flash('Invalid file type! Please upload a PDF file.', 'danger')
                   

                # Check if a file with the same name or description already exists
                existing_file = File.query.filter(
                    (File.file_type_name == file_type_name)
                ).first()

                if existing_file:
                    # Render error message if a duplicate is found
                    flash('This file has already been uploaded. Please choose another file.', 'danger')
                else:
                    # Create a unique path for storing the job description file
                    job_desc_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'job_descriptions')
                    if not os.path.exists(job_desc_folder):
                        os.makedirs(job_desc_folder)

                    filename = secure_filename(file.filename)
                    file_path = os.path.join(job_desc_folder, filename)
                    file.save(file_path)

                    # Save metadata to the database
                    new_file = File(
                        file_type_name=file_type_name,
                        file_description=file_description,
                        filename=filename
                    )
                    db.session.add(new_file)
                    db.session.commit()
                    flash('File uploaded successfully!', 'success')
            else:
                flash('Please provide a file, file type name, and description.', 'danger')

        # Update role statuses in the database
        for role in request.form:
            if role != 'form_open' and role not in ['file_type_name', 'file_description', 'file']:  # Skip irrelevant fields
                role_status = RoleStatus.query.filter_by(role_name=role).first()

                if role_status:
                    # Toggle the status
                    role_status.is_active = role in request.form
                else:
                    # Create new role if it doesn't exist
                    new_role_status = RoleStatus(role_name=role, is_active=(role in request.form))
                    db.session.add(new_role_status)

        # Commit all changes to the database
        db.session.commit()
        flash('Settings updated successfully!', 'success')

        # Redirect to avoid form resubmission
        return redirect(url_for('admin_panel'))

    # Fetch all roles and access codes for display
    roles = RoleStatus.query.order_by(RoleStatus.role_name).all()
    all_codes = AccessCode.query.order_by(AccessCode.created_at.desc()).limit(2).all()

    # Fetch all uploaded files for display
    files = File.query.all()

    return render_template('admin_panel.html', form_open=FORM_OPEN, roles=roles, all_codes=all_codes, files=files)


# Define the download_file route here
@app.route('/uploads/<filename>')
def download_file(filename):
    # Define the folder where your job description files are stored
    job_desc_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'job_description')

    # Ensure the file exists before serving it
    try:
        return send_from_directory(job_desc_folder, filename)
    except FileNotFoundError:
        flash("File not found.", "danger")
        return redirect(url_for('admin_panel'))
    
    
    #Define delete route
@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    # Get the file from the database by ID
    file_to_delete = File.query.get(file_id)

    if file_to_delete:
        # Delete the file from the file system
        job_desc_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'job_descriptions')
        file_path = os.path.join(job_desc_folder, file_to_delete.filename)

        try:
            os.remove(file_path)  # Remove the file from the server
            db.session.delete(file_to_delete)  # Remove the file entry from the database
            db.session.commit()
            flash('File deleted successfully!', 'success')
        except FileNotFoundError:
            flash('File not found on the server.', 'danger')
            return redirect(url_for('admin_panel'))
    else:
        flash('File not found in the database.', 'danger')

    return redirect(url_for('admin_panel'))



# Admin route to generate access code
# Admin route to generate access code
@app.route('/generate_code', methods=['POST'])
@admin_required
def generate_code():
    expiration_date_str = request.form.get('expiration_date')
    try:
        expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%dT%H:%M')

        if expiration_date < datetime.now():
            flash("Can't generate past date. Please enter the current or a future date.", "danger")
        else:
            # Generate new code
            new_code = generate_random_code()
            new_access_code = AccessCode(code=new_code, expiration_date=expiration_date)
            db.session.add(new_access_code)
            db.session.commit()

            # Invalidate old codes
            AccessCode.query.filter(AccessCode.code != new_code).update(
                {AccessCode.expiration_date: datetime.now()}
            )
            db.session.commit()

            flash("Access code generated successfully!", "success")
    except ValueError:
        flash("Invalid expiration date format! Please use YYYY-MM-DDTHH:MM.", "danger")

    return redirect(url_for('admin_panel'))

# Route to render the admin panel, add roles, and remove roles
@app.route('/admin/roles', methods=['GET', 'POST'])
def manage_roles():
    if request.method == 'POST':
        role_name = request.form['role_name']
        is_active = request.form['is_active'] == 'True'  # Convert string to boolean

        # Check if the role already exists
        existing_role = RoleStatus.query.filter_by(role_name=role_name).first()
        if existing_role:
            flash("This role already exists, please enter another role.", 'danger')
            return redirect(url_for('admin_panel'))

        # Create and save the new role to the database
        new_role = RoleStatus(role_name=role_name, is_active=is_active)
        db.session.add(new_role)
        db.session.commit()

        flash('New role added successfully!', 'success')
        return redirect(url_for('admin_panel'))  # Redirect to the same page

    # Query all roles from the database
    roles = RoleStatus.query.all()
    active_roles = [role.role_name for role in roles if role.is_active]
    return render_template('admin_panel', roles=roles, active_roles=active_roles)


# Route to handle role status toggling
@app.route('/admin/toggle_role_status/<int:role_id>', methods=['POST'])
@admin_required
def admin_toggle_status(role_id):
    role = RoleStatus.query.get(role_id)
    if role:
        print(f"Toggling role: {role.role_name}, Current Status: {role.is_active}")
        role.is_active = not role.is_active
        db.session.commit()
        flash(f"Role '{role.role_name}' status updated successfully!", 'success')
    else:
        flash(f"No role found with ID: {role_id}", 'danger')
    return redirect(url_for('admin_panel'))


# Route to remove a role
@app.route('/remove_role/<int:role_id>', methods=['POST'])
def remove_role(role_id):
    # Find the role by its id
    role = RoleStatus.query.get(role_id)
    if role:
        db.session.delete(role)  # Delete the role from the database
        db.session.commit()
        flash('Role removed successfully!', 'success')
    else:
        flash('Role not found!', 'danger')
    
    return redirect(url_for('admin_panel'))  # Redirect to role management page



# Admin login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin123@admin123':
            session['is_admin'] = True
            return redirect(url_for('admin_panel'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


# Session timing
@app.before_request
def check_session_timeout():
    # Ignore session checks for static files and non-authenticated routes
    if request.endpoint in ['login', 'static'] or not session.get('is_admin'):
        return

    # Check the last activity timestamp
    if 'last_activity' in session:
        last_activity = session['last_activity']

        # Convert `last_activity` to datetime object if it's stored as a string
        if isinstance(last_activity, str):
            last_activity = datetime.fromisoformat(last_activity)

        # Ensure both datetimes are naive or aware
        now = datetime.now().astimezone(last_activity.tzinfo) if last_activity.tzinfo else datetime.now()

        if (now - last_activity).total_seconds() > 1000:  # 15 seconds timeout
            session.clear()  # Clear the entire session to avoid residual data
            flash("Session timed out due to inactivity. Please log in again.", "danger")
            return redirect(url_for('login'))  # Redirect to login page

    # Update the last activity timestamp for the session
    session['last_activity'] = datetime.now().isoformat()  # Save as ISO format string


# logout route
@app.route('/logout')
def logout():
    session.pop('is_admin', None)  # Remove admin session
    flash("You have been logged out.", "info")  # Optional: Display a logout message
    return redirect(url_for('login'))  # Redirect to the login page


if __name__ == '__main__':
    app.run(debug=True)
