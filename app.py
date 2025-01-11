from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
import pytz
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
from datetime import datetime, timedelta
import random
import string

# Initialize Flask app
app = Flask(__name__)
load_dotenv()  # Load environment variables from .env file

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:deployment1234@154.53.42.12/deployment')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup folder to save CV and Cover Letter
base_dir = os.path.abspath(os.path.dirname(__file__))  # Get the absolute path of the current file
app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'Files')  # Join base directory with 'Files'

# Allowed file extensions
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx'}

# Set maximum content length (2MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit
# Set session lifetime (optional, ensures consistency)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=20)
# Secret key for session management (flash messages)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_default_secret_key')

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)
# Set the Nigerian timezone (West Africa Time)
nigerian_tz = pytz.timezone('Africa/Lagos')

# Default status values (These can be updated by admin in the backend)
FORM_OPEN = True  # True if form is open, False if closed
ROLE_OPEN_STATUS = {
    'Aggregator': True,
    'Agent': True,
    'Sales': False,
    'Customer Care': True,
    'Finance': False,
    'Cooperate Lawyer': True,
    'Frontend Software developer': True,
    'backend Software developer': True
}

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
    state = db.Column(db.String(100), nullable=False)
    lga = db.Column(db.String(100), nullable=False)
    ward = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text, nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    cv_file = db.Column(db.String(200), nullable=False)
    cover_letter_file = db.Column(db.String(200), nullable=False)
    # Create the model field with the Nigerian time zone
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(nigerian_tz))  # New field for date and time

    def __repr__(self):
        return f'<Applicants {self.name}>'


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
    role = None  # Initialize role variable to avoid undefined errors

    # Filter the active roles only
    active_roles = [role_name for role_name, status in ROLE_OPEN_STATUS.items() if status]

    if request.method == 'POST':
        role = request.form.get('role')
        access_code = request.form.get('accesscode')

        # Check if access code is entered and valid
        valid_code = AccessCode.query.filter_by(code=access_code).first()
        if valid_code and valid_code.expiration_date > datetime.now():
            if ROLE_OPEN_STATUS.get(role) == False:
                error_message = "This role is closed, please check back some other time."

        else:
            error_message = "Invalid or expired access code. Please try again later."

    return render_template('index.html',
                           role_open_status=ROLE_OPEN_STATUS,
                           error_message=error_message,
                           role=role,
                           active_roles=active_roles)  # Pass active roles to the template


# Route to handle form submission
@app.route('/submit', methods=['POST'])
def submit():
    role = request.form.get('role')
    access_code = request.form.get('accesscode')

    # Check if the form is open based on the access code and FORM_OPEN status
    valid_code = AccessCode.query.filter_by(code=access_code).first()
    if not valid_code or valid_code.expiration_date < datetime.now() or not FORM_OPEN:
        flash("This application has closed or you have entered wrong access code,  please or double-check your code come back some other time.", "danger")
        return redirect(url_for('index'))
    # Check if the role is open
    if ROLE_OPEN_STATUS.get(role) == False:
        flash("This role is closed, please check back some other time.", "danger")
        return redirect(url_for('index'))

    # Collect other form data
    name = request.form.get('name')
    phone = request.form.get('phone')
    email = request.form.get('email')
    address = request.form.get('address')
    country_code = request.form.get('countryCode')
    occupation = request.form.get('occupation')
    state = request.form.get('state')
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
    state_folder = os.path.join(role_folder, state)
    applicant_folder = os.path.join(state_folder, name)

    # Check if the role folder exists, if not create it
    if not os.path.exists(role_folder):
        os.makedirs(role_folder)

    # Check if the state folder exists, if not create it
    if not os.path.exists(state_folder):
        os.makedirs(state_folder)

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

    # Create new applicant and save to the database
    new_applicant = Applicants(
        role=role,  # Added role/job field
        state=state,
        lga=lga,
        ward=ward,
        name=name,
        phone=full_phone,
        email=email,
        address=address,
        occupation=occupation,
        cv_file=cv_path,
        cover_letter_file=cover_letter_path
    )

    # Add to the database session and commit to save
    db.session.add(new_applicant)
    db.session.commit()

    flash("Your application has been submitted successfully!", "success")
    # Redirect to the home page with success message
    return redirect(url_for('index', success=True))


# admin route to admin panel
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    global FORM_OPEN, ROLE_OPEN_STATUS

    if request.method == 'POST':
        FORM_OPEN = 'form_open' in request.form
        for role in ROLE_OPEN_STATUS:
            ROLE_OPEN_STATUS[role] = role in request.form

        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin_panel'))

   # Convert ROLE_OPEN_STATUS dictionary to a list of roles with names and statuses
    roles = [{'id': role, 'name': role, 'status': 'active' if ROLE_OPEN_STATUS[role] else 'inactive'} for role in
             ROLE_OPEN_STATUS]

    # Fetch the latest 3 access codes from the database
    all_codes = AccessCode.query.order_by(AccessCode.created_at.desc()).limit(2).all()

    return render_template('admin_panel.html', form_open=FORM_OPEN, roles=roles, all_codes=all_codes)


# Admin route to generate access code
@app.route('/generate_code', methods=['GET', 'POST'])
@admin_required
def generate_code():
    if request.method == 'POST':
        expiration_date_str = request.form.get('expiration_date')
        try:
            # Convert expiration date from string to datetime object
            expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%dT%H:%M')

            # Check if the expiration date is in the future or now
            if expiration_date < datetime.now():
                flash("Can't generate past date. Please enter the current or a future date.", "danger")

                # Fetch the roles and access codes to render the admin panel correctly
                roles = [{'id': role, 'name': role, 'status': 'active' if ROLE_OPEN_STATUS[role] else 'inactive'} for
                         role in ROLE_OPEN_STATUS]
                all_codes = AccessCode.query.order_by(AccessCode.expiration_date.desc()).limit(2).all()

                return render_template('admin_panel.html', form_open=FORM_OPEN, roles=roles, all_codes=all_codes)

            # Generate and save the new code
            new_code = generate_random_code()
            new_access_code = AccessCode(code=new_code, expiration_date=expiration_date)
            db.session.add(new_access_code)
            db.session.commit()

            # Invalidate old codes by setting their expiration date to now
            AccessCode.query.filter(AccessCode.code != new_code).update(
                {AccessCode.expiration_date: datetime.now()}
            )
            db.session.commit()

            # Store the newly generated code and expiration date in session
            session['generated_code'] = new_code
            session['expiration_date'] = expiration_date.strftime('%Y-%m-%d %H:%M')

            flash("Access code generated successfully! Existing codes have been invalidated.", "success")
        except ValueError:
            flash("Invalid expiration date format!", "danger")

            # Fetch the roles and access codes to render the admin panel correctly
            roles = [{'id': role, 'name': role, 'status': 'active' if ROLE_OPEN_STATUS[role] else 'inactive'} for role
                     in ROLE_OPEN_STATUS]
            all_codes = AccessCode.query.order_by(AccessCode.expiration_date.desc()).all()

            return render_template('admin_panel.html', form_open=FORM_OPEN, roles=roles, all_codes=all_codes)

        return redirect(url_for('admin_panel'))  # Redirect to admin panel after generating the code

    return render_template('generate_code.html')  # Render the code generation form


# Admin toggle role status route
@app.route('/admin/toggle_status/<string:role_name>', methods=['POST'])
@admin_required
def admin_toggle_status(role_name):
    if role_name in ROLE_OPEN_STATUS:
        # Toggle the status of the role
        ROLE_OPEN_STATUS[role_name] = not ROLE_OPEN_STATUS[role_name]

        flash(f"Role '{role_name}' status updated successfully!", 'success')
    else:
        flash(f"Invalid role name: '{role_name}'", 'danger')

    return redirect(url_for('admin_panel'))


# Admin login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin123':
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

        if (now - last_activity).total_seconds() > 30:  # 15 seconds timeout
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
