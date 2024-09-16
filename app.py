import sqlite3
from flask import Response
from weasyprint import HTML
from flask import make_response
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ctir'

login_manager = LoginManager()
login_manager.init_app(app)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Function to create database table
def create_table():
    conn = sqlite3.connect('incident_reports.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports
                 (id INTEGER PRIMARY KEY,
                 report_date TEXT,
                 incident_date TEXT,
                 attack_type TEXT,
                 threat_actor TEXT,
                 threat_actor_alias TEXT,
                 targeted_units TEXT,
                 target_industries TEXT,
                 incident_sites TEXT,
                 address TEXT,
                 severity TEXT,
                 digital_infrastructure TEXT,
                 operating_system TEXT,
                 attack_method TEXT,
                 impact TEXT,
                 action_taken TEXT,
                 source TEXT,
                 recommendations TEXT,
                 assessment TEXT,
                 remarks TEXT)''')
    conn.commit()
    conn.close()

# Function to insert data into database
def insert_data(report_date, incident_date, attack_type, threat_actor, threat_actor_alias, 
                targeted_units, target_industries, incident_sites, address, severity, 
                digital_infrastructure, operating_system, attack_method, impact, 
                action_taken, source, recommendations, assessment, remarks):
    conn = sqlite3.connect('incident_reports.db')
    c = conn.cursor()
    c.execute('''INSERT INTO reports (report_date, incident_date, attack_type, threat_actor, 
                 threat_actor_alias, targeted_units, target_industries, incident_sites, 
                 address, severity, digital_infrastructure, operating_system, attack_method, 
                 impact, action_taken, source, recommendations, assessment, remarks) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (report_date, incident_date, attack_type, threat_actor, threat_actor_alias,
                 targeted_units, target_industries, incident_sites, address, severity,
                 digital_infrastructure, operating_system, attack_method, impact,
                 action_taken, source, recommendations, assessment, remarks))
    conn.commit()
    conn.close()

# Route for form submission to add a new report
@app.route('/add_report', methods=['GET', 'POST'])
@login_required
def add_report():
    if request.method == 'POST':
        # Retrieve form data
        report_date = request.form['report_date']
        incident_date = request.form['incident_date']
        attack_type = request.form['attack_type']
        threat_actor = request.form['threat_actor']
        threat_actor_alias = request.form['threat_actor_alias']
        targeted_units = request.form['targeted_units']
        target_industries = request.form['target_industries']
        incident_sites = request.form['incident_sites']
        address = request.form['address']
        severity = request.form['severity']
        digital_infrastructure = request.form['digital_infrastructure']
        operating_system = request.form['operating_system']
        attack_method = request.form['attack_method']
        impact = request.form['impact']
        action_taken = request.form['action_taken']
        source = request.form['source']
        recommendations = request.form['recommendations']
        assessment = request.form['assessment']
        remarks = request.form['remarks']
        
        # Insert data into the database
        insert_data(report_date, incident_date, attack_type, threat_actor, threat_actor_alias,
                    targeted_units, target_industries, incident_sites, address, severity,
                    digital_infrastructure, operating_system, attack_method, impact,
                    action_taken, source, recommendations, assessment, remarks)
        
        flash('Report added successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_report.html')

# Function to fetch single report by ID
def get_report(report_id):
    conn = sqlite3.connect('incident_reports.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
    report = c.fetchone()
    conn.close()
    return report

# Route for the dashboard page
@app.route('/admin_dashboard')
@login_required
def dashboard():
    # Fetch data from the database
    conn = sqlite3.connect('incident_reports.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM reports')
    reports = c.fetchall()
    conn.close()
    
    # Render the dashboard template with the fetched data
    return render_template('dashboard.html', reports=reports)

# Route for viewing a single report
@app.route('/view_report/<int:report_id>')
@login_required
def view_report(report_id):
    report = get_report(report_id)
    if report:
        return render_template('view_report.html', report=report)
    else:
        flash('Report not found', 'error')
        return redirect(url_for('dashboard'))

# Function to update report
def update_report(report_id, report_date, incident_date, attack_type, threat_actor, threat_actor_alias, 
                targeted_units, target_industries, incident_sites, address, severity, 
                digital_infrastructure, operating_system, attack_method, impact, 
                action_taken, source, recommendations, assessment, remarks):
    conn = sqlite3.connect('incident_reports.db')
    c = conn.cursor()
    c.execute('''UPDATE reports SET report_date=?, incident_date=?, attack_type=?, threat_actor=?, 
                 threat_actor_alias=?, targeted_units=?, target_industries=?, incident_sites=?, 
                 address=?, severity=?, digital_infrastructure=?, operating_system=?, attack_method=?, 
                 impact=?, action_taken=?, source=?, recommendations=?, assessment=?, remarks=?
                 WHERE id=?''',
                 (report_date, incident_date, attack_type, threat_actor, threat_actor_alias,
                 targeted_units, target_industries, incident_sites, address, severity,
                 digital_infrastructure, operating_system, attack_method, impact,
                 action_taken, source, recommendations, assessment, remarks, report_id))
    conn.commit()
    conn.close()

# Route for editing a single report
@app.route('/edit_report/<int:report_id>', methods=['GET', 'POST'])
@login_required
def edit_report(report_id):
    report = get_report(report_id)
    if request.method == 'POST':
        if report:
            # Retrieve updated data from the form
            report_date = request.form['report_date']
            incident_date = request.form['incident_date']
            attack_type = request.form['attack_type']
            threat_actor = request.form['threat_actor']
            threat_actor_alias = request.form['threat_actor_alias']
            targeted_units = request.form['targeted_units']
            target_industries = request.form['target_industries']
            incident_sites = request.form['incident_sites']
            address = request.form['address']
            severity = request.form['severity']
            digital_infrastructure = request.form['digital_infrastructure']
            operating_system = request.form['operating_system']
            attack_method = request.form['attack_method']
            impact = request.form['impact']
            action_taken = request.form['action_taken']
            source = request.form['source']
            recommendations = request.form['recommendations']
            assessment = request.form['assessment']
            remarks = request.form['remarks']

            # Perform the update operation in the database
            update_report(report_id, report_date, incident_date, attack_type, threat_actor, threat_actor_alias,
                           targeted_units, target_industries, incident_sites, address, severity,
                           digital_infrastructure, operating_system, attack_method, impact,
                           action_taken, source, recommendations, assessment, remarks)

            flash('Report updated successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Report not found', 'error')
            return redirect(url_for('dashboard'))
    else:
        if report:
            return render_template('edit_report.html', report=report)
        else:
            flash('Report not found', 'error')
            return redirect(url_for('dashboard'))

# Route for deleting a single report
@app.route('/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    # Delete the report from the database
    flash('Report deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# Function to fetch single report by ID
def get_report(report_id):
    conn = sqlite3.connect('incident_reports.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
    report_row = c.fetchone()
    conn.close()
    
    # Convert the row object to a dictionary
    report = dict(report_row)
    return report

@app.route('/export_pdf/<int:report_id>')
@login_required
def export_pdf(report_id):
    # Get the report data from your database or any other source
    report = get_report(report_id)

    # Render the HTML template with the report data
    rendered_html = render_template('report_template.html', report=report)

    # Generate PDF from the rendered HTML
    pdf = HTML(string=rendered_html).write_pdf()

    # Create a response with PDF as attachment
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=CyberThreatReport_{report_id}.pdf'

    return response

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    # Since we don't have a user model, we'll just return a User object with the provided user_id
    return User(user_id)

# Login view
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Your authentication logic here
        if username == 'ctir' and password == 'project':
            user = User(1)  # Create a user object
            login_user(user)  # Log in the user
            flash('You have been logged in', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your credentials', 'error')
    return render_template('login.html')

# Logout view
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_table()
    app.run(debug=True, host="0.0.0.0", port=5001)
