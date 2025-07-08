from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
from flask_cors import CORS
import os

app = Flask(__name__)

# --- Configuration ---
# Use a strong, truly random key in production, ideally loaded from an environment variable.
# For Render, set SECRET_KEY in your Render dashboard environment variables.
app.secret_key = os.getenv('SECRET_KEY', '!@#$%^&*()1234567890qwertyUIOP')

# MySQL configurations
# These should be set as environment variables in your Render dashboard.
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Optional: returns rows as dictionaries

mysql = MySQL(app)

# Enable CORS for all domains on all routes
CORS(app)


# --- Routes ---

@app.route('/', methods=['GET'])
def home():
    """
    Home page for the API, returns a status message.
    """
    return jsonify({
        "message": "Welcome to the Flask API home page",
        "status": "API is running"
    }), 200


@app.route('/api/receipt_reg', methods=['POST'])
def receipt_registration():
    """
    Handles registration for receipts, inserting data into the receipt_reg table.
    Expects JSON with first_name, last_name, matric_number, email, phone_number.
    other_name is optional.
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid or missing JSON data. Content-Type must be application/json.'}), 400

    # Extract data with default values for optional fields
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    other_name = data.get('other_name', '')  # Default to empty string if not provided
    matric_number = data.get('matric_number')
    email = data.get('email')
    phone_number = data.get('phone_number')

    # Basic validation (can be expanded)
    if not all([first_name, last_name, matric_number, email, phone_number]):
        return jsonify(
            {'error': 'Missing required fields (first_name, last_name, matric_number, email, phone_number).'}), 400

    try:
        cursor = mysql.connection.cursor()
        cursor.execute(
            '''
            INSERT INTO receipt_reg (first_name, last_name, other_name, matric_number, email, phone_number)
            VALUES (%s, %s, %s, %s, %s, %s)
            ''',
            (first_name, last_name, other_name, matric_number, email, phone_number)
        )
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'Registration successful!'}), 201
    except Exception as e:
        # Log the actual error in a production environment
        print(f"Database error during receipt registration: {e}")
        return jsonify({'error': f'Database operation failed: {str(e)}'}), 500


@app.route('/api/login', methods=['GET', 'POST'])
def user_login():
    """
    Handles user login (staff/admin) based on username, password, and roles.
    Expects JSON with admin_id (username), password, and roles.
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid or missing JSON data. Content-Type must be application/json.'}), 400

    username = data.get('admin_id')  # Renamed from admin_id to be more generic for username
    password = data.get('password')
    roles = data.get('roles')  # e.g., 'staff' or 'admin'

    if not all([username, password, roles]):
        return jsonify({'error': 'Missing required fields (admin_id/username, password, roles).'}), 400

    try:
        cursor = mysql.connection.cursor()
        # Query the 'users' table, assuming it has columns: username, password, roles
        cursor.execute(
            'SELECT username, roles FROM users WHERE username=%s AND Password=%s AND roles=%s',
            (username, password, roles)
        )
        user = cursor.fetchone()  # Fetches a dictionary if MYSQL_CURSORCLASS is DictCursor
        cursor.close()

        if user:
            # Store login status and user info in session
            session['logged_in'] = True
            session['username'] = user['username']
            session['roles'] = user['roles']  # Store roles from DB

            return jsonify({
                'message': f'{roles} login successful!',
                'username': user['username'],
                'roles': user['roles']
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials or role.'}), 401
    except Exception as e:
        print(f"Database error during login: {e}")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500


@app.route('/api/receipt_records', methods=['GET'])
def get_receipt_records():
    """
    Retrieves all records from the receipt_reg table.
    """
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM receipt_reg")
        records = cursor.fetchall()  # Returns list of dicts because of DictCursor
        cursor.close()
        return jsonify(records), 200
    except Exception as e:
        print(f"Database error fetching receipt records: {e}")
        return jsonify({'error': f'Failed to retrieve receipt records: {str(e)}'}), 500


@app.route('/api/record', methods=['GET', 'POST'])
def handle_records():
    """
    Handles GET requests for fetching all records from the 'record' table.
    Handles POST requests for adding a new record to the 'record' table.
    (Assuming 'record' table has 'id' and 'name' columns for demonstration)
    """
    if request.method == 'GET':
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM record")  # Adjust columns as per your 'record' table
            records = cursor.fetchall()
            cursor.close()
            return jsonify(records), 200
        except Exception as e:
            print(f"Database error fetching record: {e}")
            return jsonify({'error': f'Failed to retrieve records: {str(e)}'}), 500

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify(
                {'error': 'Invalid or missing JSON data for POST. Content-Type must be application/json.'}), 400


        record_department = data.get('department')
        record_faculty = data.get('faculty')

        if not record_department or not record_faculty:
            return jsonify({'error': 'Missing "department" or "faculty" field for new record.'}), 400

        try:
            cursor = mysql.connection.cursor()
            # Corrected: both faculty and department must be passed in the VALUES tuple
            cursor.execute("INSERT INTO record (faculty, department) VALUES (%s, %s)",
                           (record_faculty, record_department))
            mysql.connection.commit()
            cursor.close()
            return jsonify({'message': 'Record added successfully!', 'faculty': record_faculty,
                            'department': record_department}), 201
        except Exception as e:
            print(f"Database error adding record: {e}")
            return jsonify({'error': f'Failed to add record: {str(e)}'}), 500

@app.route('/api/upload', methods=['POST'])
def handle_upload_json_array():
    """
    Receives a JSON array from the front-end and saves each item into the database.
    Expects JSON array of objects, each with 'token', 'token_id', and 'usage' fields.
    """

    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({'error': 'Invalid or missing JSON array. Content-Type must be application/json and body must be a JSON array.'}), 400

    # Validate all items have required fields
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            return jsonify({'error': f'Item at index {i} is not a JSON object.'}), 400
        if 'token' not in item or 'token_id' not in item or 'usage' not in item:
            return jsonify({'error': f'Missing required fields in item at index {i}. Required: token, token_id, usage.'}), 400

    try:
        cursor = mysql.connection.cursor()
        for item in data:
            token = item['token']
            token_id = item['token_id']
            usage = item['usage']
            cursor.execute(
                '''
                INSERT INTO ticket (token_id, token, usage) VALUES (%s, %s, %s)
                ''',
                (token_id, token, usage)
            )
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': f'Successfully saved {len(data)} records!'}), 201
    except Exception as e:
        print(f"Database error in /api/upload: {e}")
        return jsonify({'error': f'Failed to save data: {str(e)}'}), 500


@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    """
    Fetch all tickets from the database and return as JSON.
    """
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM ticket")  # Adjust columns as needed
        tickets = cursor.fetchall()  # Returns list of dicts if using DictCursor
        cursor.close()

        return jsonify(tickets), 200
    except Exception as e:
        print(f"Database error fetching tickets: {e}")
        return jsonify({'error': f'Failed to retrieve tickets: {str(e)}'}), 500


# --- Main execution block for local development ---
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)

