from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
from flask_cors import CORS
import os
# from waitress import serve


app = Flask(__name__)
app.secret_key = '!@#$%^&*()1234567890qwertyUIOP'  # Use a secure key in production

# Enable CORS for all domains on all routes
CORS(app)

# MySQL configurations
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'sql105.infinityfree.com')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'if0_39384912')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'agsf1234')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'if0_39384912_lasuedict25it')

mysql = MySQL(app)

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome to the Flask API home page",
        "status": "API is running"
    }), 200

@app.route('/api/receipt_reg', methods=['POST'])
def receipt_reg():
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    other_name = data.get('other_name', '')
    matric_number = data.get('matric_number')
    email = data.get('email')
    phone_number = data.get('phone_number')

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
        return jsonify({'error': str(e)}), 500

@app.route('/api/login_staff', methods=['POST'])
def login_staff():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM staff_login WHERE staff_username=%s AND staff_password=%s', (username, password))
    user = cursor.fetchone()
    cursor.close()

    if user:
        session['staff_logged_in'] = True
        session['staff_username'] = username
        return jsonify({'message': 'Staff login successful!'}), 200
    else:
        return jsonify({'error': 'Invalid staff credentials.'}), 401

@app.route('/api/login_admin', methods=['POST'])
def login_admin():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM admin_login WHERE admin_username=%s AND admin_password=%s', (username, password))
    user = cursor.fetchone()
    cursor.close()

    if user:
        session['admin_logged_in'] = True
        session['admin_username'] = username
        return jsonify({'message': 'Admin login successful!'}), 200
    else:
        return jsonify({'error': 'Invalid admin credentials.'}), 401

@app.route('/api/receipt_records', methods=['GET'])
def receipt_records():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT first_name, last_name, other_name, matric_number, email, phone_number FROM receipt_reg")
    records = cursor.fetchall()
    cursor.close()

    # Convert records to list of dicts
    records_list = []
    for row in records:
        records_list.append({
            'first_name': row[0],
            'last_name': row[1],
            'other_name': row[2],
            'matric_number': row[3],
            'email': row[4],
            'phone_number': row[5]
        })
    return jsonify(records_list), 200

@app.route('/api/record', methods=['GET'])
def record():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM record")
    records = cursor.fetchall()
    cursor.close()

    # Assuming record table columns: id, col1, col2, ...
    records_list = []
    for row in records:
        records_list.append({
            'id': row[0],
            # add other columns accordingly
        })
    return jsonify(records_list), 200

# if __name__ == '__main__':
#     app.run(debug=True)
# if __name__ == '__main__':
#     # Use Waitress to serve the Flask app on all interfaces, port 5000
#     serve(app, host='0.0.0.0', port=5000)
