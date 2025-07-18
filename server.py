from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '!@#$%^&*()1234567890qwertyUIOP')

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Example: postgresql://user:pass@host/db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)


# --- Models ---
class ReceiptReg(db.Model):
    __tablename__ = 'receipt_reg'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    other_name = db.Column(db.String(100), default='')
    matric_number = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(7), primary_key=True)  # Match varchar(7)
    username = db.Column(db.String(50), nullable=False, unique=True)
    # Map Password column exactly - column name has uppercase P in DB schema
    Password = db.Column('Password', db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False)


class Record(db.Model):
    __tablename__ = 'record'
    id = db.Column(db.Integer, primary_key=True)

    # From ReceiptReg
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    other_name = db.Column(db.String(100))
    matric_number = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))

    # From User Login
    username = db.Column(db.String(100))
    role = db.Column(db.String(50))

    # From Ticket
    token_id = db.Column(db.String(150))
    token = db.Column(db.String(150))
    usage = db.Column(db.String(100))

    # Meta
    source = db.Column(db.String(50))  # e.g., 'receipt_reg', 'login', 'upload'
    timestamp = db.Column(db.DateTime, server_default=db.func.now())


class Ticket(db.Model):
    __tablename__ = 'ticket'
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.String(150), nullable=False)
    token = db.Column(db.String(150), nullable=False)
    usage = db.Column(db.String(100), nullable=False)


# --- Routes ---

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the Flask API home page", "status": "API is running"}), 200


@app.route('/api/receipt_reg', methods=['POST'])
def receipt_registration():
    data = request.get_json()
    required_fields = ['first_name', 'last_name', 'matric_number', 'email', 'phone_number']

    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields.'}), 400

    try:
        # Save in receipt_reg table
        reg = ReceiptReg(
            first_name=data['first_name'],
            last_name=data['last_name'],
            other_name=data.get('other_name', ''),
            matric_number=data['matric_number'],
            email=data['email'],
            phone_number=data['phone_number']
        )
        db.session.add(reg)

        # Log in record table
        log = Record(
            first_name=data['first_name'],
            last_name=data['last_name'],
            other_name=data.get('other_name', ''),
            matric_number=data['matric_number'],
            email=data['email'],
            phone_number=data['phone_number'],
            source='receipt_reg'
        )
        db.session.add(log)

        db.session.commit()
        return jsonify({'message': 'Registration successful!'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")
        return jsonify({'error': 'Database operation failed.'}), 500


@app.route('/api/login', methods=['POST'])
def user_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not all([username, password, role]):
        return jsonify({'error': 'Missing required fields.'}), 400

    try:
        user = User.query.filter_by(username=username, Password=password, role=role).first()
        if user:
            session['logged_in'] = True
            session['username'] = user.username
            session['role'] = user.role

            # Log login event as before...

            return jsonify({
                'message': f'{role} login successful!',
                'username': user.username,
                'role': user.role
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials or role.'}), 401
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/api/receipt_records', methods=['GET'])
def get_receipt_records():
    try:
        records = ReceiptReg.query.all()
        result = [{
            'id': r.id,
            'first_name': r.first_name,
            'last_name': r.last_name,
            'other_name': r.other_name,
            'matric_number': r.matric_number,
            'email': r.email,
            'phone_number': r.phone_number
        } for r in records]
        return jsonify(result), 200
    except Exception as e:
        print(f"Error fetching receipts: {e}")
        return jsonify({'error': 'Failed to retrieve receipt records.'}), 500


@app.route('/api/record', methods=['GET'])
def handle_record_log():
    try:
        records = Record.query.order_by(Record.timestamp.desc()).all()
        result = [{
            'id': r.id,
            'first_name': r.first_name,
            'last_name': r.last_name,
            'other_name': r.other_name,
            'matric_number': r.matric_number,
            'email': r.email,
            'phone_number': r.phone_number,
            'username': r.username,
            'role': r.role,
            'token': r.token,
            'token_id': r.token_id,
            'usage': r.usage,
            'source': r.source,
            'timestamp': r.timestamp
        } for r in records]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve record log: {str(e)}'}), 500


@app.route('/api/upload', methods=['POST'])
def handle_upload_json_array():
    data = request.get_json()

    if not isinstance(data, list):
        return jsonify({'error': 'Request body must be a JSON array.'}), 400

    try:
        for item in data:
            if not all(key in item for key in ('token', 'token_id', 'usage')):
                return jsonify({'error': 'Invalid item in array. Each must include token, token_id, usage.'}), 400

            # Save record to Ticket table
            ticket = Ticket(token_id=item['token_id'], token=item['token'], usage=item['usage'])
            db.session.add(ticket)

            # Save to Record log
            log = Record(token_id=item['token_id'], token=item['token'], usage=item['usage'], source='upload')
            db.session.add(log)

        db.session.commit()
        return jsonify({'message': f'Successfully saved {len(data)} tickets!'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Upload error: {e}")
        return jsonify({'error': f'Failed to save data: {str(e)}'}), 500


@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    try:
        tickets = Ticket.query.all()
        result = [{'id': t.id, 'token_id': t.token_id, 'token': t.token, 'usage': t.usage} for t in tickets]
        return jsonify(result), 200
    except Exception as e:
        print(f"Ticket fetch error: {e}")
        return jsonify({'error': 'Failed to retrieve tickets.'}), 500


# --- Run the App (for local development only) ---
# if __name__ == '__main__':
#     app.run(debug=True)

