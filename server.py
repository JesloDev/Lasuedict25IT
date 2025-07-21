from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
import os
import enum
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, validate, ValidationError, EXCLUDE
import traceback

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '!@#$%^&*()1234567890qwertyUIOP')

# Enable cookies to be sent cross-site (SameSite=None) and secure flag enabled
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True  # Must be True when SameSite=None to work in modern browsers
)


# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///dev.db')  # fallback for dev
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# CORS setup supporting credentials with specific allowed origins
CORS(
    app,
    supports_credentials=True,
    origins=["https://lasued-ticketer.vercel.app", "http://localhost:5173"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'


# --- Unauthorized handler to avoid redirect (returns JSON 401) ---
@login_manager.unauthorized_handler
def unauthorized_callback():
    return jsonify({'error': 'Authentication required'}), 401


# --- Models ---
class UsageEnum(enum.Enum):
    available = 'available'
    assigned = 'assigned'


class ReceiptReg(db.Model):
    __tablename__ = 'receipt_reg'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    other_name = db.Column(db.String(100), default='')
    matric_number = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.String(7), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


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

    # New fields
    faculty = db.Column(db.String(100))
    department = db.Column(db.String(100))
    level = db.Column(db.String(20))

    # From Ticket
    token_id = db.Column(db.String(150))
    token = db.Column(db.String(150), unique=True) # Add unique=True here
    usage = db.Column(db.String(100))

    # Meta
    source = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, server_default=db.func.now())


class Ticket(db.Model):
    __tablename__ = 'ticket'

    token = db.Column(db.String(150), primary_key=True)
    token_id = db.Column(db.String(150), nullable=False)
    usage = db.Column(db.String(20), nullable=False)


# --- Schemas ---
class ReceiptRegSchema(Schema):
    first_name = fields.Str(required=True, validate=validate.Length(min=1))
    last_name = fields.Str(required=True, validate=validate.Length(min=1))
    other_name = fields.Str()
    matric_number = fields.Str(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    phone_number = fields.Str(required=True, validate=validate.Length(min=7))


class UserLoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    role = fields.Str(required=True)


class RecordMetadataUpdateSchema(Schema):
    id = fields.Int(required=True)
    faculty = fields.Str(required=True)
    department = fields.Str(required=True)
    level = fields.Str(required=True)


class AssignTokenSchema(Schema):
    matric_number = fields.Str(required=True)
    token = fields.Str(required=True)


class UploadTicketItemSchema(Schema):
    token_id = fields.Str(required=True)
    token = fields.Str(required=True)
    usage = fields.Str(required=True, validate=validate.OneOf([e.value for e in UsageEnum]))


class RecordUpdateSchema(Schema):
    id = fields.Int(required=True)
    first_name = fields.Str()
    last_name = fields.Str()
    other_name = fields.Str(allow_none=True)
    matric_number = fields.Str()
    email = fields.Email()
    phone_number = fields.Str()
    faculty = fields.Str(allow_none=True)
    department = fields.Str(allow_none=True)
    level = fields.Str(allow_none=True)
    token_id = fields.Str(allow_none=True)
    token = fields.Str(allow_none=True)
    usage = fields.Str(allow_none=True)
    source = fields.Str(allow_none=True)

    class Meta:
        unknown = EXCLUDE


# --- Routes and views ---

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the Flask API home page", "status": "API is running"}), 200


@app.route('/api/receipt_reg', methods=['POST'])
def receipt_registration():
    json_data = request.get_json()
    try:
        validated_data = ReceiptRegSchema().load(json_data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    if ReceiptReg.query.filter_by(matric_number=validated_data['matric_number']).first():
        return jsonify({'error': 'Matric number already registered.'}), 409

    try:
        reg = ReceiptReg(**validated_data)
        db.session.add(reg)
        record = Record(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            other_name=validated_data.get('other_name', ''),
            matric_number=validated_data['matric_number'],
            email=validated_data['email'],
            phone_number=validated_data['phone_number'],
            source='receipt_reg'
        )
        db.session.add(record)
        db.session.commit()

        return jsonify({
            'message': 'Registration successful!',
            'receipt': {
                'id': reg.id,
                'first_name': reg.first_name,
                'last_name': reg.last_name,
                'other_name': reg.other_name,
                'matric_number': reg.matric_number,
                'email': reg.email,
                'phone_number': reg.phone_number
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database operation failed: {e}")
        return jsonify({'error': 'Database operation failed.'}), 500


@app.route('/api/login', methods=['POST'])
def user_login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not username or not password or not role:
        return jsonify({'error': 'Username, password and role are required'}), 400

    user = User.query.filter_by(username=username, role=role).first()

    if user and user.check_password(password):
        login_user(user)
        return jsonify({
            'message': 'Login successful',
            'username': user.username,
            'role': user.role
        }), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/receipt_records', methods=['GET'])
@login_required
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
        app.logger.error(f"Error fetching receipts: {e}")
        return jsonify({'error': 'Failed to retrieve receipt records.'}), 500


@app.route('/api/record', methods=['GET'])
@login_required
def handle_record_log():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=20, type=int)
    source = request.args.get('source', type=str)

    try:
        query = Record.query
        if source:
            query = query.filter(Record.source == source)
        pagination = query.order_by(Record.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        records = pagination.items
        data = [{
            'id': r.id,
            'first_name': r.first_name,
            'last_name': r.last_name,
            'other_name': r.other_name,
            'matric_number': r.matric_number,
            'email': r.email,
            'phone_number': r.phone_number,
            'faculty': r.faculty,
            'department': r.department,
            'level': r.level,
            'token_id': r.token_id,
            'token': r.token,
            'usage': r.usage,
            'source': r.source,
            'timestamp': r.timestamp.isoformat() if r.timestamp else None
        } for r in records]
        return jsonify({
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'records': data
        }), 200
    except Exception as e:
        app.logger.error(f'Failed to retrieve record log: {e}')
        return jsonify({'error': 'Failed to retrieve record log.'}), 500


@app.route('/api/record/update_metadata', methods=['PUT'])
@login_required
def update_record_metadata():
    json_data = request.get_json()
    try:
        validated = RecordUpdateSchema().load(json_data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    record = Record.query.get(validated['id'])
    if not record:
        return jsonify({'error': f'Record with id {validated["id"]} not found.'}), 404

    try:
        for key, value in validated.items():
            if key != 'id':
                setattr(record, key, value)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to update record metadata: {e}")
        return jsonify({'error': 'Failed to update record metadata.'}), 500

    updated = {field: getattr(record, field) for field in validated.keys() if field != "id"}
    updated['id'] = record.id

    return jsonify({
        'message': 'Record updated successfully.',
        'updated_record': updated
    }), 200


@app.route('/api/upload', methods=['POST'])
@login_required
def handle_upload_json_array():
    json_data = request.get_json()
    if not isinstance(json_data, list):
        return jsonify({'error': 'Request body must be a JSON array.'}), 400
    schema = UploadTicketItemSchema()
    errors = []
    valid_items = []
    for idx, item in enumerate(json_data):
        try:
            validated = schema.load(item)
            valid_items.append(validated)
        except ValidationError as e:
            errors.append({'index': idx, 'errors': e.messages})
    if errors:
        return jsonify({'validation_errors': errors}), 400
    try:
        saved_tickets = []
        for item in valid_items:
            # Only add tickets here, no record created on upload
            ticket = Ticket(token_id=item['token_id'], token=item['token'], usage=UsageEnum(item['usage']).value)
            db.session.add(ticket)
            saved_tickets.append({
                'token_id': ticket.token_id,
                'token': ticket.token,
                'usage': ticket.usage
            })
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Upload error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to save data.'}), 500
    return jsonify({
        'message': f'Successfully saved {len(saved_tickets)} tickets!',
        'tickets': saved_tickets
    }), 201


@app.route('/api/tickets', methods=['GET'])
@login_required
def get_tickets():
    try:
        tickets = Ticket.query.all()
        data = [{
            'token_id': t.token_id,
            'token': t.token,
            'usage': t.usage
        } for t in tickets]
        return jsonify(data), 200
    except Exception as e:
        app.logger.error(f"Ticket fetch error: {e}")
        return jsonify({'error': 'Failed to retrieve tickets.'}), 500


@app.route('/api/assign', methods=['POST'])
@login_required
def assign_token_to_matric():
    json_data = request.get_json()
    try:
        validated = AssignTokenSchema().load(json_data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    matric_number = validated['matric_number']
    token_value = validated['token']

    ticket = Ticket.query.filter_by(token=token_value).first()
    if not ticket:
        return jsonify({'error': f'Token "{token_value}" not found.'}), 404

    record = Record.query.filter_by(matric_number=matric_number).first()
    if not record:
        return jsonify({'error': f'Record with matric number "{matric_number}" not found.'}), 404

    # List of fields that must be non-empty/nonnull to allow assignment
    required_fields = ['first_name', 'last_name', 'email', 'phone_number', 'faculty', 'department', 'level']

    missing_fields = []
    for field in required_fields:
        value = getattr(record, field)
        if value is None or (isinstance(value, str) and value.strip() == ''):
            missing_fields.append(field)

    if missing_fields:
        return jsonify({
            'error': 'Cannot assign token. The following fields are missing or empty in the record:',
            'missing_fields': missing_fields
        }), 400

    # If all required fields are present, proceed with assignment
    try:
        # Check if record already has the token assigned
        # If not, create a new Record with token info?
        # Or update existing record: (Your original code logic)
        if not record.token or record.token != token_value:
            record.token_id = ticket.token_id
            record.token = ticket.token

        record.usage = UsageEnum.assigned.value
        record.source = 'assign'
        ticket.usage = UsageEnum.assigned.value

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Assign error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to assign token.'}), 500

    return jsonify({
        'message': f'Token "{token_value}" assigned to matric number "{matric_number}".',
        'updated_ticket': {
            'token_id': ticket.token_id,
            'token': ticket.token,
            'usage': ticket.usage
        },
        'updated_record': {
            'id': record.id,
            'matric_number': record.matric_number,
            'usage': record.usage,
            'token': record.token,
            'token_id': record.token_id,
            'source': record.source,
            'timestamp': record.timestamp.isoformat() if record.timestamp else None
        }
    }), 200


# Uncomment to run locally with debugging:
# if __name__ == '__main__':
#     app.run(debug=True)
