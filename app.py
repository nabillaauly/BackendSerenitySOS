import datetime
from flask import Flask, redirect, url_for, request, jsonify, session, render_template, Response
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from flask_httpauth import HTTPBasicAuth
from dotenv import load_dotenv
from bson.objectid import ObjectId
import uuid
import jwt
from pymongo import TEXT, MongoClient
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from bson import ObjectId

# Importing YOLO and CV2
import os
import cv2
import calendar
from ultralytics import YOLO

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sakinahumipramita.study@gmail.com'  # Ganti dengan email sendiri
app.config['MAIL_PASSWORD'] = 'wwrsdoxygrawuprn'  # Ganti dengan password email sendiri
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_DEFAULT_SENDER'] = 'sakinahumipramita.study@gmail.com'  # Ganti dengan email sendiri

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
jwt = JWTManager(app)
auth = HTTPBasicAuth()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
CORS(app)

google_bp = make_google_blueprint(client_id=os.getenv('GOOGLE_CLIENT_ID'), client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/login')


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.is_verified = user_data.get('is_verified', False)
        self.api_key = user_data.get('api_key')

    @staticmethod
    def create_user(username, email, password=None, google_id=None):
        user = {
            "username": username,
            "email": email,
            "password": bcrypt.generate_password_hash(password).decode('utf-8') if password else None,
            "google_id": google_id,
            "is_verified": False,
            "api_key": str(uuid.uuid4())
        }
        result = mongo.db.users.insert_one(user)
        user['_id'] = str(result.inserted_id)  # Convert ObjectId to string
        return user

    @staticmethod
    def find_by_email(email):
        return mongo.db.users.find_one({"email": email})

    @staticmethod
    def find_by_google_id(google_id):
        return mongo.db.users.find_one({"google_id": google_id})

    @staticmethod
    def verify_password(stored_password, provided_password):
        return bcrypt.check_password_hash(stored_password, provided_password)

    @staticmethod
    def set_verified(user_id):
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_verified': True}})


@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return User(user) if user else None


@auth.verify_password
def verify_password(email, password):
    user_data = User.find_by_email(email)
    if user_data and User.verify_password(user_data['password'], password):
        return User(user_data)
    return None


def verify_api_key(api_key):
    user_data = mongo.db.users.find_one({"api_key": api_key})
    if user_data:
        return User(user_data)
    return None


def decodetoken(jwtToken):
    decode_result = decode_token(jwtToken)
    return decode_result


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Missing username, email, or password"}), 400

    existing_user = User.find_by_email(email)
    if existing_user:
        if existing_user.get('is_verified', False):
            return jsonify({"message": "Email already registered"}), 400
        else:
            # Resend verification email
            token = create_access_token(identity=str(existing_user['_id']), expires_delta=False)
            msg = Message('Email Verification', recipients=[email])
            msg.body = f'Your verification link is: {token}'
            mail.send(msg)
            return jsonify({"message": "Verification email sent. Please check your inbox."}), 200

    user_data = User.create_user(username=username, email=email, password=password)

    # Send verification email
    token = create_access_token(identity=user_data['_id'], expires_delta=False)
    msg = Message('Email Verification', recipients=[email])
    msg.body = f'Your verification link is: {token}'
    mail.send(msg)

    return jsonify({"message": "User registered successfully. Verification email sent."}), 201


# Define a text index on 'username' and 'email' fields for case-insensitive search
mongo.db.users.create_index([("username", TEXT), ("email", TEXT)], default_language='english')

@app.route('/bearer-auth', methods=['GET'])
def detail_user():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = decode_token(jwt_token)
        username = token.get('sub')

        if not username:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"_id": ObjectId(username)})
        if not user:
            return {"message": "User not found"}, 404

        # Update is_verified to True
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"is_verified": True}})

        data = {
            'username': user['username'],
            'email': user['email'],
            '_id': str(user['_id'])  # Convert ObjectId to string
        }
    except Exception as e:
        return {
            'message': f'Token is invalid. Please log in again! {str(e)}'
        }, 401

    return jsonify(data), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    print(f'Received login data: {data}')  # Debugging statement
    email = data.get('email')
    password = data.get('password')
    user_data = User.find_by_email(email)
    print(f'User data found: {user_data}')  # Debugging statement

    if user_data and User.verify_password(user_data['password'], password):
        if not user_data.get('is_verified'):
            print('Email not verified')  # Debugging statement
            return jsonify({"message": "Email not verified"}), 403
        user = User(user_data)
        login_user(user)
        access_token = create_access_token(identity=user.id)
        print('Login successful')  # Debugging statement
        return jsonify({'message': 'Login berhasil', 'access_token': access_token}), 200
    print('Invalid credentials')  # Debugging statement
    return jsonify({"message": "Invalid credentials"}), 401


@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    try:
        data = request.json
        current_password = data.get('Password lama')
        new_password = data.get('Password baru')

        if not current_password or not new_password:
            return jsonify({"message": "Missing current password or new password"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        if not User.verify_password(user_data['password'], current_password):
            return jsonify({"message": "Current password is incorrect"}), 401

        current_user.update_password(new_password)
        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    try:
        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        profile_data = {
            'username': user_data['username'],
            'email': user_data['email'],
            'photo': url_for('static', filename='uploads/' + user_data.get('photo', 'default_profile.jpg'))
        }

        return jsonify(profile_data), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    try:
        data = request.form
        username = data.get('username')
        photo = request.files.get('photo')

        if not username:
            return jsonify({"message": "Missing username"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        update_data = {
            'username': username
        }

        if photo:
            photo_filename = f"{current_user.id}.jpg"
            photo.save(os.path.join('static/uploads', photo_filename))
            update_data['photo'] = photo_filename

        mongo.db.users.update_one({'_id': ObjectId(current_user.id)}, {'$set': update_data})

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    try:
        data = request.json
        new_email = data.get('new_email')

        if not new_email:
            return jsonify({"message": "Missing new email"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        # Send email confirmation
        token = create_access_token(identity=str(current_user.id), expires_delta=False)
        msg = Message('Email Change Confirmation', recipients=[new_email])
        msg.body = f'Your email change confirmation token is: {token}'
        mail.send(msg)

        return jsonify({"message": "Email change confirmation sent. Please check your inbox."}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/confirm_change_email', methods=['POST'])
def confirm_change_email():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = decode_token(jwt_token)
        user_id = token.get('sub')

        if not user_id:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "User not found"}), 404

        data = request.json
        new_email = data.get('new_email')

        if not new_email:
            return jsonify({"message": "New email not provided"}), 400

        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"email": new_email}})
        return jsonify({"message": "Email changed successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200


@app.route('/login/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get('/plus/v1/people/me')
    if not resp.ok:
        return jsonify({"message": "Google login failed"}), 400
    google_info = resp.json()
    google_id = google_info['id']
    email = google_info['emails'][0]['value']
    user_data = User.find_by_google_id(google_id)
    if not user_data:
        User.create_user(username=google_info['displayName'], email=email, google_id=google_id)
        user_data = User.find_by_google_id(google_id)
    user = User(user_data)
    login_user(user)
    return redirect(url_for('index'))


@app.route('/realtime')
def realtime():
    return render_template('video.html')


def detect_objects(selected_location):
    # Setup MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    db = client['detected_objects']
    collection = db['objects']

    # Load the YOLOv8 model with .pt weights
    model = YOLO('model/best.pt')

    # Open video file
    cap = cv2.VideoCapture("model/help.mp4")
    # cap = cv2.VideoCapture(0)

    while True:
        # Read frame from the camera
        ret, frame = cap.read()

        if ret:
            # Perform inference on the image
            results = model(frame)

            # Get detection results
            pred_boxes = results[0].boxes.xyxy.cpu().numpy()
            pred_scores = results[0].boxes.conf.cpu().numpy()
            pred_classes = results[0].boxes.cls.cpu().numpy()

            # Draw bounding boxes and labels on the frame
            for i, box in enumerate(pred_boxes):
                x1, y1, x2, y2 = map(int, box)
                label = f'{model.names[int(pred_classes[i])]} {pred_scores[i]:.2f}'
                cv2.rectangle(frame, (x1, y1), (x2, y2), (255, 0, 0), 2)
                cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (255, 0, 0), 2)

                # Save detection to MongoDB
                now = datetime.datetime.now()
                day_name = calendar.day_name[now.weekday()]
                date = now.strftime('%Y-%m-%d')
                time = now.strftime('%H:%M')
                detection = {
                    "class": model.names[int(pred_classes[i])],
                    "kecamatan": selected_location,
                    "date": date,
                    "time": time,
                    "confidence": float(pred_scores[i])
                }
                collection.insert_one(detection)

            # Encode the frame as JPEG
            ret, buffer = cv2.imencode('.jpg', frame)

            if not ret:
                continue

            # Yield the frame as a byte array
            yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

        else:
            break

    # Release the camera and clean up
    cap.release()
    client.close()


@app.route('/video_feed')
def video_feed():
    selected_location = request.args.get('kecamatan')
    return Response(detect_objects(selected_location), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    profile_picture_url = url_for('static', filename='uploads/' + user_data.get('photo', 'default.jpg'))
    return jsonify(
        username=user_data['username'],
        email=user_data['email'],
        profile_picture=profile_picture_url
    ), 200


if __name__ == '__main__':
    app.run(debug=True, host='194.31.53.102', port=21094)