import uuid
from flask import Flask, request
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended import JWTManager
import random
from flask import send_file, jsonify
from flask_jwt_extended import jwt_required
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import os
import string
import re
from dotenv import load_dotenv
import razorpay
from flask import request, jsonify
import requests
import json
from datetime import datetime, timedelta

import bcrypt

app = Flask(__name__)
CORS(app)

load_dotenv()
razorpay_key = os.getenv("RAZORPAY_KEY")
razorpay_secret = os.getenv("RAZORPAY_SECRET")

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(razorpay_key, razorpay_secret))

UPI_ID = os.getenv("UPI_ID")
import psycopg2
import os

def get_db_connection():
    """Establish a connection to the PostgreSQL database using environment variables."""
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        port=os.getenv("DB_PORT")
    )
    return conn


app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "fallback_secret")  # ✅ Use .env variable
jwt = JWTManager(app)


@app.route("/create_order", methods=["POST"])
def create_order():
    data = request.json
    amount = data["amount"]

    order = razorpay_client.order.create(
        {"amount": amount * 100, "currency": "INR", "payment_capture": 1}
    )

    return jsonify(order)

@app.route("/verify_payment", methods=["POST"])
def verify_payment():
    data = request.json
    conn = get_db_connection()
    razorpay_order_id = data.get("order_id")
    razorpay_payment_id = data.get("payment_id")
    razorpay_signature = data.get("signature")
    user_id = data["user_id"]
    num_tests = data["num_tests"]

    if not razorpay_order_id or not razorpay_payment_id or not razorpay_signature:
        return jsonify({"error": "Invalid payment details"}), 400

    # Verify Signature
    params_dict = {
        "razorpay_order_id": razorpay_order_id,
        "razorpay_payment_id": razorpay_payment_id,
        "razorpay_signature": razorpay_signature,
    }

    try:
        razorpay_client.utility.verify_payment_signature(params_dict)

        # Update user's test count in the database


        cursor = conn.cursor()
        cursor.execute(
            "UPDATE Users SET tests_left = tests_left + %s WHERE user_id = %s",
            (num_tests, user_id),
        )
        conn.commit()
        return jsonify({"message": "Payment verified and tests updated."})
    except razorpay.errors.SignatureVerificationError:
        return jsonify({"error": "Payment verification failed."}), 400

@app.route("/get_razorpay_key", methods=["GET"])
def get_razorpay_key():
    if not razorpay_key:
        return jsonify({"error": "Razorpay key not found"}), 500
    return jsonify({"key": razorpay_key})

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')




def is_valid_email(email):
    """Validate email format using regex."""
    regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return bool(re.match(regex, email))



def is_strong_password(password):
    if len(password) < 8:
        return False  # Password should be at least 8 characters
    if not re.search(r"[A-Z]", password):
        return False  # At least one uppercase letter
    if not re.search(r"[a-z]", password):
        return False  # At least one lowercase letter
    if not re.search(r"\d", password):
        return False  # At least one digit
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False  # At least one special character
    return True


def is_valid_mobile(mobile):
    regex = r'^\+?[1-9][0-9]{9,14}$'  # Supports international numbers
    return re.match(regex, mobile) is not None


@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    mobile_number = data.get('mobile_number')

    conn = get_db_connection()
    cursor = conn.cursor()

    if not is_valid_email(email):
        return jsonify({"message": "Invalid email format."}), 400

    if not is_strong_password(password):
        return jsonify({
                           "message": "Weak password. Must be at least 8 characters, include uppercase, lowercase, a number, and a special character."}), 400

    if not is_valid_mobile(mobile_number):
        return jsonify({"message": "Invalid mobile number format."}), 400

    # Hash the user's password
    hashed_password = hash_password(password)

    # Check if the email already exists
    cursor.execute("SELECT user_id FROM Users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        return jsonify({"message": "Email already exists."}), 400

    # Generate a unique username
    def generate_username(email):
        base = email.split("@")[0]  # Get text before @ in email
        random_suffix = ''.join(random.choices(string.digits, k=4))  # Random 4-digit number
        return f"{base}{random_suffix}"

    username = generate_username(email)

    # Insert new user into the database
    cursor.execute("""
        INSERT INTO Users (username, email, password, mobile_number, last_login, active, tests_left)
        VALUES (%s, %s, %s, %s, NULL, TRUE, 2)
    """, (username, email, hashed_password, mobile_number))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "User registered successfully!"}), 201


@app.route("/reset_password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    new_password = data.get("new_password")

    if not email or not new_password:
        return jsonify({"error": "Missing email or new password"}), 400

    hashed_password = hash_password(new_password)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE Users SET password = %s WHERE email = %s",
        (hashed_password, email),
    )

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Password updated successfully!"})


@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve the user from the database using email
    cursor.execute("SELECT user_id, password,mobile_number FROM Users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        # Compare the hashed password with the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            access_token = create_access_token(identity=str(user[0]), expires_delta=timedelta(minutes=30))
            return jsonify({
                "message": "Login successful!",
                "access_token": access_token,
                "user_id": user[0],
                "mobile_number": user[2]
            }), 200
        else:
            return jsonify({"message": "Invalid email or password."}), 400
    else:
        return jsonify({"message": "User not found."}), 404


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """A protected route that requires JWT authentication."""
    current_user = get_jwt_identity()  # Get the user ID from the token
    return jsonify({"message": f"Hello, user {current_user}!"}), 200


def generate_pin():
    """Generate a 6-digit random PIN (avoiding leading zero)."""
    return str(random.randint(100000, 999999))  # Ensures 6-digit PIN without leading 0


def generate_questions_with_gemini(subject, num_questions):
    """Generate MCQs using the Gemini AI API."""
    api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    api_key = os.getenv("GEMINI_API_KEY")  # Fetch API key securely from .env

    if not api_key:
        print("Error: Gemini API key is missing.")
        return []

    prompt = (
        f"Generate {num_questions} multiple-choice questions for the subject: {subject}. "
        "Each question should have 4 options, with one correct answer clearly marked. "
        "Provide the output in JSON format with fields: 'question', 'options', and 'answer'."
    )

    headers = {"Content-Type": "application/json"}
    data = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        response = requests.post(f"{api_url}?key={api_key}", headers=headers, json=data)
        response.raise_for_status()
        response_data = response.json()

        if "candidates" in response_data and response_data["candidates"]:
            raw_text = response_data["candidates"][0]["content"]["parts"][0]["text"]

            # Handle JSON output wrapped in triple backticks
            if raw_text.startswith("```json") and raw_text.strip().endswith("```"):
                raw_text = raw_text[7:-4].strip()

            return json.loads(raw_text)
        else:
            print("No content received in the API response.")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return []


@app.route('/generate_questions', methods=['POST'])
@jwt_required()  # Requires authentication
def generate_questions():
    """API endpoint to generate questions using Gemini AI."""
    data = request.json
    subject = data.get('subject')
    num_questions = data.get('num_questions')

    if not subject or not num_questions:
        return jsonify({"message": "Subject and number of questions are required."}), 400

    try:
        num_questions = int(num_questions)  # Ensure it's an integer
    except ValueError:
        return jsonify({"message": "Number of questions must be an integer."}), 400

    questions = generate_questions_with_gemini(subject, num_questions)

    if not questions:
        return jsonify({"message": "Failed to generate questions."}), 500

    return jsonify({"message": "Questions generated successfully!", "questions": questions}), 200


@app.route("/get_test_details", methods=["GET"])
def get_test_details():
    """Fetch test details by test_id."""
    test_id = request.args.get("test_id")

    if not test_id:
        return jsonify({"error": "Missing test_id"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT num_questions, time_limit, pin, status, score FROM Tests WHERE test_id = %s", (test_id,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    if result:
        return jsonify({
            "num_questions": result[0],
            "time_limit": result[1],
            "pin": result[2],
            "status": result[3],
            "score": result[4]
        }), 200
    else:
        return jsonify({"error": "Test not found"}), 404


@app.route('/create_test', methods=['POST'])
@jwt_required()
def create_test():
    """Create a test and generate questions using Gemini AI."""
    data = request.json
    creator_id = get_jwt_identity()
    pin = generate_pin()

    # Generate questions using Gemini AI
    questions = generate_questions_with_gemini(data['subject'], data['num_questions'])

    return jsonify({
        "message": "Questions generated successfully!",
        "pin": pin,
        "questions": questions
    }), 200


@app.route('/finalize_test', methods=['POST'])
@jwt_required()
def finalize_test():
    """Finalize a test by saving it to the database and updating tests_left."""
    data = request.json
    creator_id = get_jwt_identity()
    test_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    pin = generate_pin()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        validity_period = data.get("validity_period")
        if validity_period:
            validity_period = datetime.strptime(validity_period, "%Y-%m-%dT%H:%M")

        # ✅ Step 1: Check Initial `tests_left`
        cursor.execute("SELECT tests_left FROM Users WHERE user_id = %s FOR UPDATE", (creator_id,))
        tests_left = cursor.fetchone()

        if not tests_left or tests_left[0] <= 0:
            return jsonify({"message": "Insufficient tests left. Please buy more tests."}), 400

        # ✅ Step 2: Insert into Tests Table
        cursor.execute("""
            INSERT INTO Tests (test_id, creator_id, subject, num_questions, time_limit, status, test_taker_name, pin, validity_period, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (test_id, creator_id, data['subject'], data['num_questions'], data['time_limit'], 'open',
              data['test_taker_name'], pin, validity_period, datetime.now()))

        # ✅ Step 3: Insert Questions (Rollback if error occurs)
        questions = generate_questions_with_gemini(data['subject'], data['num_questions'])
        for idx, question in enumerate(questions):
            cursor.execute("""
                INSERT INTO Questions_Progress (test_id, question_id, question_text, answer_choices, correct_answer, progress_data)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (test_id, idx + 1, question['question'][:255], json.dumps(question['options']), question['answer'][:255], 'not_started'))

        # ✅ Step 4: Deduct `tests_left`
        cursor.execute("""
            UPDATE Users SET tests_left = tests_left - 1 WHERE user_id = %s AND tests_left > 0 RETURNING tests_left
        """, (creator_id,))
        updated_tests_left = cursor.fetchone()

        conn.commit()  # ✅ Commit everything if no error occurs
        return jsonify({
            "message": "Test finalized successfully!",
            "test_id": test_id,
            "pin": pin,
            "tests_left": updated_tests_left[0] if updated_tests_left else tests_left[0],
            "questions": questions
        }), 201

    except Exception as e:
        conn.rollback()  # ❌ Rollback all changes if anything fails
        return jsonify({"message": "Error finalizing test", "error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()



def is_test_expired(test_id):
    """Check if a test has expired based on its validity period."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT validity_period FROM Tests WHERE test_id = %s", (test_id,))
    expiry_date = cursor.fetchone()
    cursor.close()
    conn.close()

    if expiry_date and expiry_date[0]:
        return datetime.now() > expiry_date[0]
    return False


@app.route('/start_test', methods=['POST'])
def start_test():
    """Test-taker verifies PIN and starts the test."""
    data = request.json
    test_id = data['test_id'].strip()  # Trim spaces
    entered_pin = int(data['pin']) if isinstance(data['pin'], str) else data['pin']

    conn = get_db_connection()
    cursor = conn.cursor()

    if is_test_expired(test_id):
        return jsonify({"message": "The test has expired."}), 400

    # Fetch test details and validate PIN
    cursor.execute("SELECT pin, subject, time_limit, num_questions FROM Tests WHERE test_id = %s", (test_id,))
    test_data = cursor.fetchone()

    cursor.close()
    conn.close()

    if test_data:
        stored_pin, subject, time_limit, num_questions = test_data

        if stored_pin == entered_pin:
            test_taker_id = str(uuid.uuid4())  # Generate unique test-taker ID

            return jsonify({
                "message": "PIN verified. You can start the test!",
                "test_details": {
                    "subject": subject,
                    "time_limit": time_limit,
                    "num_questions": num_questions
                },
                "test_taker_id": test_taker_id
            }), 200

    return jsonify({"message": "Invalid test ID or PIN."}), 400


@app.route('/submit_test', methods=['POST'])
def submit_test():
    """Submit test and calculate score."""
    data = request.json
    test_id = data.get('test_id')

    if not test_id:
        return jsonify({"message": "Test ID is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch all selected answers for the test from Questions_Progress
        cursor.execute("""
            SELECT question_id, selected_answer, correct_answer 
            FROM Questions_Progress 
            WHERE test_id = %s
        """, (test_id,))
        answers = cursor.fetchall()

        score = sum(1 for row in answers if row[1] and row[2] and str(row[1]).strip() == str(row[2]).strip())

        # Update the score and test status in the Tests table
        cursor.execute("""
            UPDATE Tests SET score = %s, status = 'completed' WHERE test_id = %s
        """, (score, test_id))
        conn.commit()

        return jsonify({"message": "Test submitted successfully!", "score": score}), 200

    except Exception as e:
        conn.rollback()  # Rollback in case of an error
        return jsonify({"message": "Error submitting test", "error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


@app.route('/delete_test/<test_id>', methods=['DELETE'])
@jwt_required()
def delete_test(test_id):
    """Delete a test and its related questions."""
    creator_id = get_jwt_identity()  # Get user ID from JWT token
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the test exists and belongs to the creator
    cursor.execute("SELECT 1 FROM Tests WHERE test_id = %s AND creator_id = %s", (test_id, creator_id))
    test = cursor.fetchone()

    if not test:
        cursor.close()
        conn.close()
        return jsonify({"message": "Test not found or unauthorized access."}), 404

    try:
        # Delete related questions first
        cursor.execute("DELETE FROM Questions_Progress WHERE test_id = %s", (test_id,))
        conn.commit()

        # Now, delete the test
        cursor.execute("DELETE FROM Tests WHERE test_id = %s", (test_id,))
        conn.commit()

        return jsonify({"message": "Test deleted successfully!"}), 200

    except Exception as e:
        conn.rollback()  # Rollback in case of an error
        return jsonify({"message": "Error deleting test.", "error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


@app.route('/generate_and_download_pdf/<test_id>', methods=['GET'])
@jwt_required()
def generate_and_download_pdf(test_id):
    """Generate a test result PDF and send it as a downloadable file."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT test_taker_name, score 
            FROM Tests
            WHERE test_id = %s
        """, (test_id,))
        test_details = cursor.fetchone()

        if not test_details:
            return jsonify({"message": "Test not found"}), 404

        test_taker_name, score = test_details

        # Fetch test questions
        cursor.execute("""
            SELECT question_text, selected_answer, correct_answer 
            FROM Questions_Progress
            WHERE test_id = %s
        """, (test_id,))
        questions = cursor.fetchall()

        cursor.close()
        conn.close()

        # Define PDF storage directory
        output_dir = os.path.join(os.getcwd(), "static", "test_results")
        os.makedirs(output_dir, exist_ok=True)  # Ensure directory exists

        # Generate PDF file
        pdf_file_path = os.path.join(output_dir, f"{test_id}_result.pdf")
        c = canvas.Canvas(pdf_file_path, pagesize=letter)
        width, height = letter

        # Title and test details
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, height - 40, f"Test Results for {test_taker_name}")
        c.setFont("Helvetica", 12)
        c.drawString(100, height - 60, f"Test ID: {test_id}")
        c.drawString(100, height - 80, f"Score: {score}")
        c.line(50, height - 100, width - 50, height - 100)  # Line separator

        # Set position for questions
        y_position = height - 120
        c.setFont("Helvetica", 10)
        max_width = width - 150  # Max width for text wrapping

        for question_text, selected_answer, correct_answer in questions:
            wrapped_question = simpleSplit(question_text, "Helvetica", 10, max_width)
            wrapped_selected_answer = simpleSplit(f"Selected Answer: {selected_answer}", "Helvetica", 10, max_width)
            wrapped_correct_answer = simpleSplit(f"Correct Answer: {correct_answer}", "Helvetica", 10, max_width)

            for line in wrapped_question + wrapped_selected_answer + wrapped_correct_answer:
                if y_position < 80:  # Avoid overflow
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y_position = height - 40
                c.drawString(100, y_position, line)
                y_position -= 15

            y_position -= 30  # Space between questions

        c.save()

        return send_file(pdf_file_path, as_attachment=True, download_name=f"{test_id}_result.pdf")

    except Exception as e:
        return jsonify({"message": "Error generating PDF", "error": str(e)}), 500


@app.route('/get_test_questions', methods=['GET'])
def get_test_questions():
    """Fetch test questions for a given test ID."""
    test_id = request.args.get('test_id')

    if not test_id:
        return jsonify({"message": "Test ID is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT question_id, question_text, answer_choices, correct_answer
        FROM Questions_Progress
        WHERE test_id = %s
    """, (test_id,))
    questions = cursor.fetchall()

    cursor.close()
    conn.close()

    if not questions:
        return jsonify({"message": "No questions found for this test ID"}), 404

    # Format response
    formatted_questions = [
        {
            "id": row[0],
            "text": row[1],
            "options": json.loads(row[2]),  # Convert stored string to list
            "answer": row[3]
        }
        for row in questions
    ]

    return jsonify({"questions": formatted_questions}), 200


@app.route('/update_tests', methods=['POST'])
def update_tests():
    """Update the number of tests left for a user."""
    data = request.json
    user_id = data.get("user_id")
    num_tests = data.get("num_tests")

    if not user_id or not num_tests:
        return jsonify({"error": "Missing user_id or num_tests"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE Users 
            SET tests_left = COALESCE(tests_left, 0) + %s 
            WHERE user_id = %s
        """, (num_tests, user_id))

        if cursor.rowcount == 0:
            return jsonify({"error": "User not found"}), 404

        conn.commit()

        # Retrieve updated tests_left
        cursor.execute("SELECT tests_left FROM Users WHERE user_id = %s", (user_id,))
        updated_tests_left = cursor.fetchone()

        cursor.close()
        conn.close()

        return jsonify({"message": "Tests updated successfully", "tests_left": updated_tests_left[0]}), 200

    except Exception as e:
        return jsonify({"message": "Error updating tests", "error": str(e)}), 500


from flask_jwt_extended.exceptions import NoAuthorizationError
from werkzeug.exceptions import Unauthorized
from jwt.exceptions import ExpiredSignatureError  # ✅ Import from PyJWT

@app.errorhandler(NoAuthorizationError)
def handle_missing_token(error):
    print("🚨 JWT ERROR: No token found in request")
    return jsonify({"message": "Missing authentication token"}), 401

@app.errorhandler(ExpiredSignatureError)
def handle_expired_token(error):
    print("🚨 JWT ERROR: Token has expired")
    return jsonify({"message": "Token expired. Please log in again."}), 401

@app.errorhandler(Unauthorized)
def handle_invalid_token(error):
    print("🚨 JWT ERROR: Invalid token or unauthorized access")
    return jsonify({"message": "Invalid token or unauthorized request"}), 401


@app.route('/my_tests', methods=['GET'])
def my_tests():
    """Retrieve the list of tests created by the logged-in user."""

    auth_header = request.headers.get("Authorization")  # ✅ Debugging log
    print(f"Authorization Header: {auth_header}")

    if not auth_header:
        return jsonify({"message": "Missing Authorization Header"}), 401

    if not auth_header.startswith("Bearer "):
        return jsonify({"message": "Invalid Authorization Header Format"}), 401

    try:
        verify_jwt_in_request()  # Manually verify JWT
        creator_id = get_jwt_identity()  # Extract user ID from token
    except Exception as e:
        print(f"JWT Error: {str(e)}")  # ✅ Log JWT validation error
        return jsonify({"message": "Invalid or expired token", "error": str(e)}), 401

    if not creator_id:
        return jsonify({"message": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT tests_left FROM Users WHERE user_id = %s", (creator_id,))
    tests_left = cursor.fetchone()
    tests_left_value = tests_left[0] if tests_left else 0

    cursor.execute("""
        SELECT timestamp, test_id, test_taker_name, subject, score, status, pin, num_questions 
        FROM Tests WHERE creator_id = %s
    """, (creator_id,))
    tests = cursor.fetchall()

    column_names = [desc[0] for desc in cursor.description]
    test_list = [dict(zip(column_names, row)) for row in tests]

    cursor.close()
    conn.close()

    return jsonify({"tests": test_list, "tests_left": tests_left_value})




@app.route('/get_upi_id', methods=['GET'])
def get_upi_id():
    """Retrieve the UPI ID stored in environment variables."""
    if UPI_ID:
        return jsonify({"upi_id": UPI_ID})
    return jsonify({"message": "UPI ID not configured."}), 400


@app.route('/save_answer', methods=['POST'])
def save_answer():
    """Save test answers in the database."""
    data = request.json

    test_id = data['test_id']
    question_id = data['question_id']
    selected_answer = data['selected_answer']
    question_text = data['question_text']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Use `ON CONFLICT` instead of `MERGE INTO` (since PostgreSQL does not support `MERGE`)
    cursor.execute("""
        INSERT INTO Questions_Progress (test_id, question_id, question_text, selected_answer, progress_data)
        VALUES (%s, %s, %s, %s, 'answered')
        ON CONFLICT (test_id, question_id) 
        DO UPDATE SET selected_answer = EXCLUDED.selected_answer, progress_data = 'answered';
    """, (test_id, question_id, question_text, selected_answer))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Answer saved successfully!"}), 200



# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
