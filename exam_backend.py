import uuid

from flask import Flask, request, jsonify, send_from_directory, session, send_file
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import JWTManager
import os
import random
import string
import re
from dotenv import load_dotenv
import requests
import json
import pyodbc
from datetime import datetime, timedelta

import bcrypt

app = Flask(__name__)
CORS(app)

load_dotenv()

UPI_ID = os.getenv("UPI_ID")
def get_db_connection():
    # Get the connection string from the environment
    conn = pyodbc.connect(
        f"DRIVER={os.getenv('DB_DRIVER')};"
        f"SERVER={os.getenv('DB_SERVER')};"
        f"DATABASE={os.getenv('DB_NAME')};"
        f"UID={os.getenv('DB_USER')};"
        f"PWD={os.getenv('DB_PASSWORD')};"
        f"Encrypt={os.getenv('DB_ENCRYPT')};"
        f"TrustServerCertificate={os.getenv('DB_TRUST_CERT')};"
    )
    return conn

app.config["JWT_SECRET_KEY"] = "your_secret_key"  # Change this to a strong secret key
jwt = JWTManager(app)



def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')




def is_valid_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email) is not None


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


# Endpoint for user registration
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

        # 2ï¸â£ **Check if password is strong**
    if not is_strong_password(password):
        return jsonify({
                           "message": "Weak password. Must be at least 8 characters, include uppercase, lowercase, a number, and a special character."}), 400

    if not is_valid_mobile(mobile_number):
        return jsonify({"message": "Invalid mobile number format."}), 400
    # Hash the user's password
    hashed_password = hash_password(password)

    # Check if the email already exists
    cursor.execute("SELECT * FROM Users WHERE email = ?", email)
    existing_user = cursor.fetchone()

    if existing_user:
        return jsonify({"message": "Email already exists."}), 400

    def generate_username(email):
        base = email.split("@")[0]  # Get text before @ in email
        random_suffix = ''.join(random.choices(string.digits, k=4))  # Random 4-digit number
        return f"{base}{random_suffix}"

    username = generate_username(email)

    # Insert new user into the database
    cursor.execute("""
                 INSERT INTO Users (username, email, password, mobile_number, last_login, active)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, email, hashed_password, mobile_number, None, True))
    conn.commit()

    return jsonify({"message": "User registered successfully!"}), 201

# Mock database to store test and PIN details
tests = {}

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # This route is protected, meaning the user needs a valid token to access it
    current_user = get_jwt_identity()  # Get the identity from the token
    return jsonify({"message": f"Hello, user {current_user}!"}), 200


@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve the user from the database using email
    cursor.execute("SELECT user_id, password FROM Users WHERE email = ?", email)
    user = cursor.fetchone()
    print(user)

    if user:
        # Compare the hashed password with the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):

            access_token = create_access_token(identity=user[0],expires_delta=timedelta(minutes=15) )
            print(user[0])
            return jsonify({
                "message": "Login successful!",
                "access_token": access_token,
                "user_id": user[0]

            }), 200
        else:
            return jsonify({"message": "Invalid email or password."}), 400
    else:
        return jsonify({"message": "User not found."}), 404


# Function to generate a random PIN
def generate_pin():
    return ''.join(random.choices(string.digits[1:], k=6))


# Function to generate questions using Gemini AI API
def generate_questions_with_gemini(subject, num_questions):
    api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    api_key = "AIzaSyABCZQ8cKtv8zd88mQGJAlpj_WJCPpbaJE"  # Replace with your actual API key

    prompt = f"Generate {num_questions} multiple-choice questions for the subject: {subject}. Each question should have 4 options, with one correct answer clearly marked.""Provide the output in JSON format, where each question contains: 'question', 'options', and 'answer'."

    headers = {
        "Content-Type": "application/json",
    }

    data = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    try:
        response = requests.post(f"{api_url}?key={api_key}", headers=headers, json=data)
        response.raise_for_status()

        response_data = response.json()

        if "candidates" in response_data and response_data["candidates"]:
            raw_text = response_data["candidates"][0]["content"]["parts"][0]["text"]

            if raw_text.startswith("```json") and raw_text.strip().endswith("```"):

                raw_text = raw_text[7:-4].strip()


            questions = json.loads(raw_text)
            return questions
        else:
            print("No content received in the API response.")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return []



# Endpoint for generating questions using Gemini AI API
@app.route('/generate_questions', methods=['POST'])
@jwt_required()  # You can remove the jwt_required if authentication is not needed
def generate_questions():
    data = request.json
    subject = data.get('subject')
    num_questions = data.get('num_questions')

    # Ensure the subject and num_questions are provided
    if not subject or not num_questions:
        return jsonify({"message": "Subject and number of questions are required."}), 400

    # Generate questions using Gemini AI
    questions = generate_questions_with_gemini(subject, num_questions)

    if not questions:
        return jsonify({"message": "Failed to generate questions."}), 500

    return jsonify({
        "message": "Questions generated successfully!",
        "questions": questions
    }), 200

@app.route("/get_test_details", methods=["GET"])
def get_test_details():
    test_id = request.args.get("test_id")

    if not test_id:
        return jsonify({"error": "Missing test_id"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT num_questions, time_limit, pin,status,score FROM Tests WHERE test_id = ?", (test_id,))
    result = cursor.fetchone()

    if result:
        return jsonify({
            "num_questions": result[0],
            "time_limit": result[1],
            "pin": result[2],
            "status":result[3],
            "score":result[4]
        }), 200
    else:
        return jsonify({"error": "Test not found"}), 404

# Endpoint to create a test and generate a link with PIN
@app.route('/create_test', methods=['POST'])
@jwt_required()
def create_test():
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
    data = request.json
    creator_id = get_jwt_identity()
    test_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    pin = generate_pin()

    conn = get_db_connection()
    cursor = conn.cursor()

    validity_period = data.get("validity_period")  # â Get validity period from frontend
    if validity_period:
        validity_period = datetime.strptime(validity_period, "%Y-%m-%dT%H:%M")

        # Generate questions using Gemini AI
    questions = generate_questions_with_gemini(data['subject'], data['num_questions'])

    cursor.execute("""
        INSERT INTO Tests (test_id, creator_id, subject, num_questions, time_limit, status, test_taker_name, pin,validity_period,timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, test_id, creator_id, data['subject'], data['num_questions'], data['time_limit'], 'open',
                   data['test_taker_name'], pin,validity_period,datetime.now())
    conn.commit()

    # Insert generated questions into the database
    for idx, question in enumerate(questions):
        cursor.execute("""
            INSERT INTO Questions_Progress (test_id, question_id, question_text, answer_choices, correct_answer, progress_data)
            VALUES (?, ?, ?, ?, ?, ?)
        """, test_id, idx + 1, question['question'], ','.join(question['options']), question['answer'],
                       'not_started')
    conn.commit()

    return jsonify({
        "message": "Questions generated successfully!",
        "test_id": test_id,
        "pin": pin,
        "questions": questions
    }), 201


def is_test_expired(test_id):
    conn1 = get_db_connection()
    cursor1 = conn1.cursor()
    cursor1.execute("SELECT validity_period FROM Tests WHERE test_id = ?", test_id)
    expiry_date = cursor1.fetchone()
    cursor1.close()
    conn1.close()
    if expiry_date:
        return datetime.now() > expiry_date[0]
    return False



# Endpoint for test-taker to verify PIN and start the test
@app.route('/start_test', methods=['POST'])
def start_test():
    data = request.json
    test_id = data['test_id'].strip()  # Trim spaces
    entered_pin = int(data['pin']) if isinstance(data['pin'], str) else data['pin']

    conn = get_db_connection()
    cursor = conn.cursor()
    if is_test_expired(test_id):
        return jsonify({"message": "The test has expired."}), 400

    # Fetch test details and validate PIN
    cursor.execute("SELECT pin, subject, time_limit, num_questions FROM Tests WHERE test_id = ?", (test_id,))
    test_data = cursor.fetchone()

    if test_data:
        stored_pin, subject, time_limit, num_questions = test_data

        if stored_pin == entered_pin:
            # Generate unique test-taker ID
            test_taker_id = str(uuid.uuid4())

            return jsonify({
                "message": "PIN verified. You can start the test!",
                "test_details": {
                    "subject": subject,
                    "time_limit": time_limit,
                    "num_questions": num_questions
                },
                "test_taker_id": test_taker_id
            }), 200
        else:
            return jsonify({"message": "Invalid test ID or PIN."}), 400
    else:
        return jsonify({"message": "Invalid test ID or PIN."}), 400

@app.route('/submit_test', methods=['POST'])
def submit_test():
    data = request.json
    test_id = data.get('test_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    if not test_id:
        return jsonify({"message": "Test ID is required"}), 400

    try:
        conn1 = get_db_connection()
        cursor1 = conn1.cursor()  # Create a new cursor instance

        # Fetch all selected answers for the test from Questions_Progress
        cursor1.execute("""
            SELECT question_id, selected_answer, correct_answer 
            FROM Questions_Progress 
            WHERE test_id = ?
        """, (test_id,))
        answers = cursor1.fetchall()

        score = 0

        # Calculate the score
        for row in answers:
            question_id, selected_answer, correct_answer = row

            if selected_answer and correct_answer:  # Ensure both values are not None
                if str(selected_answer).strip() == str(correct_answer).strip():
                    score += 1

        # Update the score and test status in the Tests table
        cursor1.execute("""
            UPDATE Tests SET score = ?, status = 'completed' WHERE test_id = ?
        """, (score, test_id))
        conn1.commit()



        return jsonify({"message": "Test submitted successfully!", "score": score}), 200

    except Exception as e:
        return jsonify({"message": "Error submitting test", "error": str(e)}), 500

    finally:
        cursor.close()  # Ensure cursor is closed after execution


# Delete Test API
@app.route('/delete_test/<test_id>', methods=['DELETE'])
@jwt_required()
def delete_test(test_id):
    creator_id = get_jwt_identity()  # Get user ID from JWT token
    conn = get_db_connection()
    cursor = conn.cursor()
    # Check if the test exists and belongs to the creator
    cursor.execute("SELECT * FROM Tests WHERE test_id = ? AND creator_id = ?", test_id, creator_id)
    test = cursor.fetchone()

    if not test:
        return jsonify({"message": "Test not found or unauthorized access."}), 404

    try:
        # Delete related questions first (to avoid foreign key constraint issues)
        cursor.execute("DELETE FROM Questions_Progress WHERE test_id = ?", test_id)
        conn.commit()  # Commit deletion of related records

        # Now, delete the test
        cursor.execute("DELETE FROM Tests WHERE test_id = ?", test_id)
        conn.commit()

        return jsonify({"message": "Test deleted successfully!"}), 200

    except Exception as e:
        conn.rollback()  # Rollback in case of an error
        return jsonify({"message": "Error deleting test.", "error": str(e)}), 500


from flask import send_file, jsonify
from flask_jwt_extended import jwt_required
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
import os

@app.route('/generate_and_download_pdf/<test_id>', methods=['GET'])
@jwt_required()
def generate_and_download_pdf(test_id):
    try:
        # Connect to the database
        conn1 = get_db_connection()
        cursor1 = conn1.cursor()

        cursor1.execute("""
                    SELECT test_taker_name, score 
                    FROM Tests
                    WHERE test_id = ?
                """, (test_id,))
        test_details = cursor1.fetchone()
        if not test_details:
            return jsonify({"message": "Test not found"}), 404

        test_taker_name, score = test_details

        # Fetch the relevant data for the given test_id from Questions_Progress
        cursor1.execute("""
            SELECT question_text, selected_answer, correct_answer 
            FROM Questions_Progress
            WHERE test_id = ?
        """, (test_id,))
        questions = cursor1.fetchall()

        # Define the directory where PDFs will be stored
        output_dir = '../examCode/static/test_results'

        # Check if the directory exists, and create it if it doesn't
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Generate the PDF file and save it to the specified directory
        pdf_file_path = os.path.join(output_dir, f'{test_id}_result.pdf')

        c = canvas.Canvas(pdf_file_path, pagesize=letter)
        width, height = letter  # Default letter size page

        # Add title and test details
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, height - 40, f"Test Results for {test_taker_name}")
        c.setFont("Helvetica", 12)
        c.drawString(100, height - 60, f"Test ID: {test_id}")
        c.drawString(100, height - 80, f"Score: {score}")

        # Add a line to separate the header
        c.line(50, height - 100, width - 50, height - 100)

        # Set position for question and answers
        y_position = height - 120
        c.setFont("Helvetica", 10)

        max_width = width - 150  # Max width for text wrapping

        for question_text, selected_answer, correct_answer in questions:
            # Wrap text to fit within the page width
            wrapped_question = simpleSplit(question_text, "Helvetica", 10, max_width)
            wrapped_selected_answer = simpleSplit(f"Selected Answer: {selected_answer}", "Helvetica", 10, max_width)
            wrapped_correct_answer = simpleSplit(f"Correct Answer: {correct_answer}", "Helvetica", 10, max_width)

            for line in wrapped_question:
                if y_position < 80:  # Prevents text overflow
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y_position = height - 40
                c.drawString(100, y_position, line)
                y_position -= 15  # Adjust line spacing

            y_position -= 10  # Extra spacing before answers

            for line in wrapped_selected_answer:
                if y_position < 80:
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y_position = height - 40
                c.drawString(100, y_position, line)
                y_position -= 15

            for line in wrapped_correct_answer:
                if y_position < 80:
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y_position = height - 40
                c.drawString(100, y_position, line)
                y_position -= 15

            y_position -= 30  # Space between questions

        # Save the PDF to file
        c.save()

        # Send the generated PDF file to the user for download
        return send_file(pdf_file_path, as_attachment=True, download_name=f'{test_id}_result.pdf')

    except Exception as e:
        return jsonify({"message": "Error generating PDF", "error": str(e)}), 500


@app.route('/get_test_questions', methods=['GET'])
def get_test_questions():
    test_id = request.args.get('test_id')  # Get test_id from query parameters
    conn = get_db_connection()
    cursor = conn.cursor()
    if not test_id:
        return jsonify({"message": "Test ID is required"}), 400

    # Fetch questions for the given test_id from Questions_Progress
    cursor.execute("""
        SELECT question_id, question_text, answer_choices, correct_answer
        FROM Questions_Progress
        WHERE test_id = ?
    """, test_id)

    questions = cursor.fetchall()

    if not questions:
        return jsonify({"message": "No questions found for this test ID"}), 404

    # Format the questions for the frontend
    formatted_questions = []
    for row in questions:
        question = {
            "id": row[0],
            "text": row[1],
            "options": row[2].split(','),  # Assuming answer_choices is stored as a comma-separated string
            "answer": row[3]
        }
        formatted_questions.append(question)

    return jsonify({"questions": formatted_questions}), 200

@app.route('/update_tests', methods=['POST'])
def update_tests():
    data = request.json
    user_id = data.get("user_id")
    num_tests = data.get("num_tests")


    if not user_id or not num_tests:
        return jsonify({"error": "Missing user_id or num_tests"}), 400

    update_query = """
        SET NOCOUNT OFF;
        UPDATE Users SET tests_left = COALESCE(tests_left, 0) + ? WHERE user_id = ?;
    """

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(update_query, (num_tests, user_id))
        print(f"â Rows affected: {cursor.rowcount}")
        conn.commit()

        # ð¹ Verify update with SELECT query
        cursor.execute("SELECT tests_left FROM Users WHERE user_id = ?", (user_id,))
        updated_tests_left = cursor.fetchone()

        if updated_tests_left:

            return jsonify({"message": "Tests updated successfully", "tests_left": updated_tests_left[0]}), 200
        else:

            return jsonify({"error": "User not found"}), 404

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
        print("ð¹ Connection Closed")

@app.route('/my_tests', methods=['GET'])
@jwt_required()
def my_tests():
    creator_id = get_jwt_identity()  # Get user ID from JWT token
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch tests_left
    cursor.execute("SELECT tests_left FROM Users WHERE user_id = ?", (creator_id,))
    tests_left = cursor.fetchone()
    tests_left_value = tests_left[0] if tests_left else 0  # Extract integer value or default to 0

    # Fetch tests
    cursor.execute(
        "SELECT timestamp, test_id, test_taker_name, subject, score, status, pin, num_questions FROM Tests WHERE creator_id = ?",
        (creator_id,))
    tests = cursor.fetchall()

    # Convert test records to a list of dictionaries
    column_names = [column[0] for column in cursor.description]  # Extract column names once
    test_list = [dict(zip(column_names, row)) for row in tests]  # Properly structure test data

    cursor.close()
    conn.close()

    return jsonify({
        "tests": test_list,  # Now contains only test details
        "tests_left": tests_left_value  # Correctly placed outside "tests"
    })


@app.route('/get_upi_id', methods=['GET'])
def get_upi_id():
    print(UPI_ID)
    return jsonify({"upi_id": UPI_ID})

@app.route('/save_answer', methods=['POST'])
def save_answer():
    data = request.json
 # Retrieve test_taker_id from session


    test_id = data['test_id']
    question_id = data['question_id']
    selected_answer = data['selected_answer']
    question_text = data['question_text']
    conn = get_db_connection()
    cursor = conn.cursor()
    # Store answer in Questions_Progress table
    cursor.execute("""
            MERGE INTO Questions_Progress AS target
            USING (SELECT ? AS test_id, ? AS question_id, ? AS question_text, ? AS selected_answer, ? AS progress_data) AS source
            ON target.test_id = source.test_id AND target.question_id = source.question_id
            WHEN MATCHED THEN
                UPDATE SET target.selected_answer = source.selected_answer, target.progress_data = source.progress_data
            WHEN NOT MATCHED THEN
                INSERT (test_id, question_id, question_text, selected_answer, progress_data)
                VALUES (source.test_id, source.question_id, source.question_text, source.selected_answer, source.progress_data);
        """, (test_id, question_id, question_text, selected_answer, 'answered'))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Answer saved successfully!"}), 200


# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
