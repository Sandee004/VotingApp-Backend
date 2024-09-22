from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Message, Mail
from flask_cors import CORS
#from dotenv import load_dotenv
from datetime import timedelta, datetime
import random
import string
import bcrypt
import os

#load_dotenv()
app = Flask(__name__)
#app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_SECRET_KEY"] = "fish"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mydatabase.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("EMAIL")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

mail = Mail(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    orgtype = db.Column(db.String(20))
    orgname = db.Column(db.String(100), nullable=False)

    elections = db.relationship('Elections', backref='user', lazy=True)  # Relationship with Elections table

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)  

class Elections(db.Model):
    id = db.Column(db.String(5), primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    startDate = db.Column(db.DateTime, nullable=False)
    endDate = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
questions = db.relationship('Questions', backref='election', lazy=True)


class Questions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(500), nullable=False)
    question_type = db.Column(db.String(50), nullable=False)  # e.g., 'multiple_choice', 'text', etc.
    options = db.Column(db.JSON)  # For storing multiple choice options
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'), nullable=False)


class Responses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.String(5), db.ForeignKey('elections.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    response = db.Column(db.String(500), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)


@app.route("/")
def home():
    return "Holla"

@app.route("/api/signup", methods=["POST"])
def signup():
    username = request.json.get("username")
    email = request.json.get("email")
    password = request.json.get("password")
    orgtype = request.json.get("type")
    orgname = request.json.get("orgname")
    
    if not username or not email or not password or not orgtype or not orgname:
        return jsonify({"message":"Fill all fields"}), 400
    
    if Users.query.filter_by(email=email).first():
        return jsonify({"message": "Email is already in use"}), 400
    
    new_user = Users(username=username, email=email, orgtype=orgtype, orgname=orgname)
    new_user.set_password(password)
    #new_user = Users(username=username, email=email, password=password, orgtype=orgtype)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201
    

@app.route("/api/login", methods=["POST", "GET"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Missing username or email'}), 400 

    email = data.get('email')
    password = data.get('password')

    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Account does not exist"}), 404
    
    if user.email != email or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200


@app.route('/api/election', methods=["POST", "GET"])
@jwt_required()
def election():
    user_id = get_jwt_identity()
    if request.method == "POST":
        title = request.json.get("title")
        startDate = datetime.strptime(request.json.get("startDate"), "%Y-%m-%d")
        endDate = datetime.strptime(request.json.get("endDate"), "%Y-%m-%d")

        election_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

        new_election = Elections(id=election_id, title=title, startDate=startDate, endDate=endDate, user_id=user_id)
        db.session.add(new_election)
        db.session.commit()

        response_data = {
            "message": "Election created successfully",
            "id": new_election.id  # Add the ID to the response data
        }

        return jsonify(response_data), 201
    
    if request.method == "GET":
        user_elections = Elections.query.filter_by(user_id=user_id).all()
    
        elections_data = []
        for election in user_elections:
            elections_data.append({
                'id': election.id,
                'title': election.title,
                'startDate': election.startDate.isoformat(),
                'endDate': election.endDate.isoformat()
            })
    
        return jsonify(elections_data), 200


@app.route('/api/questions', methods=["POST", "GET"])
@jwt_required()
def manage_questions():
    user_id = get_jwt_identity()
    
    if request.method == "POST":
        questions_data = request.get_json()
        print(questions_data)

        # Validate data and extract election_ids
        election_ids = []
        for question_data in questions_data:
            if not question_data.get('election_id') or not question_data.get('question_text') or not question_data.get('question_type') or not question_data.get('options'):
                return jsonify({"message": "Invalid data format"}), 400

            election_ids.append(question_data['election_id'])

        # Verify election ownership
        for election_id in election_ids:
            election = Elections.query.filter_by(id=election_id, user_id=user_id).first()
            if not election:
                return jsonify({"message": "Election not found or unauthorized"}), 404

        # Create questions
        for question_data in questions_data:
            new_question = Questions(
                question_text=question_data['question_text'],
                question_type=question_data['question_type'],
                options=question_data['options'],
                election_id=question_data['election_id']
            )
            print(new_question)
            db.session.add(new_question)
        db.session.commit()

        return jsonify({"message": "Questions added successfully"}), 201

    if request.method == "GET":
        election_id = request.args.get("election_id")
        
        # Verify that the election belongs to the current user
        election = Elections.query.filter_by(id=election_id, user_id=user_id).first()
        
        if not election:
            return jsonify({"message": "Election not found or unauthorized"}), 404

        questions = Questions.query.filter_by(election_id=election_id).all()
        questions_data = []
        for question in questions:
            questions_data.append({
                'id': question.id,
                'question_text': question.question_text,
                'question_type': question.question_type,
                'options': question.options
            })
        
        return jsonify(questions_data), 200


@app.route('/api/preview', methods=['GET'])
@jwt_required()
def preview():
    user_id = get_jwt_identity()
    user = Users.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    election_id = request.args.get('electionId')
    if not election_id:
        return jsonify({"message": "Election ID is required"}), 400

    election = Elections.query.filter_by(id=election_id, user_id=user_id).first()
    if not election:
        return jsonify({"message": "Election not found or unauthorized"}), 404

    questions = Questions.query.filter_by(election_id=election_id).all()

    user_info = {
        "id": user.id,
        "orgname": user.orgname,
        "election": {
            "id": election.id,
            "title": election.title,
            "questions": [
                {
                    "id": q.id,
                    "question_text": q.question_text,
                    "question_type": q.question_type,
                    "options": q.options
                } for q in questions
            ]
        }
    }

    return jsonify(user_info), 200


@app.route('/api/submit_ballot', methods=['POST'])
#@jwt_required()
def submit_ballot():
    print("Me? Sharp")
    #user_id = get_jwt_identity()
    data = request.json
    print("Got data")
    election_id = data.get('election_id')
    responses = data.get('responses')
    print("Checks now")

    if not election_id or not responses:
        return jsonify({"message": "Invalid data"}), 400

    # Check if the election exists and is ongoing
    election = Elections.query.get(election_id)
    if not election:
        return jsonify({"message": "Election not found"}), 404

    """current_time = datetime.utcnow()
    if current_time < election.startDate or current_time > election.endDate:
        return jsonify({"message": "Election is not active"}), 400
"""
    # Save responses
    for response in responses:
        question_id = response.get('question_id')
        answer = response.get('answer')
        new_response = Responses(
            election_id=election_id,
            question_id=question_id,
            response=answer
        )
        db.session.add(new_response)

    db.session.commit()
    return jsonify({"message": "Ballot submitted successfully"}), 201

@app.route('/api/results/<election_id>', methods=['GET'])
@jwt_required()
def get_results(election_id):
    user_id = get_jwt_identity()
    election = Elections.query.filter_by(id=election_id, user_id=user_id).first()

    if not election:
        return jsonify({"message": "Election not found or unauthorized"}), 404

    questions = Questions.query.filter_by(election_id=election_id).all()
    results = {}
    total_votes = Responses.query.filter_by(election_id=election_id).count()

    for question in questions:
        responses = Responses.query.filter_by(election_id=election_id, question_id=question.id)
        
        if question.question_type == 'multiple_choice':
            option_counts = {option: 0 for option in question.options}
            vote_counts = responses.with_entities(Responses.response, func.count(Responses.id)).group_by(Responses.response).all()
            
            for response, count in vote_counts:
                option_counts[response] = count

            results[question.id] = {
                'question_text': question.question_text,
                'type': 'multiple_choice',
                'results': option_counts,
                'total_votes': total_votes
            }
        elif question.question_type == 'text':
            text_responses = [response.response for response in responses.all()]
            results[question.id] = {
                'question_text': question.question_text,
                'type': 'text',
                'results': text_responses,
                'total_votes': total_votes
            }

    return jsonify(results), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

