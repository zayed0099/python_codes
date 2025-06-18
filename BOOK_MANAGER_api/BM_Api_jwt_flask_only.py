import os
import requests
from flask import Flask, jsonify, request, url_for, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError, DBAPIError
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
db = SQLAlchemy(app)

app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)

# Database schema
class User(db.Model):
    __tablename__ = 'user_db'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    books = db.relationship('book_manager', backref='user', lazy=True)

class book_manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    author = db.Column(db.String(200), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user_db.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author
        }

with app.app_context():
    db.create_all()

@app.route("/signin", methods=["GET", "POST"])
def signin():
    data = request.get_json()

    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    elif 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing 'username' or 'password' fields"}), 400

    username = data.get("username")
    password = data.get("password")

    check_user = User.query.filter(User.username == username).first()

    if 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing 'username' or 'password' fields"}), 400

    elif check_user:
        return jsonify({"error": "Username already taken."}), 400


    new_hashed_pw_signin = generate_password_hash(password)

    new_user = User(username=username, password=new_hashed_pw_signin)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"Successful": "Now go to /login to login."}), 200
    except (SQLAlchemyError, DBAPIError) as e:
        print(f"Database error: {e}")
        db.session.rollback() 


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if data is None:
        return jsonify({"error": "Invalid JSON or missing Content-Type: application/json"}), 400
    elif 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing 'username' or 'password' fields"}), 400

    username = data.get("username")
    password = data.get("password")

    check_user = User.query.filter(User.username == username).first()

    if check_user and check_password_hash(check_user.password , password):
        access_token = create_access_token(identity=check_user.id)
        return jsonify(access_token=access_token)        
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route("/api/v1/books")
@jwt_required()
def show_books():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        current_user_id = get_jwt_identity()

        pagination = book_manager.query.filter(book_manager.user_id == current_user_id).paginate( page=page, per_page=per_page, error_out=False)
        books = [book.to_dict() for book in pagination.items]

        return jsonify ({
            "page" : page,
            "per_page" : per_page,
            "total": pagination.total,
            "pages": pagination.pages,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev,
            "books" : books
            })
        
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route("/api/v1/books/add", methods=["GET", "POST"])
@jwt_required()
def add_books():
    if request.method == "POST":
        try:
            data = request.get_json()
        except BadRequest as e:
            return jsonify({"error": "Invalid Content-Type. Expected 'application/json'", "details": str(e)}), 400

        if not data or 'title' not in data or 'author' not in data:
            return jsonify({"message": "Invalid data"}), 400

        else:
            new_book = book_manager(title=data['title'], author=data['author'], user_id = get_jwt_identity())
            
            try:
                db.session.add(new_book)
                db.session.commit()
                return jsonify({"message": "Book added successfully."}), 200
            except (SQLAlchemyError, DBAPIError) as e:
                print(f"Database error: {e}")
                db.session.rollback()
    
    else:
        return jsonify({"message": "You can use this route to send POST requests."}), 200
  

@app.route("/api/v1/books/<int:id>", methods=["GET", "PUT", "DELETE"])
@jwt_required()
def edit_dlt(id):
    try:
        book_to_work = db.session.get(book_manager, id)
    except SQLAlchemyError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    if request.method == "PUT":
        try:
            data = request.get_json()
        except BadRequest as e:
            return jsonify({"error": "Invalid Content-Type. Expected 'application/json'", "details": str(e)}), 400

        if not data or 'title' not in data or 'author' not in data:
            return jsonify({"message": "Invalid data"}), 400

        else:
            book_to_work.title = data['title']
            book_to_work.author = data['author']
            
            try:
                db.session.commit()
                return jsonify({'message': 'Book updated successfully'}), 200
            except (SQLAlchemyError, DBAPIError) as e:
                print(f"Database error: {e}")
                db.session.rollback()

    elif request.method == "DELETE":
        try:
            db.session.delete(book_to_work)
            db.session.commit()
            return jsonify({'message': 'Book deleted successfully'}), 200
        except (SQLAlchemyError, DBAPIError) as e:
            print(f"Database error: {e}")
            db.session.rollback()
    
    else:
        return jsonify(book_to_work.to_dict()), 200

@app.route('/api/v1/info')
def info():
    message = (
        "Welcome to the Book Manager API!\n"
        "Here’s what you can do:\n"
        "- Add new books using POST /api/v1/books/add\n"
        "- Get all books using GET /api/v1/books\n"
        "- Update a book using PUT /api/v1/books/<id>\n"
        "- Delete a book using DELETE /api/v1/books/<id>\n"
        "Make sure to send JSON data with the correct fields."
    )

    return jsonify({"message": message}), 200

if __name__ == "__main__":
    app.run(debug=True)

    # get url = http://127.0.0.1:5000/api/v1/books