import os
from flask import Flask, request, jsonify, abort
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, validate
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, create_refresh_token, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
api = Api(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
db = SQLAlchemy(app)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)

def get_user_identifier():
    try:
        verify_jwt_in_request(optional=True)
        return str(get_jwt_identity() or get_remote_address())
    except Exception:
        return get_remote_address()

limiter = Limiter(
    key_func = get_user_identifier,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",    
    )

# User class
class User(db.Model):
    __tablename__ = 'user_db'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    books = db.relationship('book_manager', backref='user', lazy=True)

# Book Manager class with indexing.
class book_manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    author = db.Column(db.String(200), nullable=False)
    normalized_title = db.Column(db.String(200), nullable=False, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user_db.id'), nullable=False)

with app.app_context():
    db.create_all()

# schema for marshmallow to automate data validation
class BookSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(required=True, validate=validate.Length(min=1))
    author = fields.Str(required=True, validate=validate.Length(min=1))

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True, validate=validate.Length(min=1))
    password = fields.Str(required=True, validate=validate.Length(min=8))    

book_schema = BookSchema() # for a single book
books_schema = BookSchema(many=True) # for multiple books
user_schema = UserSchema(many=False)

class CustomBadrequest(BadRequest):
    def __init__(self, message):
        self.description = message
        super().__init__()

@app.errorhandler(CustomBadrequest)
def no_data_error(err):
    return {"message": err.description}, 400

# User sign-up class
class AddUser(Resource):
    @limiter.limit("3 per day")
    def post(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        errors = user_schema.validate(data)

        if errors:
            raise CustomBadRequest("Validation failed: " + str(errors))

        else:
            username_signin = data.get("username")
            pass_txt_signin = data.get("password")

            check_user = User.query.filter(User.username == username_signin).first()

            if check_user:
                raise CustomBadRequest("Username already taken.")
            else:
                new_hashed_pw_signin = generate_password_hash(pass_txt_signin)

                new_user = User(username=username_signin, password=new_hashed_pw_signin)

                try:
                    db.session.add(new_user)
                    db.session.commit()
                    return {"Successful": "Head to '/login' to login and start using the api."}, 200
                except (SQLAlchemyError, DBAPIError):
                    db.session.rollback()
                    return {"error": "Failed to save entry to database"}, 500

# User login class
class Login(Resource):
    @limiter.limit("3 per day")
    def post(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        errors = user_schema.validate(data)

        if errors:
            raise CustomBadRequest("Validation failed: " + str(errors))

        else:
            username_for_login = data.get("username")
            pass_txt_login = data.get("password")

            check_user = User.query.filter(User.username == username_for_login).first()

            if not check_user:
                return {"message": "An error occured"}, 404

            else:
                if check_user and check_password_hash(check_user.password , pass_txt_login):
                    access_token = create_access_token(identity=check_user.id)
                    refresh_token = create_refresh_token(identity=check_user.id)
                    return {"access_token": access_token, "refresh_token": refresh_token}, 200        
                else:
                    return {"message": "Bad username or password. Login unsuccessful"}, 401

# JWT protected class to only get access token using the refresh token
class Ref_Token(Resource):
    @limiter.limit("5 per day")
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return {"access_token" : access_token}

# JWT protected class to only get all books and add new books
class Book_CR(Resource):
    method_decorators = [jwt_required()]
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        title = request.args.get('title', '', type=str)
        author = request.args.get('author', '', type=str)

        current_user_id = get_jwt_identity()
        
        filters = [book_manager.user_id == current_user_id]

        if title and author:
            filters.append(book_manager.normalized_title == title)
            filters.append(book_manager.author == author)
        elif author:
            filters.append(book_manager.author == author)
        elif title:
            filters.append(book_manager.normalized_title == title)
        
        pagination = book_manager.query.filter(*filters).paginate(
            page=page, per_page=per_page, error_out=False)

        if not pagination.items:
            return {"message": "No books found"}, 404

        else:
            books =  books_schema.dump(pagination.items)

            return {
            'books': books,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_items': pagination.total,
            'total_pages': pagination.pages
            }, 200

    @limiter.limit("50 per day")
    def post(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")
        
        errors = book_schema.validate(data)

        if errors:
            raise CustomBadRequest("Validation failed: " + str(errors))

        else:
            title = data.get("title")
            author = data.get("author")

            normalized_title = title.lower().strip()

            new_book = book_manager(title=title, author=author, normalized_title=normalized_title, user_id=get_jwt_identity())
            try:
                db.session.add(new_book)
                db.session.commit()
                return book_schema.dump(new_book), 201
            except (SQLAlchemyError, DBAPIError):
                db.session.rollback()
                return {"error": "Failed to save entry to database"}, 500
            
# JWT protected class to update, delete and get book by id.
class Book_RUD(Resource):
    method_decorators = [jwt_required()]
    def get(self, id):
        current_user_id = get_jwt_identity()
        book_to_work = book_manager.query.filter_by(user_id=current_user_id, id=id).first()        
        
        if not book_to_work:
            return {"message" : "No Book found for this user"}, 404
        else:
            return (book_schema.dump(book_to_work)), 200

    @limiter.limit("50 per day")
    def put(self, id):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")
        
        errors = book_schema.validate(data)

        if errors:
            raise CustomBadRequest("Validation failed: " + str(errors))
            
        else:
            current_user_id = get_jwt_identity()
            
            book_to_work = book_manager.query.filter_by(user_id=current_user_id, id=id).first()
            
            if not book_to_work:
                return {"message" : "No Book found for this user"}, 404

            try:
                book_to_work.title = data['title']
                book_to_work.author = data['author'] 
                db.session.commit()
                return {"message" : "Updated Successfully"}, 200 
            except (SQLAlchemyError, DBAPIError):
                db.session.rollback()
                return {"error": "Failed to save entry to database"}, 500
    
    @limiter.limit("50 per day")
    def delete(self, id):
        current_user_id = get_jwt_identity()
            
        book_to_work = book_manager.query.filter_by(user_id=current_user_id, id=id).first()
        if not book_to_work:
            return {"message": "Book not found"}, 404

        try:    
            db.session.delete(book_to_work)
            db.session.commit()
            return {"message" : "Deleted Successfully"}, 200
        except (SQLAlchemyError, DBAPIError):
            db.session.rollback()
            return {"error": "Failed to delete entry from database"}, 500


api.add_resource(Book_CR, '/api/v1/books/', endpoint='view')  # For Create & Read (all)
api.add_resource(Book_RUD, '/api/v1/books/<int:id>', endpoint='edit_delete')  # For Read (one), Update, Delete
api.add_resource(AddUser, '/api/v1/signin', endpoint='signin')
api.add_resource(Login, '/api/v1/login', endpoint='login')
api.add_resource(Ref_Token, '/api/v1/refresh', endpoint='ref_token')

if __name__ == "__main__":
    app.run(debug=True)


'''
uri for curl
get/post - http://127.0.0.1:5000/api/v1/books/
rud = http://127.0.0.1:5000/api/v1/books/id


curl script to post--
curl -X POST -H "Content-Type: application/json" -d '{"title": "testing book 3", "author": "mojo khao"}' http://127.0.0.1:5000/api/v1/books/

'''
