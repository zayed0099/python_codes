# filename: __init__.py
from flask import Flask
import os
from flask_restful import Api

# Local Import
from app.errors.handlers import register_error_handlers
from app.routes.auth_routes import auth_bp
from app.routes.book_routes import book_bp
from app.routes.admin_routes import admin_bp
from app.extensions import db
from .config import Config, dbconfig, jwt_config
from app.jwt_extensions import jwt, limiter

def create_app():
    app = Flask(__name__)
    api = Api(app)

    app.config.from_object(Config)
    app.config.from_object(dbconfig)
    app.config.from_object(jwt_config)
    
    limiter.init_app(app)
    db.init_app(app)
    jwt.init_app(app)

    from app.models import User, book_manager, jwt_blacklist

    with app.app_context(): # creating all the database tables
        db.create_all()

    register_error_handlers(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(book_bp)
    app.register_blueprint(admin_bp)
    
    return app


# filename: config.py
import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
	SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')

class dbconfig:
	basedir = os.path.abspath(os.path.dirname(__file__))
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

class jwt_config:
	JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
	JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
	JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)


# filename: extensions.py
from flask_sqlalchemy import SQLAlchemy

# Local Import
from app.schema import BookSchema, UserSchema

# Schema instances
book_schema = BookSchema() # for a single book
books_schema = BookSchema(many=True) # for multiple books
user_schema = UserSchema(many=False)

# Global instances
db = SQLAlchemy()


# filename: jwt_extensions.py
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity, get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from app.extensions import db
from app.models import User, jwt_blacklist

jwt = JWTManager()

# Function to get user identifier
def get_user_identifier():
    try:
        verify_jwt_in_request(optional=True)
        return str(get_jwt_identity() or get_remote_address())
    except Exception:
        return get_remote_address()

limiter = Limiter(
    key_func = get_user_identifier,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"    
    )

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload['jti']
    token = db.session.query(jwt_blacklist.id).filter_by(jti=jti).scalar()

    return token is not None
# "Return True (i.e., token is revoked) only if we found the token in the blocklist."

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = get_jwt()
        role = token.get('role', None)

        if role == 'admin':
            return func(*args, **kwargs)
        else:
            return {'message': 'Access denied'}, 403

    return wrapper


# filename: book_schema.py
from marshmallow import Schema, fields, validate

class BookSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(required=True, validate=validate.Length(min=1))
    author = fields.Str(required=True, validate=validate.Length(min=1))


# filename: user_schema.py
from marshmallow import Schema, fields, validate

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True, validate=validate.Length(min=1))
    password = fields.Str(required=True, validate=validate.Length(min=8))
    email = fields.Str(required=True, validate=validate.Length(min=1))


# filename: admin_routes.py
from flask import Blueprint
from flask_restful import Api

admin_bp = Blueprint('admin', __name__, url_prefix='/a/v1')
admin_api = Api(admin_bp)

from app.resources.admin import Admin_Crud, Admin_Book_Manage, User_Control, Jwt_Manage
admin_api.add_resource(Admin_Crud, '/manage')
admin_api.add_resource(Admin_Book_Manage, '/books')
admin_api.add_resource(User_Control, '/user/ban')
admin_api.add_resource(Jwt_Manage, '/jwt/clear')


# filename: auth_routes.py
from flask import Blueprint
from flask_restful import Api

auth_bp = Blueprint('auth', __name__, url_prefix='/auth/v1')
auth_api = Api(auth_bp)

from app.resources.auth import AddUser, Login, Ref_Token, Del_Token
auth_api.add_resource(AddUser, '/register')
auth_api.add_resource(Login, '/login')
auth_api.add_resource(Ref_Token, '/refresh')
auth_api.add_resource(Del_Token, '/logout')


# filename: book_routes.py
from flask import Blueprint
from flask_restful import Api

book_bp = Blueprint('book', __name__)
book_api = Api(book_bp)

from app.resources.book import Book_CR, Book_RUD, Book_reuse, Book_Favourite
book_api.add_resource(Book_CR, '/api/v1/books', endpoint='view')  # For Create & Read (all)
book_api.add_resource(Book_RUD, '/api/v1/books/<int:id>', endpoint='edit_delete')  # For Read (one), Update, Delete
book_api.add_resource(Book_reuse, '/api/v1/recovery', endpoint='recover')
book_api.add_resource(Book_reuse, '/api/v1/favourites', endpoint='favourite')


# filename: auth.py
from flask_restful import Resource, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import BadRequest
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)

# Local Import
from app.models.user import User
from app.models.blacklist import jwt_blacklist 
from app.errors.handlers import CustomBadRequest
from app.extensions import db, user_schema
from app.jwt_extensions import jwt, limiter, admin_required

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
            raise CustomBadRequest("Validation failed")

        else:
            username_signin = data.get("username")
            pass_txt_signin = data.get("password")
            email_signin = data.get("email")

            now = datetime.now(timezone.utc)

            check_user = User.query.filter(User.username == username_signin).first()

            if check_user:
                raise CustomBadRequest("Username already taken.")
            else:
                new_hashed_pw_signin = generate_password_hash(pass_txt_signin)

                new_user = User(username=username_signin,
                    password=new_hashed_pw_signin,
                    email=email_signin ,joined=now)

                try:
                    db.session.add(new_user)
                    db.session.commit()
                    return {"Successful": "Head to '/login' to login and start using the api."}, 200
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e

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
            raise CustomBadRequest("Validation failed")

        else:
            username_for_login = data.get("username")
            pass_txt_login = data.get("password")

            check_user = User.query.filter(
                User.username == username_for_login
                ,User.is_banned == False).first()

            if not check_user:
                abort(404, description="User not found.")

            elif check_user.is_banned:
                abort(404, description="User is banned. Email to user.support@bookroad.com")
            
            else:
                if check_user and check_password_hash(check_user.password , pass_txt_login):
                    access_token = create_access_token(identity=check_user.id
                        ,additional_claims={"roles": check_user.role})
                    refresh_token = create_refresh_token(identity=check_user.id
                        ,additional_claims={"roles": check_user.role})
                    return {"access_token": access_token, "refresh_token": refresh_token}, 200        
                else:
                    return {"message": "Bad username or password. Login unsuccessful"}, 401

# JWT protected class to only get access token using the refresh token
class Ref_Token(Resource):
    @limiter.limit("10 per day")
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        token = get_jwt()
        jti = token['jti']
        ttype = token["type"]
        now = datetime.now(timezone.utc)
        role = token['role']

        user = db.session.get(User, identity)

        try:
            new_refresh_revoke = jwt_blacklist(jti=jti
                ,ttype=ttype
                ,created_at=now
                ,user_id_jwt=identity
                ,role= role)
            db.session.add(new_refresh_revoke)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            raise e

        access_token = create_access_token(
            identity=identity
            ,additional_claims={"role": user.role})
        refresh_token = create_refresh_token(
            identity=identity
            ,additional_claims={"role": user.role})
        return {"access_token" : access_token, "refresh_token" : refresh_token}

class Del_Token(Resource):
    @limiter.limit("10 per day")
    @jwt_required()
    def delete(self):
        user_id_jwt = get_jwt_identity()
        token = get_jwt()
        jti = token['jti']
        ttype = token["type"]
        role = token['role']
        now = datetime.now(timezone.utc)
        try:
            new_re = jwt_blacklist(jti=jti
                ,ttype=ttype
                ,created_at=now
                ,user_id_jwt=user_id_jwt
                ,role= role)
            db.session.add(new_re)
            db.session.commit()
            return {'message': f'{ttype.capitalize()}: JWT token revoked.'}
        except SQLAlchemyError as e:
            db.session.rollback()
            raise e


# filename: book resouces.py
from flask_restful import Resource, request, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.exceptions import BadRequest
from sqlalchemy.exc import SQLAlchemyError

# Local Import
from app.models.book import book_manager
from app.errors.handlers import CustomBadRequest
from app.extensions import db, book_schema, books_schema
from app.jwt_extensions import limiter

class Book_CR(Resource):
    @jwt_required()
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        title_get = request.args.get('title', '', type=str)
        author = request.args.get('author', '', type=str)

        title = title_get.strip().lower()

        current_user_id = get_jwt_identity()
        
        genre = request.args.get('genre', default=None, type=str)

        sort_query = request.args.get('sort', default=None, type=str)
        order = request.args.get('order', 'asc', type=str)

        filters = [book_manager.user_id == current_user_id, book_manager.is_deleted == False]
        filt = []

        if genre is not None:
            filters.append(book_manager.genre == genre)

        if title and author:
            filters.append(book_manager.normalized_title == title)
            filters.append(book_manager.author == author)

        elif author:
            filters.append(book_manager.author == author)
            
            if sort_query == 'author' and order == 'desc':
                filt = [book_manager.author.desc()]
            elif sort_query == 'author':
                filt = [book_manager.author.asc()]

        elif title:
            filters.append(book_manager.normalized_title == title)

            if sort_query == 'title' and order == 'desc':
                filt = [book_manager.title.desc()]
            elif sort_query == 'title':
                filt = [book_manager.title.asc()]
        
        if sort_query is None:
            pagination = book_manager.query.filter(*filters).paginate(
            page=page, per_page=per_page, error_out=False)
        else:
            pagination = book_manager.query.filter(*filters).order_by(
                *filt).paginate(
                page=page, per_page=per_page, error_out=False)

        if not pagination.items:
            abort(404, description="Book not found.")

        else:
            books =  books_schema.dump(pagination.items)

            return {
            'books': books,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_items': pagination.total,
            'total_pages': pagination.pages
            }, 200

    @jwt_required()
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
            raise CustomBadRequest("Validation failed")

        else:
            title = data.get("title")
            author = data.get("author")
            genre = data.get("genre", None)

            normalized_title = title.lower().strip()

            del_check = book_manager.query.filter_by(
                user_id=get_jwt_identity()
                , is_deleted=True
                , normalized_title=normalized_title).first() 
            
            if not del_check:
                new_book = book_manager(
                    title = title,
                    author = author,
                    normalized_title = normalized_title,
                    user_id = get_jwt_identity(),
                    is_deleted = False,
                    genre = genre
                )

                try:
                    db.session.add(new_book)
                    db.session.commit()
                    return book_schema.dump(new_book), 201
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e
            else:
                del_check.is_deleted = False
                try:
                    db.session.commit()
                    return {'message' : f"({del_check.title}) is added to the list."}
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e

# JWT protected class to update, delete and get book by id.
class Book_RUD(Resource):
    @jwt_required()
    def get(self, id):
        current_user_id = get_jwt_identity()
        book_to_work = book_manager.query.filter_by(user_id=current_user_id, id=id, is_deleted = False).first()        
        
        if not book_to_work:
            abort(404, description="Book not found.")
        else:
            return (book_schema.dump(book_to_work)), 200

    @jwt_required()
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
            raise CustomBadRequest("Validation failed")
            
        else:
            current_user_id = get_jwt_identity()
            
            book_to_work = book_manager.query.filter_by(user_id=current_user_id, id=id, is_deleted = False).first()
            
            if not book_to_work:
                abort(404, description="Book not found.")

            try:
                book_to_work.title = data['title']
                book_to_work.author = data['author'] 
                db.session.commit()
                return {"message" : "Updated Successfully"}, 200 
            except SQLAlchemyError as e:
                db.session.rollback()
                raise e
    
    @jwt_required()
    @limiter.limit("50 per day")
    def delete(self, id):
        current_user_id = get_jwt_identity()
            
        book_tw = book_manager.query.filter_by(user_id=current_user_id, id=id).first()
        if not book_tw:
            abort(404, description="Book not found.")

        try:    
            book_tw.is_deleted = True
            db.session.commit()
            return {"message" : "Deleted Successfully"}, 200
        except SQLAlchemyError as e:
            db.session.rollback()
            raise e

class Book_reuse(Resource):
    @jwt_required()
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        pagination = book_manager.query.filter(
            user_id=get_jwt_identity()
            ,is_deleted=True
            ).paginate(
            page=page, per_page=per_page, error_out=False)

        if not pagination.items:
            abort(404, description="Book not found.")

        else:
            books =  books_schema.dump(pagination.items)

            return {
            'books': books,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_items': pagination.total,
            'total_pages': pagination.pages
            }, 200

class Book_Favourite(Resource):
    @jwt_required()
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        title_get = request.args.get('title', '', type=str)
        author = request.args.get('author', '', type=str)

        title = title_get.strip().lower()

        current_user_id = get_jwt_identity()
        
        sort_query = request.args.get('sort', default=None, type=str)
        order = request.args.get('order', 'asc', type=str)
        
        genre = request.args.get('genre', default=None, type=str)

        filters = [
            book_manager.user_id == current_user_id,
            book_manager.favourite == True,
            book_manager.is_deleted == False,
        ]

        filt = []

        if genre is not None:
            filters.append(book_manager.genre == genre)

        if title and author:
            filters.append(book_manager.normalized_title == title)
            filters.append(book_manager.author == author)

        elif author:
            filters.append(book_manager.author == author)
            
            if sort_query == 'author' and order == 'desc':
                filt = [book_manager.author.desc()]
            elif sort_query == 'author':
                filt = [book_manager.author.asc()]

        elif title:
            filters.append(book_manager.normalized_title == title)

            if sort_query == 'title' and order == 'desc':
                filt = [book_manager.title.desc()]
            elif sort_query == 'title':
                filt = [book_manager.title.asc()]
        
        if sort_query is None:
            pagination = book_manager.query.filter(*filters).paginate(
            page=page, per_page=per_page, error_out=False)
        else:
            pagination = book_manager.query.filter(*filters).order_by(
                *filt).paginate(
                page=page, per_page=per_page, error_out=False)

        if not pagination.items:
            abort(404, description="Book not found.")

        else:
            books =  books_schema.dump(pagination.items)

            return {
            'favourite books': books,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_items': pagination.total,
            'total_pages': pagination.pages
            }, 200

    @jwt_required()
    def put(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        title = data.get('title')

        normalized_title = title.lower().strip()

        if not username_of_user:
            raise CustomBadRequest("Username required.")
        else:
            check = book_manager.query.filter_by(
                book_manager.normalized_title == normalized_title).first()

            if check.is_deleted:
                return {'message' : 'Book deleted. Restore to add as favourite.'}, 404

            elif check.favourite:
                return {'message' : 'Book already added as favourite.'}, 404

            elif not check:
                try:
                    check.favourite == True
                    db.session.commit()
                    return {'message' : 'Book added as favourite'}, 200
                except SQLAlchemyError as e:
                    db.session.rollback()
                    return {'message' : 'An error occured.'}
                    raise e

    @jwt_required()
    def delete(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        title = data.get('title')

        normalized_title = title.lower().strip()

        if not username_of_user:
            raise CustomBadRequest("Username required.")
        else:
            check = book_manager.query.filter_by(
                book_manager.normalized_title == normalized_title).first()

            if check.is_deleted:
                return {'message' : 'Book already deleted. Head to /api/v1/recovery to restore.'}, 404

            elif check.favourite:
                try:
                    check.favourite == False
                    db.session.commit()
                    return {'message' : 'Book removed from favourites.'}
                except SQLAlchemyError as e:
                    db.session.rollback()
                    return {'message' : 'An error occured.'}
                    raise e


# filename: admin.py
from flask_restful import Resource, request, abort
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash
from werkzeug.exceptions import BadRequest
from sqlalchemy.exc import SQLAlchemyError
import random
import string

# Local Import
from app.extensions import (
    db, user_schema, books_schema, book_schema)
from app.models import User, book_manager, jwt_blacklist
from app.errors.handlers import CustomBadRequest
from app.jwt_extensions import jwt, admin_required, limiter, admin_required
from app.logging.ext_admin import logging, logger
'''
admin can see how manu users in there. 
add new admin.
look how many books there are. who has how many books.
ban/mute a user
control flow of all new user joining/account deletion
'''

# A route to get all the admin info and ban/unban them
class Admin_Crud(Resource):
    # Getting info of all admins
    @jwt_required()
    @admin_required()
    @limiter.limit("3 per day")
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        pagination = User.query.filter(User.role == 'admin'
            ,User.is_banned == False).paginate(
            page=page, per_page=per_page, error_out=False)

        if not pagination.items:
            abort(404, description="No admins found.")

        else:
            admins =  user_schema.dump(pagination.items, many=True)

            logger.info('Admin requested to see data of all admins.')
            return {
            'admins': admins,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_items': pagination.total,
            'total_pages': pagination.pages
            }, 200
    
    # Adding new admin. (full new user)
    @jwt_required()
    @admin_required()
    @limiter.limit("3 per day")
    def post(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        username_new_admin = data.get("username")
        pass_new_admin = data.get("password")
        now = datetime.now(timezone.utc)

        if not username_new_admin or not pass_new_admin:
            raise CustomBadRequest("Username and password required.")

        else:
            check_user = User.query.filter(User.username == username_new_admin).first()

            if check_user:
                return {'message' : 'User already exists. Change his role to admin with a put req.'}
            else:
                new_hashed_pw_admin = generate_password_hash(pass_new_admin)

                new_admin = User(username=username_new_admin
                    ,password=new_hashed_pw_admin
                    ,joined=now
                    ,role='admin')

                try:
                    db.session.add(new_admin)
                    db.session.commit()
                    logger.info(f'{username_new_admin} has been added as new admin')
                    return {"Successful": "Head to '/login' to login and start using the api."}, 200
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e

    # Upgrading User -> admin
    @jwt_required()
    @admin_required()
    @limiter.limit("3 per day")
    def put(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        username_of_user = data.get("username")

        if not username_of_user:
            raise CustomBadRequest("Username required.")

        else:
            check_user = User.query.filter(User.username == username_of_user).first()

            if not check_user:
                abort(404, description="User not found in the database.")

            else:
                try:
                    check_user.role = 'admin'
                    db.session.commit()
                    return {'message' : 'User added as admin successfully'}
                    logger.info(f'{username_of_user} : promoted to user -> Admin')
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e


    # removing someone from admin
    @jwt_required()
    @admin_required()
    @limiter.limit("3 per day")
    def delete(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        username_of_user = data.get("username")

        if not username_of_user:
            raise CustomBadRequest("Username required.")

        else:
            check_user = User.query.filter(User.username == username_of_user
                ,User.role == 'admin').first()

            if not check_user:
                return {'message' : 'User is not an admin.'}

            else:
                try:
                    check_user.role = 'user'
                    db.session.commit()
                    logger.info(f'{username_of_user} has been removed from admin.')
                    return {'message' : 'User removed from admin. Go to /user/ban to ban him from being a user too.'}
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e

class Admin_Book_Manage(Resource):
    # admin wanting to see all the books in the db regardless of user
    @jwt_required()
    @admin_required()
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        title_get = request.args.get('title', '', type=str)
        author = request.args.get('author', '', type=str)

        title = title_get.strip().lower()

        # admin can generally see all the books + only user specific books too.
        user_id = request.args.get('user_id', default=None, type=int)
        
        sort_query = request.args.get('sort', default=None, type=str)
        order = request.args.get('order', 'asc', type=str)


        if user_id is not None:
            filters = [book_manager.is_deleted == False
            ,book_manager.user_id == user_id]
            filt = []
        else:
            filters = [book_manager.is_deleted == False]
            filt = []

        if title and author:
            filters.append(book_manager.normalized_title == title)
            filters.append(book_manager.author == author)
        
        elif author:
            filters.append(book_manager.author == author)
            if sort_query == 'author' and order == 'desc':
                filt = [book_manager.author.desc()]
            elif sort_query == 'author':
                filt = [book_manager.author.asc()]
            

        elif title:
            filters.append(book_manager.normalized_title == title)      
            if sort_query == 'title' and order == 'desc':
                filt = [book_manager.title.desc()]
            elif sort_query == 'title':
                filt = [book_manager.title.asc()]
            


        if sort_query is None:
            pagination = book_manager.query.filter(*filters).paginate(
            page=page, per_page=per_page, error_out=False)
        else:
            pagination = book_manager.query.filter(*filters).order_by(
                *filt).paginate(
                page=page, per_page=per_page, error_out=False)


        if not pagination.items:
            abort(404, description="Book not found.")

        else:
            books =  books_schema.dump(pagination.items)

            logger.info('Admin asked to see all book data.')
            return {
            'user_id' : user_id,
            'books': books,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total_items': pagination.total,
            'total_pages': pagination.pages
            }, 200

class User_Control(Resource):
    # banning a user from the api.
    @jwt_required()
    @admin_required()
    def delete(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        username_of_user = data.get("username")

        if not username_of_user:
            raise CustomBadRequest("Username required.")

        else:
            check_user = User.query.filter(User.username == username_of_user).first()

            if not check_user:
                return {'message' : 'User not found.'}

            else:
                try:
                    check_user.is_banned = True
                    db.session.commit()
                    logger.info(f'User [{username_of_user}] has been banned.')
                    return {'message' : f'User [{username_of_user}] has been banned.'}
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e

    # Unbanning a user from the api.
    @jwt_required()
    @admin_required()
    def put(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        username_of_user = data.get("username")

        if not username_of_user:
            raise CustomBadRequest("Username required.")
        else:
            check_user = User.query.filter(User.username == username_of_user).first()

            if not check_user:
                return {'message' : 'User not found.'}

            else:
                try:
                    check_user.is_banned = False
                    db.session.commit()
                    logger.info(f'User [{username_of_user}] has been unbanned.')
                    return {'message' : f"Access for user '{username_of_user}' has been restored."}
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e             

    @jwt_required()
    @admin_required()
    def post(self):
        try:
            data = request.get_json()
            if data is None:
                raise CustomBadRequest("Missing JSON in request.")
        except BadRequest:
            raise CustomBadRequest("Invalid JSON format.")

        username_of_user = data.get("username")
        email = data.get('email')

        if not username_of_user and email:
            raise CustomBadRequest("Username and Email both required.")

        else:
            check_user = User.query.filter(User.username == username_of_user, email == email)

            if not check_user:
                return {'message' : 'User not found.'}

            else:
                random_string = ''.join(random.choice(string.ascii_letters) for _ in range(10))

                check_user.password = random_string
                try:
                    db.session.commit()
                    logger.info(f'User [{username_of_user}] password has been changed..')
                    return {'message' : f"Password for user '{username_of_user}' is : {random_string}"}
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e


class Jwt_Manage(Resource):
    # Deleting all old jwt token from the db.
    @jwt_required()
    @admin_required()
    def delete(self):
        now = datetime.now(timezone.utc)

        for token in jwt_blacklist.query.all():
            if now >= (token.created_at + timedelta(days=15)):
                try:
                    db.session.delete(token)
                    db.session.commit()
                    logger.info("JWT token blacklist database has been cleared.")
                except SQLAlchemyError as e:
                    db.session.rollback()
                    raise e


# filename: book.py
from app.extensions import db

class book_manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    normalized_title = db.Column(db.String(200), nullable=False, index=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    favourite = db.Column(db.Boolean, default=False, nullable=False)
    genre = db.Column(db.String(30), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user_db.id'), index=True, nullable=False)

    __table_args__ = (
    db.UniqueConstraint('user_id', 'normalized_title', name='uq_user_title_normalized'),
    )


# filename: user.py
from app.extensions import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'user_db'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    joined = db.Column(db.DateTime, nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)

    books = db.relationship('book_manager', backref='user', lazy=True)


# filename: blacklist.py
from app.extensions import db
from datetime import datetime

class jwt_blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(300), nullable=False) # jti → Stands for JWT ID
    ttype = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)   
    user_id_jwt = db.Column(db.Integer, nullable=False)
    role = db.Column(db.String(20), nullable=False)


# filename: ext_admin.py
# myapp.py
import logging
from app.resources.admin import Admin_Crud, Admin_Book_Manage, User_Control

logger = logging.getLogger(__name__)
    
def main():
    logging.basicConfig(filename='myapp.log', level=logging.INFO)
    logger.info('Started')
    Admin_Crud.get()
    Admin_Crud.post()
    Admin_Crud.put()
    Admin_Crud.delete()
    Admin_Book_Manage.get()
    User_Control.put()
    User_Control.delete()

    logger.info('Finished')

if __name__ == '__main__':
    main()


# filename: handlers.py
from flask import abort
from werkzeug.exceptions import BadRequest
from sqlalchemy.exc import SQLAlchemyError

class CustomBadRequest(BadRequest):
    def __init__(self, respond):
        self.description = respond
        super().__init__()

def register_error_handlers(app):
    @app.errorhandler(CustomBadRequest)
    def no_data_error(e):
        return {"message": e.description}, 400

    @app.errorhandler(SQLAlchemyError)
    def db_entry_error(e):
        return {"error": "Failed to save entry to database"}, 500

    @app.errorhandler(404)
    def data_not_found_error(e):
        return {"message": e.description or "Resource not found."}, 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return {"error": "An internal server error occurred."}, 500


# filename: mylib.py
# mylib.py
import logging
logger = logging.getLogger(__name__)

def do_something():
    logger.info('Doing something')


# filename: run.py
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)