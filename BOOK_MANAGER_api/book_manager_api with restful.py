from flask import Flask, request, jsonify, abort
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
api = Api(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')

db = SQLAlchemy(app)

class book_manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    author = db.Column(db.String(200), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author
        }

with app.app_context():
    db.create_all()

class Book_CR(Resource):
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        pagination = book_manager.query.paginate(page=page, per_page=per_page, error_out=False)
        books = [book.to_dict() for book in pagination.items]
        return ({
            "page" : page,
            "per_page" : per_page,
            "total": pagination.total,
            "pages": pagination.pages,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev,
            "books" : books
            }), 200

    def post(self):
        data = request.get_json()

        if not data or 'title' not in data or 'author' not in data:
            return jsonify({"message": "Invalid data"}), 400

        else:
            new_book = book_manager(title=data['title'], author=data['author'])
            
            db.session.add(new_book)
            db.session.commit()

            return {"message": "You can use this route to send POST requests."}

class Book_RUD(Resource):
    def get(self, id):
        book_to_work = db.session.get(book_manager, id)        
        return (book_to_work.to_dict()), 200

    def put(self, id):
        data = request.get_json()
        book_to_work = db.session.get(book_manager, id)        
        
        data['title'] = book_to_work.title
        data['author'] = book_to_work.author
        db.session.commit()

    def delete(self, id):
        book_to_work = db.session.get(book_manager, id)
        db.session.delete(book_to_work)
        db.session.commit()

api.add_resource(Book_CR, '/api/v1/books/', endpoint='view')  # For Create & Read (all)
api.add_resource(Book_RUD, '/api/v1/books/<int:id>', endpoint='edit_delete')  # For Read (one), Update, Delete


if __name__ == "__main__":
    app.run(debug=True)


'''
uri for curl
get - http://127.0.0.1:5000/api/v1/books/
rud = http://127.0.0.1:5000/api/v1/books/id
'''