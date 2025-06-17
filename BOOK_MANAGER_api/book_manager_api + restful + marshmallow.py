import os
from flask import Flask, request, jsonify, abort
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, validate

app = Flask(__name__)
api = Api(app)


basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')

db = SQLAlchemy(app)

class book_manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    author = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# schema for marshmallow
class BookSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(required=True, validate=validate.Length(min=1))
    author = fields.Str(required=True, validate=validate.Length(min=1))

book_schema = BookSchema() # for a single book
books_schema = BookSchema(many=True) # for multiple books

class Book_CR(Resource):
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        pagination = book_manager.query.paginate(page=page, per_page=per_page, error_out=False)

        books =  books_schema.dump(pagination.items)

        return jsonify({
        'books': books,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'total_items': pagination.total,
        'total_pages': pagination.pages
        })

    def post(self):
        data = request.get_json()

        errors = book_schema.validate(data)
        if errors:
            return errors, 400

        else:
            new_book = book_manager(**data)
            db.session.add(new_book)
            db.session.commit()

            return book_schema.dump(new_book), 201

class Book_RUD(Resource):
    def get(self, id):
        book_to_work = db.session.get(book_manager, id)        
        return (book_schema.dump(book_to_work)), 200

    def put(self, id):
        data = request.get_json()
        book_to_work = db.session.get(book_manager, id)        
        
        book_to_work.title = data['title']
        book_to_work.author = data['author'] 
        db.session.commit()
        return jsonify({"Updated Successfully"}), 200 

    def delete(self, id):
        book_to_work = db.session.get(book_manager, id)
        db.session.delete(book_to_work)
        db.session.commit()
        return jsonify({"Deleted Successfully"}), 200
        
api.add_resource(Book_CR, '/api/v1/books/', endpoint='view')  # For Create & Read (all)
api.add_resource(Book_RUD, '/api/v1/books/<int:id>', endpoint='edit_delete')  # For Read (one), Update, Delete


if __name__ == "__main__":
    app.run(debug=True)


'''
uri for curl
get/post - http://127.0.0.1:5000/api/v1/books/
rud = http://127.0.0.1:5000/api/v1/books/id


curl script to post--
curl -X POST -H "Content-Type: application/json" -d '{"title": "testing book 3", "author": "mojo khao"}' http://127.0.0.1:5000/api/v1/books/

'''