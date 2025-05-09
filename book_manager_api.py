import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

list_book = [
    {
        "id": 1,
        "title": "1984",
        "author": "George Orwell"
    },
    {
        "id": 2,
        "title": "Pride and Prejudice",
        "author": "Jane Austen"
    },
    {
        "id": 3,
        "title": "To Kill a Mockingbird",
        "author": "Harper Lee"
    },
    {
        "id": 4,
        "title": "The Hitchhiker's Guide to the Galaxy",
        "author": "Douglas Adams"
    },
    {
        "id": 5,
        "title": "The Lord of the Rings",
        "author": "J.R.R. Tolkien"
    }
]

@app.route("/GET/books", methods=["GET", "POST"])
def showing():
    if request.method == "POST":
        data = request.get_json()
        list_book.extend(data)
        return jsonify(list_book)
    else:
        return jsonify(list_book)


@app.route("/GET/books/<int:id>")
def showing_by_id(id):
    for book in list_book:
        if book["id"] == id:
            return jsonify(book)

@app.route("/POST/books", methods=["GET","POST"])
def adding_book():
    url = 'http://127.0.0.1:5000/GET/books'
    payload = [{
    "id" : 6,
    "title" : "Automate boring stuff with Python",
    "author" : "Al Sweigart"
    }]
    headers = {"Content-Type": "application/json"}


    r = requests.post(url, json=payload, headers=headers)
    return f"Status Code: {r.status_code}, Operation Successful"


if __name__ == "__main__":
    app.run(debug=True)