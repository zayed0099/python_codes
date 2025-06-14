import requests

payload = {
        'id' : 1,
        "title": "Lost in Translation",
        "year": 2003,
        "genre": "Drama",
        "director": "Sofia Coppola",
        "actor": "Bill Murray",
        "imdb_rating": 7.7
    },{
    "id": 2,
    "title": "The Green Mile",
    "year": 1999,
    "genre": "Drama",
    "director": "Frank Darabont",
    "actor": "Tom Hanks",
    "imdb_rating": 8.6
    }
url = 'http://127.0.0.1:5000/movies'

r = requests.post(url, json=payload)

if r.status_code in (200, 201):
	print(f"Status Code: {r.status_code}, Operation Successful")
else:
	print(f"Status Code: {r.status_code}, Operation Unsuccessful")