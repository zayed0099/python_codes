import requests

payload = {
        "id": 6,
        "title": "Spirited Away",
        "year": 2001,
        "genre": "Animation",
        "director": "Hayao Miyazaki",
        "actor": "Rumi Hiiragi",
        "imdb_rating": 8.6
    },{
        "id": 7,
        "title": "Parasite",
        "year": 2019,
        "genre": "Comedy",
        "director": "Bong Joon-ho",
        "actor": "Song Kang-ho",
        "imdb_rating": 8.5
    },{
        "id": 8,
        "title": "The Dark Knight",
        "year": 2008,
        "genre": "Action",
        "director": "Christopher Nolan",
        "actor": "Christian Bale",
        "imdb_rating": 9.0
    },{
        "id": 9,
        "title": "Pulp Fiction",
        "year": 1994,
        "genre": "Crime",
        "director": "Quentin Tarantino",
        "actor": "John Travolta",
        "imdb_rating": 8.9
    },{
        "id": 10,
        "title": "Forrest Gump",
        "year": 1994,
        "genre": "Drama",
        "director": "Robert Zemeckis",
        "actor": "Tom Hanks",
        "imdb_rating": 8.8
    }
url = 'http://127.0.0.1:5000/movies'

r = requests.post(url, json=payload)

if r.status_code in (200, 201):
	print(f"Status Code: {r.status_code}, Operation Successful")
else:
	print(f"Status Code: {r.status_code}, Operation Unsuccessful")