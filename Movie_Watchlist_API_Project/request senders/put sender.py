import requests

payload = {
    "title": "The TEST",
    "year": 1010,
    "genre": "Drama",
    "director": "Frank Darabont",
    "actor": "Tom Hanks",
    "imdb_rating": 10.0
    }

id_ = int(input("ENTER THE ID : "))

url = f"http://127.0.0.1:5000/movies/view/{id_}"

r = requests.put(url, json=payload)

if r.status_code in (200, 201):
	print(f"Status Code: {r.status_code}, Operation Successful")
else:
	print(f"Status Code: {r.status_code}, Operation Unsuccessful")