"""I will create a api that will accept all get, put, post, delete request. but the put, post and delete
request will have to be made from outside of the api file. like curl, postman or extra script"""

import requests
from flask import Flask, jsonify, request
import json
import os

app = Flask(__name__)

# making the file in current directory as the code
current_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_dir, 'data.json')


# making a opening point to store data
if os.path.exists(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
else:
    data = []


@app.route('/movies', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
        return jsonify(data)

    elif request.method == 'POST':
        sent_data = request.get_json()
        
        data.extend(sent_data)
        formated = jsonify(data)
        
        with open(file_path, "w") as file:
            json.dump(data, file, indent=4)
        return 'Successful'

@app.route("/movies/view/<int:id>", methods=["GET", "PUT", "DELETE"])
def show_by_id(id):
    if request.method == "GET":
        for movie in data:
            if movie['id'] == id:
                return jsonify(movie)

    elif request.method == 'PUT':
        sent_data = request.get_json()
        
        for movie in data:
            if movie['id'] == id:
                movie['title'] = sent_data.get("title", movie['title'])
                movie['year'] = sent_data.get("year", movie['year'])
                movie['genre'] = sent_data.get("genre", movie['genre'])
                movie['director'] = sent_data.get("director", movie['director'])
                movie['actor'] = sent_data.get("actor", movie['actor'])
                movie['imdb_rating'] = sent_data.get("imdb_rating", movie['imdb_rating'])
                
                with open(file_path, 'w') as file:
                    json.dump(data, file, indent=4)

        return "PUT request received"

    elif request.method == "DELETE":
       
       for index, movie in enumerate(data):
            if movie["id"] == id:
                deleted= data.pop(index)

                with open(file_path, 'w') as file:
                    json.dump(data, file, indent=4)

                return jsonify({"message": "Movie deleted", "Movie": deleted}), 200



@app.route("/movies/view/<string:imdbid>")
def search_omdb(imdbid):
    try:    
        url = f"https://www.omdbapi.com/?i={imdbid}&apikey=7a7e87e3"
        response = requests.get(url)

        data = response.json()

        if response.status_code == 200:
            return(f"""<b>Movie Name</b> : {data['Title']}<br>
<b>Actors</b> : {data['Actors']} <br>
<b>Director</b> : {data['Director']}<br>
<b>Genre</b> : {data['Genre']}<br>
<b>Language</b> : {data['Language']}<br>
<b>Released</b> : {data['Released']}<br>
<b>imdbID</b> : {data['imdbID']}<br>
<b>imdbRating</b> : {data['imdbRating']}<br>
<b>Country</b> : {data['Country']}<br>
<b>BoxOffice</b> : {data['BoxOffice']}<br>
<b>Poster</b> : <a href="{data['Poster']}" target="_blank">Click here</a>
""")      

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return None


if __name__ == "__main__":
    app.run(debug=True)
