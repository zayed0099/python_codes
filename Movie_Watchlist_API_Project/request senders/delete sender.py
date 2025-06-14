import requests
import json


id_ = int(input("ENTER THE ID : "))

url = f"http://127.0.0.1:5000/movies/view/{id_}"

headers = {'Content-Type': 'application/json; charset=UTF-8'}

response = requests.delete(url, headers=headers)

print("Response Code : ", response.status_code)