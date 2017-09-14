
import json

with open('profile.json') as json_data:
    d = json.load(json_data)
    print(d)
