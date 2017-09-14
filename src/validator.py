
import json

with open('profile.json') as json_data:
    data = json.load(json_data)
    print(data)


#recursive iterator of json data tree
def recursive_iter(obj):
    if isinstance(obj, dict):
        for item in obj.values():
            yield from recursive_iter(item)
    elif any(isinstance(obj, t) for t in (list, tuple)):
        for item in obj:
            yield from recursive_iter(item)
    else:
        yield obj


for item in recursive_iter(data):
    print(item)
