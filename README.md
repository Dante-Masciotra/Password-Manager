# COMP 3340 Final Project - Password Manager

### Zach Hutz, Dante Masciotra, Caden Quiring, Zach Wasylyk

## First-Time Setup

1. (optional) Consider setting up a virtual environment.\
   On Windows (cmd):

```shell
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

2. Create a folder called "db" in the "app" directory.
3. Run `create-db.py` to create a fresh SQLite database
4. `flask run` will run the API. Directly executing `index.py` will run in debug mode.
