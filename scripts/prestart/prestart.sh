#!/bin/bash

# chmod +x init_db.py
# ./init_db.py

# check if migrations folder is not empty
if ! [ "$(find "$FLASK_APP_MIGRATIONS" -mindepth 1 -print -quit 2>/dev/null)" ]; then
	flask db init
fi

flask db upgrade
