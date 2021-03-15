#!bash

cd $(dirname "$0")
python -V
inv check-db-password
inv create-views --host power-bi.db.dev.roadsync.com --sql views.sql --no-show-views
