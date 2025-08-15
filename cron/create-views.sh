#!bash

cd $(dirname "$0")
inv check-db-password 2>&1 | tee -a /tmp/create-views.log
inv create-views --host power-bi.db.dev.dldinternet.com --sql views.sql --show-views 2>&1 | tee -a /tmp/create-views.log
