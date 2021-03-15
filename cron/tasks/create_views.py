import os
import boto3
import dotenv
import psycopg2
from invoke import task
from postgres import Postgres

env_path = os.getenv('DOT_ENV', '.env')
if env_path and os.path.exists(env_path):
    dotenv.load_dotenv(dotenv_path=env_path, override=False, verbose=True)

from .snapshots_tool_utils import LOGGER


@task(help={
    'verbose': "bool flag", 'debug': 'bool flag', 'profile': 'str', 'region': 'str',
    'host': 'str', 'database': 'str',
    'username': 'str', 'port': 'int',
    'password_secret': 'str',
    'sql': 'str', 'show_views': 'bool flag',
})
def create_views(context,
                      host='PowerBI-Database-5220580aeddf840b.elb.us-west-2.amazonaws.com', username='roadsync',
                      database='roadsync', port=5432,
                      password_secret='rds/app-prod/password',
                      profile=None, region=os.getenv('AWS_DEFAULT_REGION'), verbose=False, debug=False,
                      sql=None, show_views=True):
    LOGGER.info(region)
    boto3.setup_default_session(profile_name=profile)
    session = boto3.DEFAULT_SESSION
    client = session.client('secretsmanager', region_name=region)
    response = client.get_secret_value(
        SecretId=password_secret,
    )
    password = response['SecretString']

    try:
        if isinstance(sql, str):
            if os.path.exists(sql):
                with open(sql, 'rt') as h:
                    sql = h.read()
                    h.close()
        elif sql is not None:
            LOGGER.warning(f'"sql({sql.__class__.__name__})" is not supported')
    except Exception as e:
        LOGGER.error(e)
        raise

    # postgresql://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]
    try:
        pg = Postgres(url=f'postgresql://{username}:{password}@{host}:{port}/{database}')
        LOGGER.info(f'Password valid!')
        views = [ t.table_name for t in pg.all("select * from information_schema.views WHERE table_schema='public'")]
        if sql:
            if len(views) <= 1:
                pg.run(sql)
                LOGGER.info(f'Views created')
                views = [ t.table_name for t in pg.all("select * from information_schema.views WHERE table_schema='public'")]
            LOGGER.info(f'{len(views)} views found')
        else:
            LOGGER.info(f'No SQL commands provided.')
        if show_views:
            LOGGER.info(f'Inspecting views!')
            [ print(tn) for tn in sorted(views)]
    except psycopg2.DatabaseError as e:
        LOGGER.error(e)
