import os
import boto3
import dotenv
import psycopg2
from invoke import task
from .snapshots_tool_utils import LOGGER
from postgres import Postgres

env_path = os.getenv('DOT_ENV', '.env')
if env_path and os.path.exists(env_path):
    dotenv.load_dotenv(dotenv_path=env_path, override=True, verbose=True)


@task(help={
    'verbose': "bool flag", 'debug': 'bool flag', 'profile': 'str', 'region': 'str',
    'host': 'str', 'database': 'str',
    'username': 'str', 'port': 'int',
    'password_secret': 'str',
    'oldpassword_secret': 'str',
})
def check_db_password(context,
                      host='PowerBI-Database-5220580aeddf840b.elb.us-west-2.amazonaws.com', username='roadsync',
                      database=None, port=5432,
                      password_secret='rds/app-prod/password', oldpassword_secret='rds/app-prod/oldpassword',
                      profile=None, region=os.getenv('AWS_DEFAULT_REGION'), verbose=False, debug=False):
    LOGGER.info(region)
    boto3.setup_default_session(profile_name=profile)
    session = boto3.DEFAULT_SESSION
    client = session.client('secretsmanager', region_name=region)
    response = client.list_secrets(
        SortOrder='asc'
    )
    ss = {s['Name'] for s in response['SecretList']}
    LOGGER.info(ss)
    assert len({password_secret, oldpassword_secret} & ss) == 2, f'{{{password_secret}, {oldpassword_secret}}}'
    response = client.get_secret_value(
        SecretId=password_secret,
        # VersionId='string',
        # VersionStage='string'
    )
    password = response['SecretString']
    response = client.get_secret_value(
        SecretId=oldpassword_secret,
        # VersionId='string',
        # VersionStage='string'
    )
    oldpassword = response['SecretString']
    LOGGER.info('Got both passwords')

    # postgresql://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]
    try:
        try:
            pg = Postgres(url=f'postgresql://{username}:{oldpassword}@{host}:{port}')
            LOGGER.info(f'Old password valid!')
            pg.run(f"ALTER ROLE {username} WITH PASSWORD '{password}'")
            pg = Postgres(url=f'postgresql://{username}:{password}@{host}:{port}')
            LOGGER.info(f'New password valid!')
        except psycopg2.OperationalError as e:
            LOGGER.warning(f'Old password not valid!: {e}')
            pg = Postgres(url=f'postgresql://{username}:{password}@{host}:{port}')
            LOGGER.info(f'New password valid!')
    except psycopg2.DatabaseError as e:
        LOGGER.error(e)
