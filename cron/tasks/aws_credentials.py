import json

import os
import boto3
import dotenv
from invoke import task

env_path = os.getenv('DOT_ENV', '.env')
if env_path and os.path.exists(env_path):
    dotenv.load_dotenv(dotenv_path=env_path, override=True, verbose=True)
from .snapshots_tool_utils import LOGGER


@task(help={'verbose': "bool flag", 'debug': 'bool flag', 'profile': 'str', 'region': 'str'})
def aws_credentials(context, profile=None, region=None, verbose=False, debug=False):
  """
  Do some invoke recon
  """
  boto3.setup_default_session(profile_name=profile)
  session = boto3.DEFAULT_SESSION
  credentials = session.get_credentials()

  client = session.client('sts', region_name=region, api_version=None,
                                        use_ssl=True, verify=None, endpoint_url=None,
                                        aws_access_key_id=credentials.access_key, aws_secret_access_key=credentials.secret_key,
                                        aws_session_token=credentials.token, config=None)
  response = client.get_caller_identity()
  LOGGER.info(json.dumps(response, indent=2))
