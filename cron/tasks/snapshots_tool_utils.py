'''
Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''


# snapshots_tool_utils
# Support module for the Snapshot Tool for RDS

import boto3
from datetime import datetime, timedelta
import os
import logging
import re


# Initialize everything
import botocore

_LOGLEVEL = os.getenv('LOG_LEVEL', 'ERROR').strip()

_DESTINATION_REGION = os.getenv(
    'DEST_REGION', os.getenv('AWS_DEFAULT_REGION', '')).strip()

_KMS_KEY_DEST_REGION = os.getenv('KMS_KEY_DEST_REGION', 'None').strip()

_KMS_KEY_SOURCE_REGION = os.getenv('KMS_KEY_SOURCE_REGION', 'None').strip()

_TIMESTAMP_FORMAT = '%Y-%m-%d-%H-%M'

if os.getenv('REGION_OVERRIDE', 'NO') != 'NO':
    _REGION = os.getenv('REGION_OVERRIDE').strip()
else:
    _REGION = os.getenv('AWS_DEFAULT_REGION')

_SUPPORTED_ENGINES = [ 'mariadb', 'sqlserver-se', 'sqlserver-ee', 'sqlserver-ex', 'sqlserver-web', 'mysql', 'oracle-se', 'oracle-se1', 'oracle-se2', 'oracle-ee', 'postgres' ]


def logger_set_formatter(logger=None):
    handlers = logger.handlers
    if len(handlers) == 0:
        # noinspection PyUnresolvedReferences
        handlers = logger.root.handlers
    for handler in handlers:
        formatter = handler.formatter
        if not 'lineno' in formatter._fmt:
            formatter._fmt = re.sub(r'(\\t|\t)%\(asctime\)s\.%\(msecs\)dZ', '',
                                    re.sub(r'(%\(message\)s\n?)', '%(pathname)s:%(lineno)d:: \\1', formatter._fmt))
        if getattr(formatter, '_style', None):
            if not 'lineno' in formatter._style._fmt:
                formatter._style._fmt = re.sub(r'(\\t|\t)%\(asctime\)s\.%\(msecs\)dZ', '',
                                               re.sub(r'(%\(message\)s\n?)', '%(pathname)s:%(lineno)d:: \\1',
                                                      formatter._style._fmt))

# --- LOGGER
on_aws_lambda = any((os.getenv('AWS_LAMBDA_LOG_GROUP_NAME', None), os.getenv('AWS_LAMBDA_LOG_GROUP_NAME', None),
                     os.getenv('AWS_LAMBDA_LOG_GROUP_NAME', None)))
if not on_aws_lambda:
    logging.basicConfig(format="\n[%(levelname)s] %(pathname)s:%(lineno)d:: %(message)s", level=logging.INFO)
else:
    logging.basicConfig(format="%(pathname)s:%(lineno)d:: %(message)s", level=logging.INFO)
# LOGGER = structlog.get_logger()
LOGGER = logging.getLogger()
LOGGER.setLevel(_LOGLEVEL.upper())
logger_set_formatter(logger=LOGGER)
logger = LOGGER


class SnapshotToolException(Exception):
    pass


def search_tag_copydbsnapshot(response):
# Takes a list_tags_for_resource response and searches for our CopyDBSnapshot tag
    try:

        for tag in response['TagList']:
            if tag['Key'] == 'CopyDBSnapshot' and tag['Value'] == 'True': return True

    except Exception: return False

    else: return False



def search_tag_created(response):
# Takes a describe_db_snapshots response and searches for our CreatedBy tag
    try:

        for tag in response['TagList']:
            if tag['Key'] == 'CreatedBy' and tag['Value'] == 'Snapshot Tool for RDS': return True

    except Exception: return False

    else: return False



def search_tag_shared(response):
# Takes a describe_db_snapshots response and searches for our shareAndCopy tag
    try:
        for tag in response['TagList']:
            if tag['Key'] == 'shareAndCopy' and tag['Value'] == 'YES':
                for tag2 in response['TagList']:
                    if tag2['Key'] == 'CreatedBy' and tag2['Value'] == 'Snapshot Tool for RDS':
                        return True

    except Exception:
        return False

    return False



def search_tag_copied(response):
# Search for a tag indicating we copied this snapshot
    try:
        for tag in response['TagList']:
            if tag['Key'] == 'CopiedBy' and tag['Value'] == 'Snapshot Tool for RDS':
                return True

    except Exception:
        return False

    return False

def get_own_snapshots_no_x_account(pattern, response, REGION):
    # Filters our own snapshots
    filtered = {}
    for snapshot in response['DBSnapshots']:

        if snapshot['SnapshotType'] == 'manual' and re.search(pattern, snapshot['DBInstanceIdentifier']) and snapshot['Engine'] in _SUPPORTED_ENGINES:
            client = boto3.client('rds', region_name=REGION)
            response_tags = client.list_tags_for_resource(
                ResourceName=snapshot['DBSnapshotArn'])

            if search_tag_created(response_tags):
                filtered[snapshot['DBSnapshotIdentifier']] = {
                    'Arn': snapshot['DBSnapshotArn'], 'Status': snapshot['Status'], 'DBInstanceIdentifier': snapshot['DBInstanceIdentifier']}
        #Changed the next line to search for ALL_CLUSTERS or ALL_SNAPSHOTS so it will work with no-x-account
        elif snapshot['SnapshotType'] == 'manual' and pattern == 'ALL_SNAPSHOTS' and snapshot['Engine'] in _SUPPORTED_ENGINES:
            client = boto3.client('rds', region_name=REGION)
            response_tags = client.list_tags_for_resource(
                ResourceName=snapshot['DBSnapshotArn'])

            if search_tag_created(response_tags):
                filtered[snapshot['DBSnapshotIdentifier']] = {
                    'Arn': snapshot['DBSnapshotArn'], 'Status': snapshot['Status'], 'DBInstanceIdentifier': snapshot['DBInstanceIdentifier']}

    return filtered


def get_shared_snapshots(pattern, response):
# Returns a dict with only shared snapshots filtered by pattern, with DBSnapshotIdentifier as key and the response as attribute
    filtered = {}
    for snapshot in response['DBSnapshots']:
        if snapshot['SnapshotType'] == 'shared' and re.search(pattern, snapshot['DBInstanceIdentifier']) and snapshot['Engine'] in _SUPPORTED_ENGINES:
            filtered[get_snapshot_identifier(snapshot)] = {
                'Arn': snapshot['DBSnapshotIdentifier'], 'Encrypted': snapshot['Encrypted'], 'DBInstanceIdentifier': snapshot['DBInstanceIdentifier']}
            if snapshot['Encrypted'] is True:
                filtered[get_snapshot_identifier(snapshot)]['KmsKeyId'] = snapshot['KmsKeyId']

        elif snapshot['SnapshotType'] == 'shared' and pattern == 'ALL_SNAPSHOTS' and snapshot['Engine'] in _SUPPORTED_ENGINES:
            filtered[get_snapshot_identifier(snapshot)] = {
                'Arn': snapshot['DBSnapshotIdentifier'], 'Encrypted': snapshot['Encrypted'], 'DBInstanceIdentifier': snapshot['DBInstanceIdentifier']}
            if snapshot['Encrypted'] is True:
                filtered[get_snapshot_identifier(snapshot)]['KmsKeyId'] = snapshot['KmsKeyId']
    return filtered



def get_snapshot_identifier(snapshot):
# Function that will return the RDS Snapshot identifier given an ARN
    match = re.match('arn:aws:rds:.*:.*:snapshot:(.+)',
                     snapshot['DBSnapshotArn'])
    return match.group(1)


def get_own_snapshots_dest(pattern, response):
# Returns a dict  with local snapshots, filtered by pattern, with DBSnapshotIdentifier as key and Arn, Status as attributes
    filtered = {}
    for snapshot in response['DBSnapshots']:

        if snapshot['SnapshotType'] == 'manual' and re.search(pattern, snapshot['DBInstanceIdentifier']) and snapshot['Engine'] in _SUPPORTED_ENGINES:
            filtered[snapshot['DBSnapshotIdentifier']] = {
                'Arn': snapshot['DBSnapshotArn'], 'Status': snapshot['Status'], 'Encrypted': snapshot['Encrypted'], 'DBInstanceIdentifier': snapshot['DBInstanceIdentifier']}

            if snapshot['Encrypted'] is True:
                filtered[snapshot['DBSnapshotIdentifier']]['KmsKeyId'] = snapshot['KmsKeyId']

        elif snapshot['SnapshotType'] == 'manual' and pattern == 'ALL_SNAPSHOTS' and snapshot['Engine'] in _SUPPORTED_ENGINES:
            filtered[snapshot['DBSnapshotIdentifier']] = {
                'Arn': snapshot['DBSnapshotArn'], 'Status': snapshot['Status'], 'Encrypted': snapshot['Encrypted'], 'DBInstanceIdentifier': snapshot['DBInstanceIdentifier'] }

            if snapshot['Encrypted'] is True:
                filtered[snapshot['DBSnapshotIdentifier']]['KmsKeyId'] = snapshot['KmsKeyId']

    return filtered

def filter_instances(taggedinstance, pattern, instance_list):
# Takes the response from describe-db-instances and filters according to pattern in DBInstanceIdentifier
    filtered_list = []

    for instance in instance_list['DBInstances']:

        if taggedinstance == 'TRUE':
            client = boto3.client('rds', region_name=_REGION)
            response = client.list_tags_for_resource(ResourceName=instance['DBInstanceArn'])

        if pattern == 'ALL_INSTANCES' and instance['Engine'] in _SUPPORTED_ENGINES:
            if (taggedinstance == 'TRUE' and search_tag_copydbsnapshot(response)) or taggedinstance == 'FALSE':
                filtered_list.append(instance)

        else:
            match = re.search(pattern, instance['DBInstanceIdentifier'])

            if match and instance['Engine'] in _SUPPORTED_ENGINES:
                if (taggedinstance == 'TRUE' and search_tag_copydbsnapshot(response)) or taggedinstance == 'FALSE':
                    filtered_list.append(instance)

    return filtered_list


def get_own_snapshots_source(pattern, response, backup_interval=None, check_tags=True):
# Filters our own snapshots
    filtered = {}

    client = boto3.client('rds', region_name=_REGION)
    for snapshot in response['DBSnapshots']:
        
        # No need to consider snapshots that are still in progress
        if 'SnapshotCreateTime' not in snapshot:
            continue

        # No need to get tags for snapshots outside of the backup interval
        if backup_interval and snapshot['SnapshotCreateTime'].replace(tzinfo=None) < datetime.utcnow().replace(tzinfo=None) - timedelta(hours=backup_interval):
            continue

        if (snapshot['SnapshotType'] in {'manual', 'shared'}
            and (
                re.search(pattern, snapshot['DBInstanceIdentifier'])
            or
                (pattern == 'ALL_CLUSTERS' or pattern == 'ALL_SNAPSHOTS' or pattern == 'ALL_INSTANCES'))
            and snapshot['Engine'] in _SUPPORTED_ENGINES
        ):
            response_tags = {'TagList': []}
            if snapshot.get('TagList', None) is not None:
                response_tags = snapshot
            else:
                if check_tags:
                    try:
                        response_tags = client.list_tags_for_resource(
                            ResourceName=snapshot['DBSnapshotArn'])
                    except botocore.exceptions.ClientError as ce:
                        msg = '{} :{}'.format(snapshot['DBSnapshotArn'], str(ce))
                        if (    ce.response.get('Error')
                            and ce.response['Error'].get('Code')
                            and ce.response['Error']['Code'] == 'InvalidParameterValue'
                        ):
                            logger.info(msg)
                        else:
                            logger.error(msg)
            tags_matched = not check_tags
            if not tags_matched:
                tags_matched = search_tag_created(response_tags)
            if tags_matched:
                filtered[snapshot['DBSnapshotIdentifier']] = {
                    **{'Arn': snapshot['DBSnapshotArn']},
                    **snapshot
                }

    return filtered


def get_timestamp_no_minute(snapshot_identifier, snapshot_list):
# Get a timestamp from the name of a snapshot and strip out the minutes
    pattern = '%s-(.+)-\d{2}' % snapshot_list[snapshot_identifier]['DBInstanceIdentifier']
    timestamp_format = '%Y-%m-%d-%H'
    date_time = re.search(pattern, snapshot_identifier)

    if date_time is not None:
        return datetime.strptime(date_time.group(1), timestamp_format)


def get_timestamp(snapshot_identifier, snapshot_list):
# Searches for a timestamp on a snapshot name
    pattern = '%s-(.+)' % snapshot_list[snapshot_identifier]['DBInstanceIdentifier']
    date_time = re.search(pattern, snapshot_identifier)

    if date_time is not None:

        try:
            return datetime.strptime(date_time.group(1), _TIMESTAMP_FORMAT)

        except Exception:
            return None

    return None



def snapshot_get_timestamp(snapshot):
    # Searches for a timestamp on a snapshot name
    pattern = '%s-(.+)' % snapshot['DBInstanceIdentifier']
    date_time = re.search(pattern, snapshot_identifier(snapshot))

    if date_time is not None:

        try:
            return datetime.strptime(date_time.group(1), _TIMESTAMP_FORMAT)

        except Exception:
            return None

    return None



def get_latest_snapshot_ts(instance_identifier, filtered_snapshots):
# Get latest snapshot for a specific DBInstanceIdentifier
    timestamps = []

    for snapshot,snapshot_object in filtered_snapshots.items():

        if snapshot_object['DBInstanceIdentifier'] == instance_identifier:
            timestamp = get_timestamp_no_minute(snapshot, filtered_snapshots)

            if timestamp is not None:
                timestamps.append(timestamp)

    if len(timestamps) > 0:
        return max(timestamps)

    else:
        return None



def requires_backup(backup_interval, instance, filtered_snapshots):
# Returns True if latest snapshot is older than INTERVAL
    latest = get_latest_snapshot_ts(instance['DBInstanceIdentifier'], filtered_snapshots)

    if latest is not None:
        backup_age = datetime.now() - latest

        if backup_age.total_seconds() >= (backup_interval * 60 * 60):
            return True

        else:
            return False

    elif latest is None:
        return True


def requires_restore(restore_interval, instance, filtered_snapshots):
    # Returns True if latest snapshot is older than INTERVAL
    latest = get_latest_snapshot_ts(instance['DBInstanceIdentifier'], filtered_snapshots)

    if latest is not None:
        restore_age = datetime.now() - latest

        if restore_age.total_seconds() >= (restore_interval * 60 * 60):
            return True

        else:
            return False

    elif latest is None:
        return True


def paginate_api_call(client, api_call, objecttype, *args, **kwargs):
#Takes an RDS boto client and paginates through api_call calls and returns a list of objects of objecttype
    response = {}
    response[objecttype] = []

    # Create a paginator
    paginator = client.get_paginator(api_call)

    # Create a PageIterator from the Paginator
    page_iterator = paginator.paginate(**kwargs)
    for page in page_iterator:
        for item in page[objecttype]:
            response[objecttype].append(item)

    return response


def copy_local(snapshot_identifier, snapshot_object):
    client = boto3.client('rds', region_name=_REGION)

    tags = [{
            'Key': 'CopiedBy',
            'Value': 'Snapshot Tool for RDS'
        }]

    if snapshot_object['Encrypted']:
        logger.info('Copying encrypted snapshot %s locally' % snapshot_identifier)
        response = client.copy_db_snapshot(
            SourceDBSnapshotIdentifier = snapshot_object['Arn'],
            TargetDBSnapshotIdentifier = snapshot_identifier,
            KmsKeyId = _KMS_KEY_SOURCE_REGION,
            Tags = tags)

    else:
        logger.info('Copying snapshot %s locally' %snapshot_identifier)
        response = client.copy_db_snapshot(
            SourceDBSnapshotIdentifier = snapshot_object['Arn'],
            TargetDBSnapshotIdentifier = snapshot_identifier,
            Tags = tags)

    return response



def copy_remote(snapshot_identifier, snapshot_object):
    client = boto3.client('rds', region_name=_DESTINATION_REGION)

    if snapshot_object['Encrypted']:
        logger.info('Copying encrypted snapshot %s to remote region %s' % (snapshot_object['Arn'], _DESTINATION_REGION))
        response = client.copy_db_snapshot(
            SourceDBSnapshotIdentifier = snapshot_object['Arn'],
            TargetDBSnapshotIdentifier = snapshot_identifier,
            KmsKeyId = _KMS_KEY_DEST_REGION,
            SourceRegion = _REGION,
            CopyTags = True)

    else:
        logger.info('Copying snapshot %s to remote region %s' % (snapshot_object['Arn'], _DESTINATION_REGION))
        response = client.copy_db_snapshot(
            SourceDBSnapshotIdentifier = snapshot_object['Arn'],
            TargetDBSnapshotIdentifier = snapshot_identifier,
            SourceRegion = _REGION,
            CopyTags = True)

    return response


def snapshot_identifier(snapshot):
    if isinstance(snapshot, dict):
        id = snapshot.get('DBSnapshotIdentifier')
    else:
        id = snapshot
    if not id:
        return None
    if 'arn:' in id:
        parser = botocore.utils.ArnParser()
        parts = parser.parse_arn(id)
        id = parts['resource'].split(':')[-1]

    return id