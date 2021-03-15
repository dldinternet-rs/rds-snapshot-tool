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
import socket
import botocore
from botocore.utils import ArnParser, InvalidArnException
from botocore.exceptions import ClientError

# Initialize everything

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

MAX_WAIT = int(os.getenv('MAX_WAIT', 300)) - 1
TIMESTAMP_FORMAT = '%Y-%m-%d-%H-%M'
if os.getenv('REGION_OVERRIDE', 'NO') != 'NO':
    REGION = os.getenv('REGION_OVERRIDE').strip()
else:
    REGION = os.getenv('AWS_DEFAULT_REGION')

def get_ipv4_by_hostname(hostname):
    # see `man getent` `/ hosts `
    # see `man getaddrinfo`

    l = (
        i        # raw socket structure
        [4]  # internet protocol info
        [0]  # address
        for i in
        socket.getaddrinfo(
            hostname,
            0  # port, required
        )
        if i[0] is socket.AddressFamily.AF_INET  # ipv4

           # ignore duplicate addresses with other socket types
           and i[1] in {socket.SocketKind.SOCK_RAW,socket.SocketKind.SOCK_STREAM,}
    )
    return list(l)


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


def check_on_db_instance(db_identifier, max_wait=MAX_WAIT, region=REGION):
    client = boto3.client('rds', region_name=region)
    response = client.describe_db_instances(
        Filters=[
            {
                'Name': 'db-instance-id',
                'Values': [db_identifier]
            },
        ]
    )
    if response['DBInstances']:
        db_inst = response['DBInstances'][0]
        state = db_inst['DBInstanceStatus']
        if state != 'available':
            logger.info(f"{db_identifier} in {state}, not available for modification, waiting")
            waiter = client.get_waiter('db_instance_available')
            max_att = int(max_wait / 5)
            waiter.wait(
                DBInstanceIdentifier=db_identifier,
                WaiterConfig={'Delay': 5, 'MaxAttempts': max_att}
            )
    else:
        msg = '{} restore not started?'.format(db_identifier)
        logger.error(msg)
        # raise Exception(msg)
        return None
    return db_inst


def switch_load_balancer(lb, ss, db, region=REGION):
    elbv2 = boto3.client('elbv2', region_name=region)
    try:
        try:
            parts = ArnParser().parse_arn(lb)
            elb = parts['resource']
            response = elbv2.describe_load_balancers(
                LoadBalancerArns=[
                    lb,
                ],
            )
        except InvalidArnException:
            response = elbv2.describe_load_balancers(
                # LoadBalancerArns=[
                #    LOAD_BALANCER,
                # ],
                Names=[
                    lb,
                ],
            )
        if response['LoadBalancers']:
            ilb = response['LoadBalancers'][0]
            logger.info(ilb)
            lba = ilb['LoadBalancerArn']
            response = elbv2.describe_listeners(
                LoadBalancerArn=lba,
            )
            if response['Listeners']:
                listeners = [ l for l in response['Listeners'] if l['Port'] == ss['Port']]
                logger.info(listeners)
                if listeners:
                    for lsn in listeners:
                        for act in lsn['DefaultActions']:
                            if act['Type'] == 'forward':
                                tga = act['TargetGroupArn']
                                response = elbv2.describe_target_groups(
                                    # LoadBalancerArn=lba,
                                    TargetGroupArns=[
                                        tga,
                                    ],
                                )
                                if response['TargetGroups']:
                                    tg = response['TargetGroups'][0]
                                    logger.info(tg)
                                    response = elbv2.describe_target_health(
                                        TargetGroupArn=tga,
                                    )
                                    if response['TargetHealthDescriptions']:
                                        thds = response['TargetHealthDescriptions']
                                        ips = set(get_ipv4_by_hostname(db['Endpoint']['Address']))
                                        tis = set([
                                            t['Target']['Id']
                                            for t in thds
                                            if t['TargetHealth']['State'] not in {'draining'}])
                                        if len(ips & tis) != len(ips):
                                            for thd in thds:
                                                tgt = thd['Target']
                                                logger.info(tgt)
                                                response = elbv2.deregister_targets(
                                                    TargetGroupArn=tga,
                                                    Targets=[
                                                        {
                                                            'Id': tgt['Id'],
                                                            # 'Port': 123,
                                                            # 'AvailabilityZone': 'string'
                                                        },
                                                    ]
                                                )
                                            for ip in ips:
                                                response = elbv2.register_targets(
                                                    TargetGroupArn=tga,
                                                    Targets=[
                                                        {
                                                            'Id': ip,
                                                            'Port': db['Endpoint']['Port'],
                                                            'AvailabilityZone': db['AvailabilityZone']
                                                        },
                                                    ]
                                                )
    except ClientError as ce:
        logger.error(ce)


def delete_old_db(db_identifier, region=REGION):
    client = boto3.client('rds', region_name=region)
    response = client.describe_db_instances(
        Filters=[
            {
                'Name': 'db-instance-id',
                'Values': [db_identifier]
            },
        ]
    )
    if response['DBInstances']:
        db_inst = response['DBInstances'][0]
        state = db_inst['DBInstanceStatus']
        if state not in {'available', 'deleting'}:
            raise Exception('This database is not available: {}'.format(db_identifier))
        if state in {'available'}:
            response = client.delete_db_instance(
                DBInstanceIdentifier=db_identifier,
                SkipFinalSnapshot=True,
                # FinalDBSnapshotIdentifier='string',
                DeleteAutomatedBackups=True
            )
            if response['DBInstance']:
                logger.warning(f"Deleting {response['DBInstance']['DBInstanceIdentifier']}")
        else:
            logger.info(f'{db_identifier} is {state}')
    else:
        msg = '{} old DB not found?!'.format(db_identifier)
        logger.error(msg)
        raise Exception(msg)
    return True
