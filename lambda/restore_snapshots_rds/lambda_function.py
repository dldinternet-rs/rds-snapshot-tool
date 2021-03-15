'''
Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

# share_snapshots_rds
# This Lambda function shares snapshots created by aurora_take_snapshot with the account set in the environment variable DEST_ACCOUNT
# It will only share snapshots tagged with shareAndCopy and a value of YES
import json
from botocore.exceptions import ClientError
from botocore.utils import ArnParser, InvalidArnException
from snapshots_tool_utils import *

if __name__ == '__main__':
    import dotenv

    env_path = os.getenv('DOT_ENV', '.env')
    if env_path:
        dotenv.load_dotenv(dotenv_path=env_path, override=True, verbose=True)

# Initialize from environment variable
LOGLEVEL = os.getenv('LOG_LEVEL', 'WARNING').strip().upper()
SNAPSHOT_TYPE = str(os.getenv('SNAPSHOT_TYPE', 'manual')).strip()
RESTORE_INTERVAL = int(os.getenv('INTERVAL', '24'))
SNAPSHOT_PATTERN = os.getenv('SNAPSHOT_PATTERN', 'ALL_INSTANCES')
DB_PATTERN = os.getenv('DB_PATTERN', 'NO_INSTANCES')
TAGGEDINSTANCE = os.getenv('TAGGEDINSTANCE', 'FALSE')
MAX_WAIT = int(os.getenv('MAX_WAIT', 300))
LOAD_BALANCER = os.getenv('LOAD_BALANCER', None)
SNAPSHOT_DB_MAP = os.getenv('SNAPSHOT_DB_MAP', '{ ".*": null }')
try:
    SNAPSHOT_DB_MAP = json.loads(SNAPSHOT_DB_MAP)
except Exception as e:
    logger.error('Invalid SNAPSHOT_DB_MAP: {}'.format(str(e)))
    exit(1)
RESTORE_ARGS = os.getenv('RESTORE_ARGS', None)
if isinstance(RESTORE_ARGS, str):
    try:
        RESTORE_ARGS = json.loads(RESTORE_ARGS)
    except Exception as e:
        logger.error('Invalid RESTORE_ARGS: {}'.format(str(e)))
        exit(1)
else:
    RESTORE_ARGS = {
        'DBInstanceClass': 'db.t3.medium',
        #'AvailabilityZone': 'string',
        #'DBSubnetGroupName': 'string',
        'MultiAZ': False,
        'PubliclyAccessible': False,
        'AutoMinorVersionUpgrade': True,
        # 'LicenseModel': 'string',
        # 'Engine': 'string',
        # 'Port': 5432,
        # 'Iops': 123,
        # 'OptionGroupName': 'string',
    }
logger = LOGGER
if os.getenv('REGION_OVERRIDE', 'NO') != 'NO':
    REGION = os.getenv('REGION_OVERRIDE').strip()
else:
    REGION = os.getenv('AWS_DEFAULT_REGION')
TIMESTAMP_FORMAT = '%Y-%m-%d-%H-%M'
import socket

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


def check_on_db_instance(db_identifier):
    client = boto3.client('rds', region_name=REGION)
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
            max_att = int(MAX_WAIT / 5)
            waiter.wait(
                DBInstanceIdentifier=db_identifier,
                WaiterConfig={'Delay': 5, 'MaxAttempts': max_att}
            )
    else:
        msg = '{} restore not started?'.format(db_identifier)
        logger.error(msg)
        raise Exception(msg)
    return db_inst


def switch_load_balancer(lb, ss, db):
    elbv2 = boto3.client('elbv2', region_name=REGION)
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


def delete_old_db(db_identifier):
    client = boto3.client('rds', region_name=REGION)
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
            raise Exception('This database is not available: {}'.format(db_identifier))
        response = client.delete_db_instance(
            DBInstanceIdentifier=db_identifier,
            SkipFinalSnapshot=True,
            # FinalDBSnapshotIdentifier='string',
            DeleteAutomatedBackups=True
        )
        if response['DBInstance']:
           logger.warning(json.dumps(response['DBInstance']))
    else:
        msg = '{} old DB not found?!'.format(db_identifier)
        logger.error(msg)
        raise Exception(msg)
    return True


def lambda_handler(event, context):
    client = boto3.client('rds', region_name=REGION)
    response = paginate_api_call(client, 'describe_db_snapshots', 'DBSnapshots',
                                 SnapshotType=SNAPSHOT_TYPE, IncludeShared=(SNAPSHOT_TYPE == 'shared'))
    filtered_snapshots = get_own_snapshots_source(SNAPSHOT_PATTERN, response, check_tags=False)
    # Get the newest snapshot for each DB
    db_snapshots = {}
    for ssid, ss in filtered_snapshots.items():
        db_snapshots[ss['DBInstanceIdentifier']] = db_snapshots.get(ss['DBInstanceIdentifier'], [])
        db_snapshots[ss['DBInstanceIdentifier']].append(ss)
    filtered_snapshots = {}
    for db, sss in db_snapshots.items():
        sss = sorted(sss, key=lambda ss: snapshot_get_timestamp(ss))
        ss = sss[-1]
        filtered_snapshots[ss['DBSnapshotIdentifier']] = ss

    logger.info('Filtered snapshots: {}'.format(len(filtered_snapshots)))

    response = paginate_api_call(client, 'describe_db_instances', 'DBInstances')
    now = datetime.now()
    pending_restores = 0
    filtered_instances = filter_instances(TAGGEDINSTANCE, DB_PATTERN, response)

    # Now we need to match each snapshot to a DB (which may not exist)
    snapshot_map = {}
    for ssre, dbre in SNAPSHOT_DB_MAP.items():
        for ssid, ss in filtered_snapshots.items():
            ss_id = snapshot_identifier(ssid)
            snapshot_map[ssid] = snapshot_map.get(ssid, [])
            if re.search(ssre, ss_id):
                dbid = None
                for instance in filtered_instances:
                    dbid = instance.get('DBInstanceIdentifier')
                    if dbid and dbre and not re.search(dbre, dbid):
                        dbid = None
                    if dbid == ss_id:
                        # Found a db for this snapshot!
                        snapshot_map[ssid].append({
                            'old': dbid,
                            'new': ss_id
                        })
                    else:
                        snapshot_map[ssid].append({
                            'old': dbid,
                            'new': None
                        })
    logger.info(json.dumps(snapshot_map))
    # With this set of snapshots, old and new DB's we can go to work
    if snapshot_map:
        for ssid, dbsl in snapshot_map.items():
            ss = filtered_snapshots[ssid]
            for dbs in dbsl:
                if dbs['new']:
                    db_identifier = dbs['new']
                    # 1. Do we have any restores already in flight for this DB? If so bypass
                    if dbs['old'] == dbs['new']:
                        try:
                            db_inst = check_on_db_instance(db_identifier)
                            # 4. If the restore of the snapshot is complete then potentially switch the ILB
                            if LOAD_BALANCER:
                                switch_load_balancer(LOAD_BALANCER, ss, db_inst)
                        except ClientError as ce:
                            logger.error(ce)
                            pending_restores += 1
                        except Exception as e:
                            logger.error(e)
                            pending_restores += 1
                    else:
                        # 2. Restore the snapshot to a new DB with a snapshot derived name (or specified?)
                        try:
                            timestamp_format = now.strftime(TIMESTAMP_FORMAT)
                            try:
                                restore_args = {
                                    **RESTORE_ARGS,
                                    **{
                                        'LicenseModel': ss['LicenseModel'],
                                        'Engine': ss['Engine'],
                                        'Port': ss['Port'],
                                    }
                                }
                                logger.info(json.dumps(restore_args))
                                response = client.restore_db_instance_from_db_snapshot(
                                    DBSnapshotIdentifier=snapshot_identifier(ssid),
                                    DBInstanceIdentifier=db_identifier,
                                    Tags=[
                                        {'Key': 'CreatedBy', 'Value': 'Snapshot Tool for RDS'},
                                        {'Key': 'CreatedOn', 'Value': timestamp_format},
                                    ],
                                    **restore_args
                                )
                                logger.info(json.dumps(response))
                            except botocore.exceptions.ClientError as ce:
                                logger.error(e)
                                raise ce
                        except Exception as e:
                            pending_restores += 1
                            logger.info('Could not create snapshot %s (%s)' % (snapshot_identifier, e))

                        try:
                            db_inst = check_on_db_instance(db_identifier)
                            # 4. If the restore of the snapshot is complete then potentially switch the ILB
                            if LOAD_BALANCER:
                                switch_load_balancer(LOAD_BALANCER, ss, db_inst)
                            # 5. Now kill the old DB
                            delete_old_db(dbs['old'])
                        # 3. If the snapshot restore does not complete in a reasonable time (waiter.Wait) then give up and finish next time
                        except ClientError as ce:
                            logger.error(ce)
                            pending_restores += 1
                        except Exception as e:
                            logger.error(e)
                            pending_restores += 1
                elif dbs['old'] and dbs['new'] is None:
                    delete_old_db(dbs['old'])

    if pending_restores > 0:
        log_message = 'Could not completely restore every instance. Restores pending: %s' % pending_restores
        logger.warning(log_message)


if __name__ == '__main__':
    lambda_handler(None, None)
