'''
Copyright 2021 Roadsync, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

# restore_snapshots_rds
# This Lambda function restores snapshots within the account. These snapshots can be created, or shared and copied by other stacks in the rds-snapshot-tool family possibly in other accounts.
import os
if __name__ == '__main__':
    import dotenv

    env_path = os.getenv('DOT_ENV', '.env')
    if env_path:
        dotenv.load_dotenv(dotenv_path=env_path, override=True, verbose=True)

import traceback
import json
from botocore.exceptions import ClientError
from snapshots_tool_utils import *

# Initialize from environment variable
LOGLEVEL = os.getenv('LOG_LEVEL', 'WARNING').strip().upper()
SNAPSHOT_TYPE = str(os.getenv('SNAPSHOT_TYPE', 'manual')).strip()
RESTORE_INTERVAL = int(os.getenv('RESTORE_INTERVAL', 0))
SNAPSHOT_PATTERN = os.getenv('SNAPSHOT_PATTERN', 'ALL_INSTANCES')
DB_PATTERN = os.getenv('DB_PATTERN', 'NO_INSTANCES')
TAGGEDINSTANCE = os.getenv('TAGGEDINSTANCE', 'FALSE')
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
                    onl = [ on for on in snapshot_map[ssid] if on['new'] == ss_id]
                    if dbid == ss_id:
                        # Found a db for this snapshot! "Update" (NOP if ss_id already restored)
                        if not any(onl):
                            snapshot_map[ssid].append({
                                'old': None,
                                'new': ss_id
                            })
                    else:
                        # Replace (If dbid is None then Create)
                        if not any(onl):
                            snapshot_map[ssid].append({
                                'old': dbid,
                                'new': ss_id
                            })
    logger.info(json.dumps(snapshot_map))
    # With this set of snapshots, old and new DB's we can go to work
    if snapshot_map:
        for ssid, dbsl in snapshot_map.items():
            ss = filtered_snapshots[ssid]
            for dbs in dbsl:
                if dbs['new']:
                    db_identifier = dbs['new']
                    # Are we working with the existing instance?
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
                        # 1. Do we have any restores already in flight for this DB? If so bypass
                        db_inst = check_on_db_instance(db_identifier)
                        if not db_inst:
                            fresh_inst = None
                            for inst in filtered_instances:
                                inst_create_time = inst['InstanceCreateTime'].replace(tzinfo=None)
                                freshness_window = datetime.utcnow().replace(tzinfo=None)
                                if RESTORE_INTERVAL:
                                    freshness_window -= timedelta(hours=RESTORE_INTERVAL)
                                if RESTORE_INTERVAL and inst_create_time > freshness_window:
                                    fresh_inst = inst
                                    db_inst = inst if not db_inst else db_inst
                            if not fresh_inst:
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
                                        logger.error(ce)
                                        raise ce
                                    db_inst = check_on_db_instance(db_identifier)
                                except Exception as e:
                                    LOGGER.info(traceback.format_tb(e.__traceback__))
                                    logger.error('Could not restore snapshot %s (%s)' % (snapshot_identifier, e))
                                    pending_restores += 1
                        if db_inst:
                            try:
                                # 4. If the restore of the snapshot is complete then potentially switch the ILB
                                if LOAD_BALANCER:
                                    switch_load_balancer(LOAD_BALANCER, ss, db_inst)
                                # 5. Now kill the old DB
                                if dbs['old'] and not (db_inst and dbs['old'] == db_inst['DBInstanceIdentifier']):
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
