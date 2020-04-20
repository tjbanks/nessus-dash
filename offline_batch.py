from app import settings
from app.utils.nessus import Batch
from sqlalchemy import create_engine

server = settings.NESSUS_SERVER
username = settings.NESSUS_USERNAME
password = settings.NESSUS_PASSWORD
folder_exclude = settings.NESSUS_FOLDER_EXCLUDE
scan_exclude = settings.NESSUS_SCAN_EXCLUDE
nessus_table = settings.OMNIANA_NESSUS_TABLE
nessus_history_table = settings.OMNIANA_HISTORY_TABLE

database = settings.NESSUS_SQLALCHEMY_PATH

engine = create_engine('sqlite:///'+database, echo=False)

Batch.run_batch(engine=engine,nessus_server=server,nessus_username=username,
        nessus_password=password,nessus_folder_exclude=folder_exclude,
        nessus_scan_exclude=scan_exclude,nessus_table=nessus_table,
        nessus_history_table=nessus_history_table)
