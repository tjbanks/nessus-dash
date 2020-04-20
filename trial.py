from app import settings
from sqlalchemy import create_engine
import pandas as pd

nessus_table = settings.OMNIANA_NESSUS_TABLE
nessus_history_table = settings.OMNIANA_HISTORY_TABLE

database = settings.NESSUS_SQLALCHEMY_PATH

engine = create_engine('sqlite:///'+database, echo=False)

import pdb;pdb.set_trace()
