from app import settings
from sqlalchemy import create_engine
import pandas as pd
import numpy as np 

nessus_table = settings.OMNIANA_NESSUS_TABLE
nessus_history_table = settings.OMNIANA_HISTORY_TABLE

database = settings.NESSUS_SQLALCHEMY_PATH

engine = create_engine("sqlite:///"+database, echo=False)

from app.utils.nessus import Plots

df = Plots.get_latest_vulnerabilities_data(engine)

def explode(df, lst_cols, fill_value='', preserve_index=False):
    # make sure `lst_cols` is list-alike
    if (lst_cols is not None
        and len(lst_cols) > 0
        and not isinstance(lst_cols, (list, tuple, np.ndarray, pd.Series))):
        lst_cols = [lst_cols]
    # all columns except `lst_cols`
    idx_cols = df.columns.difference(lst_cols)
    # calculate lengths of lists
    lens = df[lst_cols[0]].str.len()
    # preserve original index values
    idx = np.repeat(df.index.values, lens)
    # create "exploded" DF
    res = (pd.DataFrame({
                col:np.repeat(df[col].values, lens)
                for col in idx_cols},
                index=idx)
             .assign(**{col:np.concatenate(df.loc[lens>0, col].values)
                            for col in lst_cols}))
    # append those rows that have empty lists
    if (lens == 0).any():
        # at least one list in cells is empty
        res = (res.append(df.loc[lens==0, idx_cols], sort=False)
                  .fillna(fill_value))
    # revert the original index order
    res = res.sort_index()
    # reset index if requested
    if not preserve_index:
        res = res.reset_index(drop=True)
    return res

df['Exploitable'] = (df['Metasploit']==True) | (df['Core Impact']==True) |(df['CANVAS']==True)

df = df[['Plugin ID','CVE','CVSS','Risk','Host','Synopsis','Scan','MSKB','Plugin Publication Date','Exploitable']]
df.dropna(subset=['MSKB'],inplace=True)
df = explode(df.assign(MSKB=df.MSKB.str.split(';')),'MSKB')
import pdb;pdb.set_trace()
