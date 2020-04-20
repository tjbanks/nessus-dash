from flask import current_app

import pandas as pd
from app import db

from app.extensions.nessusapi import Nessus
import json
import os
import sys
import time

import plotly.graph_objs as go 

class Plots:
    @staticmethod
    def get_figure_overall_vuln_trend(engine=None):
        """
        Return the parameters for plotly plot
        for the overall vulnerability trend
        """
        
        query = """
        SELECT 
        history_date,
        scan_name,
        Risk,
        COUNT(*) AS count
        FROM vulnerabilities 
        GROUP BY history_date,Risk 
        ORDER BY history_date,Risk
        """
        
        title = "Server CVE Count Trend"

        return Plots.vuln_trend(query,title,engine=engine)

    @staticmethod
    def get_figure_plugin_vuln_trend(engine=None):
        """
        Return the parameters for plotly plot
        for the overall vulnerability trend
        """
        
        query = """
        SELECT 
        history_date,
        scan_name,
        Risk,
        COUNT(*) AS count
        FROM (
            SELECT DISTINCT 
            \"Plugin ID\",
            Host,
            Risk,
            scan_name,
            history_date 
            FROM Vulnerabilities
            ) as i 
        GROUP BY history_date,Risk 
        ORDER BY history_date,Risk
        """

        title = "Server Plugin Count Trend"

        return Plots.vuln_trend(query,title,engine=engine)

    @staticmethod
    def vuln_trend(query,title,engine=None):
        """
        Returns:
        figure: plotly object
        """
        if engine is None:
            bind = current_app.config['NESSUS_SQLALCHEMY_BINDS']
            database = db.get_engine(bind=bind)
        else:
            database = engine
        df = pd.read_sql_query(query,database)
        df['Date'] = pd.to_datetime(df['history_date'],unit='s') - pd.to_timedelta(7, unit='d')
        df_weekly = df.groupby(['Risk', pd.Grouper(key='Date', freq='W-MON')])['count'].sum().reset_index().sort_values('Date')

        #risks = df['Risk'].unique().tolist()
        risks = ["Critical", "High", "Medium", "Low", "None"]
        ignored_risks = []
        colors = {"Critical":"red",
                "High":"orange",
                "Medium":"yellow",
                "Low":"green",
                "None":"blue"}
        visible = {"Critical":True,
                "High":True,
                "Medium":"legendonly",
                "Low":"legendonly",
                "None":"legendonly"}


        graph = []

        for risk in risks:
            if risk not in ignored_risks:
                df_temp = pd.DataFrame(df[df['Risk']==risk]
                    .groupby(['scan_name', pd.Grouper(key='Date', freq='W-MON')])['count'].last().reset_index()).groupby('Date').sum().reset_index()
                
                name = risk
                if risk == "None" or not name:
                    name = "Info"
                trace = go.Scatter(
                    x = df_temp['Date'].astype(str).tolist(),
                    y = df_temp['count'].tolist(),
                    mode = 'lines',
                    name = name,
                    line = dict(color=colors[risk]),
                    visible = visible[risk]
                )

                graph.append(trace)
                

        layout_one = dict(title=title,
            xaxis = dict(title="Date",type='date'),
            #autotick=False, tick0=1990, dtick=25),
            yaxis = dict(title='Vulnerabilities')    
        )

        figure = dict(data=graph, layout=layout_one)

        return figure

class Batch:
    @staticmethod
    def run_batch(csv_path='./data/', database=None,remove_csv=False, engine=None,
        nessus_server=None, nessus_username=None, nessus_password=None,
        nessus_folder_exclude=None, nessus_scan_exclude=None, nessus_table=None,
        nessus_history_table=None):
        """
        ETL Pipeline -
        Extract - data from Nessus API
        Transform - add additional date columns
        Load - into sqlite database

        Parameters:
        config_file (str): location of webapp config
        csv_path (str): location to save temporary csvs
        remove_csv (bool): delete temporary csv files once they're loaded into db
        """
        if not nessus_server:
            server = current_app.config['NESSUS_SERVER']
        else:
            server = nessus_server

        if not nessus_username:
            username = current_app.config['NESSUS_USERNAME']
        else:
            username = nessus_username
        
        if not nessus_password:
            password = current_app.config['NESSUS_PASSWORD']
        else:
            password = nessus_password

        if not nessus_folder_exclude:
            folder_exclude = current_app.config['NESSUS_FOLDER_EXCLUDE']
        else:
            folder_exclude = nessus_folder_exclude
        
        if not nessus_scan_exclude:
            scan_exclude = current_app.config['NESSUS_SCAN_EXCLUDE']
        else:
            scan_exclude = nessus_scan_exclude

        if not nessus_table:
            table = current_app.config['OMNIANA_NESSUS_TABLE']
        else:
            table = nessus_table

        if not nessus_history_table:
            history_table = current_app.config['OMNIANA_HISTORY_TABLE']
        else:
            history_table = nessus_history_table

        if not engine:
            if not database:
                database = current_app.config['NESSUS_SQLALCHEMY_BINDS']
            #engine = create_engine('sqlite:///'+database, echo=False)
            engine = db.get_engine(bind=database)

        history_df = pd.DataFrame(columns=['history_id'])
        # history table check
        if engine.dialect.has_table(engine, history_table):
            history_df = pd.read_sql_query("SELECT * FROM " + history_table,engine)

        history_list = history_df['history_id'].tolist()

        nessus = Nessus(server,username,password)

        folders = nessus.get_scan_folders()

        for folder in folders:
            folder_id = folder[0]
            folder_name = folder[1]

            if folder_name not in folder_exclude:
                print(folder_name)
                scans = nessus.get_scan_ids(folder_id)
                for scan in scans:
                    scan_id = scan[0]
                    scan_name = scan[1]
                    if scan_name not in scan_exclude:
                        print("  " + scan_name)
                        scan_name_folder = scan_name.replace(' ','_')
                        scan_name_folder_path = os.path.join(csv_path,scan_name_folder).replace('\\','/')
                        if not os.path.exists(scan_name_folder_path):
                            os.makedirs(scan_name_folder_path)
                        history_ids = nessus.get_scan_history_ids(scan_id)
                        for history in history_ids:
                            history_id = history[0]
                            history_date = history[1]
                            history_date_formatted = time.strftime('%m-%d-%Y',
                                time.localtime(history_date))
                            print("    " + str(history_id) + " - " + history_date_formatted)
                            if history_id not in history_list:
                                save_path = os.path.join(csv_path,scan_name_folder,history_date_formatted+'.csv')
                                save_path = save_path.replace('\\','/')
                                nessus.scans_export(scan_id,history_id,save_path)

                                df = Batch.transform_df(save_path,scan_id,scan_name,history_id,history_date)
                                Batch.load_df_database(df,engine,table)

                                history_df = history_df.append([{'history_id':history_id}])
                                history_df.to_sql(history_table, con=engine,if_exists='replace',index=False)
                            else:
                                print("      Skipping - already loaded into database")
        
        return
    @staticmethod
    def transform_df(save_path,scan_id,scan_name,history_id,history_date):
        df = pd.read_csv(save_path)
        
        df['scan_id'] = scan_id
        df['scan_name'] = scan_name
        df['history_id'] = history_id
        df['history_date'] = history_date

        return df
    @staticmethod
    def load_df_database(df,database,table):
        df.to_sql(table, con=database,if_exists='append',index=False)
        return
