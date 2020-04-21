from flask import Blueprint, redirect, render_template, current_app, abort
from flask import request, url_for, flash, send_from_directory, jsonify, render_template_string, make_response
from flask_user import current_user, login_required, roles_accepted

from app import db
from app.models.user_models import UserProfileForm, User, UsersRoles, Role
from app.utils.forms import ConfirmationForm
from app.utils.nessus import Plots
import uuid, json, os
from datetime import datetime,timedelta

import plotly

# When using a Flask app factory we must use a blueprint to avoid needing 'app' for '@app.route'
nessus_blueprint = Blueprint('nessus', __name__, template_folder='templates')

# The User page is accessible to authenticated users (users that have logged in)
@nessus_blueprint.route('/nessus')
def main_page():
    if not current_user.is_authenticated:
        return redirect(url_for('user.login'))
    
    figures = []
    vuln_trend_overall = Plots.get_figure_overall_vuln_trend()
    vuln_trend_plugin = Plots.get_figure_plugin_vuln_trend()
    figures.append(vuln_trend_overall)
    figures.append(vuln_trend_plugin)

    ids = ['figure-{}'.format(i) for i,_ in enumerate(figures)]

    figuresJSON = json.dumps(figures,cls=plotly.utils.PlotlyJSONEncoder)
    #return render_template('index.html', ids=ids, figuresJSON=figuresJSON)
    df = Plots.get_latest_vulnerabilities_data()
    # 'Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis',
    # 'Description', 'Solution', 'See Also', 'Scan',
    # 'Plugin Publication Date',Metasploit, Core Impact, CANVAS,'Plugin Output'
    df = df.sort_values('Risk').drop_duplicates(subset=['Plugin ID','Host'],keep='first')
    vulns = df.groupby('Risk').count()['Plugin ID'].tolist()
    vulns = [vulns[i] for i in [0,1,3,2]] #reorder
    return render_template('pages/nessus/nessus_base.html',ids=ids, figuresJSON=figuresJSON,vulns=vulns)

@nessus_blueprint.route('/nessus-breakdown')
def breakdown_page():
    if not current_user.is_authenticated:
        return redirect(url_for('user.login'))
    return render_template('pages/nessus/nessus_breakdown.html')

@nessus_blueprint.route('/nessus-breakdown-data')
def breakdown_data():
    if not current_user.is_authenticated:
        return redirect(url_for('user.login'))
    df = Plots.get_latest_vulnerabilities_data()
    # 'Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis',
    # 'Description', 'Solution', 'See Also', 'Scan',
    # 'Plugin Publication Date',Metasploit, Core Impact, CANVAS
    df['Exploitable'] = (df['Metasploit']==True) | (df['Core Impact']==True) |(df['CANVAS']==True)
    df = df[['Plugin ID','CVE','CVSS','Risk','Host','Synopsis','Scan','Plugin Publication Date','Exploitable']]
    return make_response(df.to_json(orient="records"))

@nessus_blueprint.route('/nessus-breakdown-plugin')
def breakdown_plugin_page():
    if not current_user.is_authenticated:
        return redirect(url_for('user.login'))

    return render_template('pages/nessus/nessus_breakdown_plugin.html')

@nessus_blueprint.route('/nessus-breakdown-plugin-data')
def breakdown_plugin_data():
    if not current_user.is_authenticated:
        return redirect(url_for('user.login'))
    df = Plots.get_latest_vulnerabilities_data()
    # 'Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis',
    # 'Description', 'Solution', 'See Also', 'Scan',
    # 'Plugin Publication Date',Metasploit, Core Impact, CANVAS
    #df = df.sort_values('Risk').drop_duplicates(subset=['Plugin ID','Host'],keep='first')
    #df = df[['Plugin ID','CVSS','Risk','Host','Synopsis','Solution','Scan']]

    cvss = request.args.get('cvss', default = -1, type = int)
    risk = request.args.get('risk', default = None, type = str)
    daysold = request.args.get('daysold',default = -1, type = int)
    exploit = request.args.get('exploit',default = 0, type = int)

    if exploit != 0:
        df = df[(df['Metasploit']==True) | (df['Core Impact']==True) |(df['CANVAS']==True)]
        
    df = df.sort_values('Risk').drop_duplicates(subset=['Plugin ID','Host'],keep='first')
    
    if cvss != -1 and cvss>0 and cvss<=10:
        df = df[df.CVSS >= cvss]
    if risk:
        risk_arr = risk.split('-')
        #df = df[df.isin({'Risk':risk_arr})].dropna(subset=['Risk'])
        df = df[df['Risk'].isin(risk_arr)]
    if daysold >= 0:
        current_date = datetime.now()
        new_date = current_date - timedelta(days=daysold)
        date = new_date.strftime("%Y/%m/%d")
        df = df[(df['Plugin Publication Date']<date)]

    df['Exploitable'] = (df['Metasploit']==True) | (df['Core Impact']==True) |(df['CANVAS']==True)
    df = df[['Plugin ID','CVSS','Risk','Host','Synopsis','Solution','Plugin Output','Scan','Plugin Publication Date','Exploitable']]

    return make_response(df.to_json(orient="records"))


# The Admin page is accessible to users with the 'admin' role
@nessus_blueprint.route('/nessus-admin')
@roles_accepted('admin')
def admin_page():
    return render_template('pages/nessus/nessus_admin.html')
