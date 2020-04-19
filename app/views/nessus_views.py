from flask import Blueprint, redirect, render_template, current_app, abort
from flask import request, url_for, flash, send_from_directory, jsonify, render_template_string
from flask_user import current_user, login_required, roles_accepted

from app import db
from app.models.user_models import UserProfileForm, User, UsersRoles, Role
from app.utils.forms import ConfirmationForm
from app.utils.nessus import Plots
import uuid, json, os
import datetime

import plotly

# When using a Flask app factory we must use a blueprint to avoid needing 'app' for '@app.route'
nessus_blueprint = Blueprint('nessus', __name__, template_folder='templates')

# The User page is accessible to authenticated users (users that have logged in)
@nessus_blueprint.route('/nessus')
def main_page():
    if not current_user.is_authenticated:
        return redirect(url_for('user.login'))
    """
    figures = []
    vuln_trend_overall = Plots.get_figure_overall_vuln_trend()
    vuln_trend_plugin = Plots.get_figure_plugin_vuln_trend()
    figures.append(vuln_trend_overall)
    figures.append(vuln_trend_plugin)

    ids = ['figure-{}'.format(i) for i,_ in enumerate(figures)]

    figuresJSON = json.dumps(figures,cls=plotly.utils.PlotlyJSONEncoder)
    return render_template('index.html', ids=ids, figuresJSON=figuresJSON)
    """
    return render_template('pages/nessus/nessus_base.html')

# The Admin page is accessible to users with the 'admin' role
@nessus_blueprint.route('/nessus-admin')
@roles_accepted('admin')
def admin_page():
    return render_template('pages/nessus/nessus_admin.html')