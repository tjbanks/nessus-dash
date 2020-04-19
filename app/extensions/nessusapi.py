"""
Created on Tues Apr 14 11:48:43 2020

@author: Tyler Banks
"""
import requests
import json
import time

import warnings
warnings.filterwarnings("ignore")


class Nessus:

    url_folders = '/folders'
    url_scans = '/scans'
    url_session = '/session'
    url_pull_scan = None


    def __init__(self, server, username, password, verify=False):
        self.entry = server
        self.username = username
        self.password = password

        self.token = None

        self.verify = verify
        return

    def _post(self, url, payload={}, connect_timeout = 5.0, read_timeout = 30.0, 
        session_retrys=2, x_cookie=False):
        """
        Generic post wrapper

        Parameters:
        url (str): URL to send post request to

        Returns:
        response (dict): dictionary of post response
        """

        headers = {"Content-Type":"application/json"}

        if x_cookie:
            headers["X-Cookie"] = "token="+self.get_session_token()+";"

        attempts = 0
        status_code = -1

        while attempts < session_retrys and status_code != 200: 
            response = requests.post(url, json=payload, headers=headers,
                timeout=(connect_timeout, read_timeout), verify=self.verify)
            status_code = response.status_code
            attempts = attempts + 1
            if status_code == 401:
                payload['token'] = self.get_session_token(reauth=True)
        return response

    def _delete(self, url, payload={}, connect_timeout = 5.0, read_timeout = 30.0, session_retrys=2):
        """
        Generic post wrapper

        Parameters:
        url (str): URL to send post request to

        Returns:
        response (dict): dictionary of post response
        """
        attempts = 0
        status_code = -1

        while attempts < session_retrys and status_code != 200: 
            response = requests.delete(url, params=payload, 
                timeout=(connect_timeout, read_timeout), verify=self.verify)
            status_code = response.status_code
            attempts = attempts + 1
            if status_code == 401:
                payload['token'] = self.get_session_token(reauth=True)
        return response


    def _get(self, url, payload={}, connect_timeout = 5.0, read_timeout = 30.0, 
                session_retrys=2, x_cookie=False):
        """
        Generic get wrapper

        Parameters:
        url (str): URL to send post request to

        Returns:
        response (dict): dictionary of post response
        """
        #headers = {"Content-Type":"application/json"}
        headers = {}
        if x_cookie:
            headers["X-Cookie"] = "token="+self.get_session_token()+";"
        attempts = 0
        status_code = -1

        while attempts < session_retrys and status_code != 200:
            response = requests.get(url, params=payload, headers=headers,
                timeout=(connect_timeout, read_timeout), verify=self.verify)
            status_code = response.status_code
            attempts = attempts + 1
            if status_code == 401:
                payload['token'] = self.get_session_token(reauth=True)
        
        return response
    
    """
    Self defined methods for this use case
    """
    def get_session_token(self, reauth=False):
        if not self.token or reauth:    
            response_text = self.session_create()
            self.token = response_text['token']

        return self.token

    def logout(self):
        return self.session_delete()


    def update_payload_token(self, dic):
        dic['token'] = self.get_session_token()

    def scans_export(self,scan_id,history_id,filename,status_interval=1,status_max=120,verbose=True):
        """
        Parameters:
        status_interval: Wait n seconds before checking status again
        """

        #request
        request = self.scans_export_request(scan_id,history_id)
        file_id = request['file']

        #check for updates
        ready_status = False
        status_check = 1
        while not ready_status:
            
            ready_status = self.scans_export_status(scan_id,file_id)

            if ready_status:
                break

            if verbose:
                print("Waiting for file download (" + str(file_id) + ") to be ready (" + str(status_check) +
                "/" + str(status_max) + ")")
            time.sleep(status_interval)
            
            if status_check >= status_max:
                raise Exception("File not ready for download in time, increase status_max value")

            status_check = status_check + 1
        
        download_response = self.scans_export_download(scan_id,file_id,filename)

        return download_response


    def download_file(self,url,filename,payload={},x_cookie=False):
        headers = {}
        if x_cookie:
            headers["X-Cookie"] = "token="+self.get_session_token()+";"

        with requests.get(url, params=payload, headers=headers, verify=self.verify, stream=True) as r:
            r.raise_for_status()
            with open(filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): 
                    if chunk: # filter out keep-alive new chunks
                        f.write(chunk)
                        # f.flush()
        return filename

    def get_scan_folders(self):
        """
        Get all of the scan folders
        
        Returns:
        ret (list): a list of tuples (folder_id, folder_name)
        """
        folders_list = self.folders_list()
        ret = [(f['id'],f['name']) for f in folders_list['folders']]

        return ret

    def get_scan_ids(self,folder_id=None):
        """
        Get all of the scans for a speficied folder
        
        Parameters:
        folder_id (int): the id for the folder containing your scans (optional)

        Returns:
        ret (list): a list of tuples (scan_id, scan_name)
        """
        scans_list = self.scans_list()
        ret = [(f['id'],f['name']) for f in scans_list['scans'] if not folder_id or f['folder_id']==folder_id]

        return ret

    def get_scan_history_ids(self, scan_id, completed=True):
        """
        Get all of the history ids for a specified scan

        Parameters:
        scan_id (int): id for the scan
        completed (bool): only collect completed scans

        Returns:
        history (list): a list of tuples (history_id(int),timestamp:int)
        """
        scans_details = self.scans_details(scan_id)
        if scans_details['history']:
            history = [(f['history_id'],f['creation_date'])for f in scans_details['history'] 
                if not completed or f['status'] == 'completed']
        else:
            history = []

        return history
    
    """
    FOLDERS
    """

    def folders_list(self):
        url = self.entry + Nessus.url_folders

        payload = {}
        self.update_payload_token(payload)
        response = self._get(url,payload)        
        response_text = json.loads(response.text)

        return response_text


    """
    SCANS
    """

    def scans_list(self,folder_id=None,scan_id=None):
        url = self.entry + Nessus.url_scans

        if scan_id:
            url = url + '/' + str(scan_id)

        payload = {}

        if folder_id:
            payload['folder_id'] = folder_id
        
        self.update_payload_token(payload)

        response = self._get(url,payload)
        response_text = json.loads(response.text)

        return response_text

    def scans_details(self,scan_id):
        return self.scans_list(scan_id=scan_id)

    def scans_export_request(self,scan_id,history_id=None,format_type='csv'):
        url = self.entry + Nessus.url_scans

        url = url + '/' + str(scan_id) + '/export'

        if history_id:
            url = url + '?history_id=' + str(history_id)

        payload = {}
        self.update_payload_token(payload)

        payload['format']=format_type
        
        payload['reportContents.hostSections.scan_information']=True
        payload['reportContents.hostSections.host_information']=True
        payload['reportContents.vulnerabilitySections.synopsis']=True
        payload['reportContents.vulnerabilitySections.description']=True
        payload['reportContents.vulnerabilitySections.see_also']=True
        payload['reportContents.vulnerabilitySections.solution']=True
        payload['reportContents.vulnerabilitySections.risk_factor']=True
        payload['reportContents.vulnerabilitySections.cvss3_base_score']=True
        payload['reportContents.vulnerabilitySections.cvss3_temporal_score']=True
        payload['reportContents.vulnerabilitySections.cvss_base_score']=True
        payload['reportContents.vulnerabilitySections.cvss_temporal_score']=True
        payload['reportContents.vulnerabilitySections.stig_severity']=True
        payload['reportContents.vulnerabilitySections.references']=True
        payload['reportContents.vulnerabilitySections.exploitable_with']=True
        payload['reportContents.vulnerabilitySections.plugin_information']=True
        payload['reportContents.vulnerabilitySections.plugin_output']=True
        
        # Had to watch web traffic from the functional web app to see this
        # Pain in the ass
        csvColumns = {"id":True,"cve":True,"cvss":True,"risk":True,"hostname":True,"protocol":True,
        "port":True,"plugin_name":True,"synopsis":True,"description":True,"solution":True,
        "see_also":True,"plugin_output":True,"stig_severity":True,"cvss3_base_score":True,
        "cvss_temporal_score":True,"cvss3_temporal_score":True,"risk_factor":True,"references":True,
        "plugin_information":True,"exploitable_with":True}

        payload['reportContents'] = {'csvColumns':csvColumns}

        response = self._post(url,payload,x_cookie=True)
        response_text = json.loads(response.text)

        return response_text
 

    def scans_export_status(self,scan_id,file_id,simple=True):
        url = self.entry + Nessus.url_scans

        url = url + '/' + str(scan_id) + '/export/' + str(file_id) + '/status'

        payload = {}

        response = self._get(url,payload,x_cookie=True)       

        state = json.loads(response.text)['status']

        if simple:
            if response.status_code == 200 and state=='ready':
                return True
            else:
                return False
        else:
            return response

    def scans_export_download(self,scan_id,file_id,filename):
        url = self.entry + Nessus.url_scans

        url = url + '/' + str(scan_id) + '/export/' + str(file_id) + '/download'

        payload = {}
        
        response = self.download_file(url,filename,payload=payload,x_cookie=True)

        return response
    """
    SESSION
    """

    def session_create(self):
        url = self.entry + Nessus.url_session

        payload = {
                    "username":self.username,
                    "password":self.password
                }

        response = self._post(url, payload)
        #TODO Handle 400, 401, 500
        response_text = json.loads(response.text)

        return response_text

    def session_delete(self):
        url = self.entry + Nessus.url_session

        payload = {}
        self.update_payload_token(payload)

        response = self._delete(url,payload)
        

        return response

    def session_get(self):
        url = self.entry + Nessus.url_session

        payload = {}
        self.update_payload_token(payload)

        response = self._get(url,payload)
        
        response_text = json.loads(response.text)

        return response_text