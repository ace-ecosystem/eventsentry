import json
import logging
import os
import subprocess

from lib.config import config
from lib.constants import HOME_DIR
from lib.indicator import make_url_indicators
#from requests.exceptions import HTTPError

class ACEAlert:
    def __init__(self, alert_path):

        # Start logging.
        self.logger = logging.getLogger()

        # Read the alert JSON.
        with open(alert_path, encoding='utf8') as a:
            self.ace_json = json.load(a)

        self.alert_dir = os.path.dirname(alert_path)
        self.path = alert_path
        self.time = self.ace_json['event_time']
        self.tool = self.ace_json['tool']
        self.type = self.ace_json['type']
        self.name = self.ace_json['uuid']
        self.description = self.ace_json['description']
        try:
            self.company_name = self.ace_json['company_name']
        except:
            self.company_name = 'legacy'

        # Get all detection points
        self.detections = self.get_all_detection_points()

        # Load the URL from the config file.
        self.url = config['ace']['ace_alert_url'] + self.name

        """
        #
        # USER ANALYSIS
        #
        """
        # Try and find any user analysis files.
        user_analysis_files = self.get_all_analysis_paths('saq.modules.user:EmailAddressAnalysis')

        # Parse any user_analysis_files.
        self.user_analysis = []
        for file in user_analysis_files:
            if os.path.exists(os.path.join(self.alert_dir, '.ace', file)):
                self.logger.info("processing EmailAddressAnalysis for user data...")
                with open(os.path.join(self.alert_dir, '.ace', file), encoding='utf8') as j:
                    user_analysis_data = json.load(j)

                for json_data in user_analysis_data:
                    user = {'cn': '',
                            'displayName': '',
                            'mail': '',
                            'title': '',
                            'description': '',
                            'department': '',
                            'company': '',
                            'distinguishedName': ''}

                    if 'attributes' not in json_data:
                        continue

                    user_data = json_data['attributes']

                    try: user['cn'] = user_data['cn']
                    except KeyError: pass

                    try: user['displayName'] = user_data['displayName']
                    except KeyError: pass

                    try: user['mail'] = user_data['mail']
                    except KeyError: pass

                    try: user['title'] = user_data['title']
                    except KeyError: pass

                    try: user['description'] = ' | '.join(user_data['description'])
                    except KeyError: pass

                    try: user['department'] = user_data['department']
                    except KeyError: pass

                    try: user['company'] = user_data['company']
                    except KeyError: pass

                    try: user['distinguishedName'] = user_data['distinguishedName']
                    except KeyError: pass

                    self.user_analysis.append(user)

        """
        #
        # URLS
        #
        """
        # Save whatever URLs ACE was able to automatically extract.
        urls = set()
        url_files = self.get_all_analysis_paths('saq.modules.file_analysis:URLExtractionAnalysis')
        for file in url_files:
            try:
                with open(os.path.join(self.alert_dir, '.ace', file), encoding='utf8') as j:
                    json_data = json.load(j)
                    for url in json_data['urls']:
                        if url.endswith('/'):
                            url = url[:-1]
                        urls.add(url)
            except FileNotFoundError as e:
                logging.warning("Caught FileNotFoundError trying to open '{}'".format(os.path.join(self.alert_dir, '.ace', file)))
 
        self.urls = sorted(list(urls))

        # Make indicators from the URLs.
        self.indicators = make_url_indicators(self.urls)

        """
        #
        # SCREENSHOTS
        #
        """
        screenshots = set()
        for observable in self.ace_json['observable_store'].keys():
            try:
                if 'screenshot' in self.ace_json['observable_store'][observable]['tags']:
                    screenshot_path = os.path.join(self.alert_dir, self.ace_json['observable_store'][observable]['value'])
                    screenshots.add(screenshot_path)
                    self.logger.debug('Found ACE screenshot: {}'.format(screenshot_path))
            except:
                pass
        self.screenshots = sorted(list(screenshots))

        """
        #
        # TAGS
        #
        """
        tags = set()
        for observable in self.ace_json['observable_store'].keys():
            try:
                for tag in self.ace_json['observable_store'][observable]['tags']:
                    tags.add(tag)
            except:
                pass
        self.tags = sorted(list(tags))
        self.logger.debug('"{}" alert has these tags: {}'.format(self.name, self.tags))

        """
        #
        # Falcon Reports
        #
        """
        self.download_full_falcon_reports()

    @property
    def json(self):
        """ Return a JSON compatible view of the ACE alert. """

        json = {}
        json['alert_dir'] = self.alert_dir
        json['company_name'] = self.company_name
        json['description'] = self.description
        json['name'] = self.name
        json['path'] = self.path
        json['screenshots'] = self.screenshots
        json['tags'] = self.tags
        json['time'] = self.time
        json['tool'] = self.tool
        json['type'] = self.type
        json['url'] = self.url
        json['urls'] = self.urls
        json['user_analysis'] = self.user_analysis
        json['detections'] = self.detections

        return json

    def get_all_analysis_paths(self, ace_module):
        analysis_paths = []

        # Loop over each observable in the alert.
        for observable in self.ace_json['observable_store'].keys():
            # See if there is an analysis for the given ACE module.
            try:
                json_file = self.ace_json['observable_store'][observable]['analysis'][ace_module]['details']['file_path']
                if json_file:
                    analysis_paths.append(self.ace_json['observable_store'][observable]['analysis'][ace_module]['details']['file_path'])
            except:
                pass

        return analysis_paths

    def get_all_falcon_sandbox_jobs(self):
        job_ids = []
        for path in self.get_all_analysis_paths('saq.modules.falcon_sandbox:FalconSandboxAnalysis'):
            falcon_json = None
            if os.path.exists(os.path.join(self.alert_dir, '.ace', path)):
                with open(os.path.join(self.alert_dir, '.ace', path), 'r') as fp:
                    falcon_json = json.load(fp)
            if falcon_json:
                if 'report_summary' in falcon_json and falcon_json['report_summary'] and 'job_id' in falcon_json['report_summary']:
                    job_ids.append(falcon_json['report_summary']['job_id'])
                if 'submission_result' in falcon_json and falcon_json['submission_result'] and 'job_id' in falcon_json['submission_result']:
                    job_ids.append(falcon_json['submission_result']['job_id'])
        return list(set(job_ids))

    def download_full_falcon_reports(self):
        event_dir = os.path.dirname(self.alert_dir)
        for job_id in self.get_all_falcon_sandbox_jobs():
            proxy = config['network']['proxy']
            output_path = os.path.join(event_dir, job_id+'.falcon.json')
            falcon_command = 'falcon-sandbox get report {} -o {}'.format(job_id, output_path)
            command = 'export https_proxy={} && {} && unset https_proxy'.format(proxy, falcon_command)
            self.logger.info("Attempting to get full falcon report with: {}".format(falcon_command))
            try:
                output = subprocess.check_output(command, shell=True).decode('utf-8')
            #except HTTPError as e:
            #    self.logger.warning("Caught HTTPError from falcon-sandbox: {}".format(e))
            except Exception as e:
                self.logger.error("Got Error attempting to get falcon report: {}".format(e))
            if os.path.exists(output_path) and os.stat(output_path).st_size == 0:
                # problem happened and an empty report was written
                self.logger.error("EMPTY FALCON REPORT INDICATES 'falcon-sandbox' had a problem. Deleteing {}".format(output_path))
                os.remove(output_path)

    def get_all_detection_points(self):
        """ Parse out all detections we can find from the ACE alerts json and
            perform special logic based on the configuration.
        """
        # Is this an alert we should verbosly ignore detections for?
        ignore_detections = False
        verbosely_ignore_descriptions = config['ace']['detections']['verbosely_ignore_detections_for'].get('descriptions', [])
        if any(ignore_descrip_str in self.description for ignore_descrip_str in verbosely_ignore_descriptions):
            ignore_detections = True
        verbosely_ignore_tools = config['ace']['detections']['verbosely_ignore_detections_for'].get('tools', [])
        if any(self.tool.startswith(ignore_tool) for ignore_tool in verbosely_ignore_tools):
            ignore_detections = True

        # root level detections
        detections = self.ace_json.get('detections', [])

        # should we consider the alert itself a detection?
        not_detection_tools = config['ace']['detections'].get('not_detection_tools', [])
        if not any(self.tool.startswith(dt) for dt in not_detection_tools):
            detections.append({ 'description': self.description,
                                'details': "EVENT SENTRY" })

        #observable store detections
        for _okey, o in self.ace_json['observable_store'].items():
            detections.extend(o['detections'])

            #analysis detections
            for a_module, results in o['analysis'].items():
                if not results:
                    continue
                detections.extend(results['detections'])

        # Finally, supply the ignore_detection flag on every detection
        for detection in detections:
            detection['ignore_detection'] = ignore_detections

        return detections
