import datetime
import logging
import re
import subprocess

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # These are the companies that will get cbinterface queries.
        ignore_these_companies = list(set(self.config.get('production', 'ignore_these_companies').split(',')))
        company_names = set()
        for alert in self.event_json['ace_alerts']:
            if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
                company_names.add(alert['company_name'])

        # These are the process names that will be ignored from the queries.
        ignore_these_process_names = list(set(self.config.get('production', 'ignore_these_process_names').split(',')))
        ignore_these_process_names_string = ''
        for process_name in ignore_these_process_names:
            ignore_these_process_names_string += '-process_name:{} '.format(process_name)

        # These are the process MD5s that will be ignored from the queries.
        ignore_these_process_md5s = list(set(self.config.get('production', 'ignore_these_process_md5s').split(',')))
        ignore_these_process_md5s_string = ''
        for process_md5 in ignore_these_process_md5s:
            ignore_these_process_md5s_string += '-process_md5:{} '.format(process_md5)

        # Get all of the good Windows - FileName indicators from the event.
        good_indicators = [i for i in self.event_json['indicators'] if not i['whitelisted']]
        filenames = list(set([i['value'] for i in good_indicators if i['type'] == 'Windows - FileName' and (i['status'] == 'New' or i['status'] == 'Analyzed')]))

        # Get all of the good Hash - MD5 indicators from the event.
        md5s = list(set([i['value'] for i in good_indicators if i['type'] == 'Hash - MD5' and (i['status'] == 'New' or i['status'] == 'Analyzed')]))

        # Run the cbinterface commands for each company in the event.
        for company in company_names:
        
            # Search for each filename.
            for filename in filenames:

                # Build and run the cbinterface command.
                command = 'cbinterface -e {} query \'{} {} filemod:"{}"\''.format(company, ignore_these_process_names_string, ignore_these_process_md5s_string, filename)
                try:
                    output = subprocess.check_output(command, shell=True).decode('utf-8')

                    # If there was output, it means the search returned something.
                    if output:

                        # Loop over each of the lines to try and find the GUI Link line.
                        for line in output.splitlines():

                            if 'GUI Link: ' in line:
                                gui_link = line.replace('GUI Link: ', '').strip()
                                self.detections.append('! DETECTED FILENAME {} ! {}'.format(filename, gui_link))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                self.extra.append(output)
                except:
                    self.logger.exception('Error running cbinterface command: {}'.format(command))

            # Search for each MD5.
            for md5 in md5s:

                command = 'cbinterface -e {} query \'{} {} md5:{}\''.format(company, ignore_these_process_names_string, ignore_these_process_md5s_string, md5)
                try:
                    output = subprocess.check_output(command, shell=True).decode('utf-8')

                    # If there was output, it means the search returned something.
                    if output:

                        # Loop over each of the lines to try and find the GUI Link line.
                        for line in output.splitlines():

                            if 'GUI Link: ' in line:
                                gui_link = line.replace('GUI Link: ', '').strip()
                                self.detections.append('! DETECTED MD5 {} ! {}'.format(md5, gui_link))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                self.extra.append(output)
                except:
                    self.logger.exception('Error running cbinterface command: {}'.format(command))
