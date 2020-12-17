import datetime
import json
import logging
import re
import subprocess

from pprint import pprint
from cbapi.response import *
from cbinterface.modules.process import ProcessWrapper
from cbinterface.modules.helpers import as_configured_timezone

from lib.constants import SPLUNKLIB
from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.info('Running the {} detection module'.format(self.name))

        # Stupid hack for 1000 Talents events with tons of URLs.
        skip_these = ['1000 talents', '1000_talents']
        if any(skip in self.event_json['name'].lower() for skip in skip_these) or any(skip in self.event_json['tags'] for skip in skip_these):
            notice = ("INFO NOTICE: Skipped checking for clickers becase this event was identified as '1000 Talents'"
                       "\n\t"+u'\u21B3'+" 1000 Talents events are notorious for having a lot of URLs and we don't care to respond to any clicks."
                       "\n\t"+u'\u21B3'+" This event was detected as '1000 Talents' by the event name OR because of tags.")
            self.detections.append(notice)
            return

        # Simple regex that defines what an employee ID looks like.
        employee_id_pattern = re.compile(r'{}'.format(self.config['employee_id_pattern']))

        """
        QUERY SPLUNK FOR CLICKERS IN PROXY LOGS
        """

        # These are the companies that will get Splunk queries.
        ignore_these_companies = self.config['ignore_these_companies']
        company_names = set()
        for alert in self.event_json['ace_alerts']:
            if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
                company_names.add(alert['company_name'])

        # Get the start time.
        start_time = ''
        if self.event_json['emails']:
            start_time = self.event_json['emails'][0]['received_time']
            self.logger.info("Using start time from emails received_time: {}".format(start_time))
        elif self.event_json['ace_alerts']:
            start_time = self.event_json['ace_alerts'][0]['time']
            self.logger.info("Using start time from ace alert time: {}".format(start_time))

        # We need to make sure the start time is in the format "YYYY-MM-DD", which is 10 characters long.
        start_time = start_time[0:10]

        # Force the start time to begin at 00:00:00.
        start_time = '{} 00:00:00'.format(start_time)

        # These are legit things that we expect to generate some results.
        whitelisted_things = self.config['whitelisted_things']
        if whitelisted_things:
            cb_whitelisted_things_string = '-hostname:' + ' -hostname:'.join(whitelisted_things)
            splunk_whitelisted_things_string = 'NOT ' + ' NOT '.join(whitelisted_things)
        else:
            cb_whitelisted_things_string = ''
            splunk_whitelisted_things_string = ''

        # NOTE How did cb queries end up in this file instead of cbinterface? FIX XXX
        '''
        ignore_these_hosts = self.config['ignore_these_computers']
        if ignore_these_hosts:
            cb_whitelisted_things_string = '-hostname:' + ' -hostname:'.join(ignore_these_hosts)
        else:
            cb_whitelisted_things_string = ''
        '''

        ignored_source_ips = self.config['ignored_source_ips']
        if ignored_source_ips:
            ignored_source_ips_string = ' OR '.join(ignored_source_ips)
        else:
            ignored_source_ips_string = ''

        # Get all of the New/Analyzed domains and IP addresses from the event.
        good_indicators = [i for i in self.event_json['indicators'] if not i['whitelisted'] and (i['status'] == 'New' or i['status'] == 'Analyzed' or i['status'] == 'In Progress')]
        domains = list(set([i['value'].lower() for i in good_indicators if i['type'] == 'URI - Domain Name' and not 'from_domain' in i['tags']]))
        ips = list(set([i['value'].lower() for i in good_indicators if i['type'] == 'Address - ipv4-addr']))

        # Get all of the Dropbox/Google Drive/etc URI paths from the event.
        extra_domains = ['dropbox.com', 'www.dropbox.com', 'drive.google.com', 'gitlab.com', 'www.gitlab.com']
        content_protecting_domains = list(set([i['value'] for i in good_indicators if i['type'] == 'Email - Content - Domain Name' and i['status'] != 'Deprecated']))
        extra_domains.extend(content_protecting_domains)
        extra_domains = list(set(extra_domains))

        self.logger.info(f"extra domains: {extra_domains}")

        uri_paths = list(set([i['value'].lower() for i in good_indicators if i['type'] == 'URI - Path' and any(rel in extra_domains for rel in i['relationships'])]))
        all_url_list = list(set([i['value'].lower() for i in good_indicators if i['type'] == 'URI - URL']))
        url_list = list(set([url for url in all_url_list if any(domain in url for domain in extra_domains)]))

        self.logger.info(f"URL List: {url_list}")

        # Collect all of the domains/IPs/paths we want to search for in Splunk.
        domains_ips_paths_urls = list(set(domains + ips + uri_paths + url_list))
        domains_ips_paths_for_splunk = ['"'+indicator+'"' for indicator in domains_ips_paths_urls]
        if domains_ips_paths_urls:
            domains_ips_paths_string = ' OR '.join(domains_ips_paths_for_splunk)
        else:
            return

        # Only continue if we have a valid start time.
        if len(start_time) == 19:

            # Bump the start time back an extra hour to help make sure we have better coverage.
            # XXX Temporary hack.. I noticed our alert and email tims are in UTC but our splunk logs are in EST. ~ going back 5 hrs
            earlier_start_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') - datetime.timedelta(hours=5)
            earlier_start_time = earlier_start_time.strftime('%Y-%m-%d %H:%M:%S')
            start_time = earlier_start_time

            # Maps for keeping track of users, computers, and processes accross data logs
            ## i.e. simple correlation
            computer_user_map = {} # get users associated with computer
            computer_proc_map = {} # get processes associated with computer

            # Run the Splunk search for each company we found in the alerts.
            for company in company_names:

                # Create CbResponse object 
                cb = CbResponseAPI(profile=company)

                # Store the employee IDs who clicked for each domain/IP.
                clicker_ids = []

                # Store the employee email addresses inside the event.
                email_addresses = list(set([i['value'] for i in self.event_json['indicators'] if i['type'] == 'Email - Address' and company.lower() in i['value'].lower()]))

                """
                BUILD AND RUN THE Carbon Black SEARCH FOR EACH DOMAIN/IP
                """

                self.logger.debug("Got these domains: {}".format(domains))
                for domain in domains:

                    # Build and run the cb query.
                    query = '(domain:"{}" OR cmdline:"{}") {}'.format(domain, domain, cb_whitelisted_things_string)
                    try:
                        # min_last_server_update takes a ISO 8601 string formatted timestamp
                        processes = cb.select(Process).where(query).group_by('id').min_last_server_update(start_time.replace(' ','T')+'Z')
                        self.logger.info("Searching Carbon Black data for network connections by domain with: {}".format(query))
                        # If there was output, it means the search returned something.
                        if processes:
                            if len(processes) > 500:
                                self.logger.warning("{} processes returned by Carbon Black for '{}' since '{}'".format(len(processes), query, start_time))
                                self.detections.append('! DETECTED {} PROCESSSES THAT MADE NETCONNS TO DOMAIN {} ! -- TOO LARGE of dataset to display, only including first 100 results in extra detections.'.format(len(processes), domain))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                for proc in processes[:100]:
                                    proc_summary = "Hostname:{} User:{} Process_Name:{} Command_Line:{} GUI_Link:{}".format(proc.hostname,
                                                                                                                            proc.username,
                                                                                                                            proc.process_name,
                                                                                                                            proc.cmdline,
                                                                                                                            proc.webui_link)
                                    self.extra.append(proc_summary)
                            else:
                                for proc in processes:
                                    user_id = proc.username.lower()
                                    if '\\' in user_id:
                                        # such as corp\user_id
                                        user_id = user_id[user_id.rfind('\\')+1:]
                                    clicker_ids.append(user_id)
                                    self.detections.append('! DETECTED NETCONN {} TO DOMAIN {} FROM {} ! {}'.format(user_id, domain, proc.hostname, proc.webui_link))
                                    if proc.hostname not in computer_user_map:
                                        computer_user_map[proc.hostname] = []
                                    if user_id not in computer_user_map[proc.hostname]:
                                        computer_user_map[proc.hostname].append(user_id)
                                    if proc.hostname not in computer_proc_map:
                                        computer_proc_map[proc.hostname] = {}
                                    if proc.id not in computer_proc_map[proc.hostname].keys():
                                        computer_proc_map[proc.hostname][proc.id] = proc
                                    self.tags.append('incidents')
                                    self.tags.append('exploitation')
                                    # just using the convienient display of ProcessWrapper
                                    self.extra.append(str(ProcessWrapper(proc)))
                    except:
                        self.logger.exception('Error searching CarbonBlack data: {}'.format(query))

                for url in url_list:
                    # Build and run the cb query.
                    query = 'cmdline:"{}" {}'.format(url, cb_whitelisted_things_string)
                    try:
                        # min_last_server_update takes a ISO 8601 string formatted timestamp
                        processes = cb.select(Process).where(query).group_by('id').min_last_server_update(start_time.replace(' ','T')+'Z')
                        self.logger.info("Searching Carbon Black data for network connections by url with: {}".format(query))
                        # If there was output, it means the search returned something.
                        if processes:
                            if len(processes) > 500:
                                self.logger.warning("{} processes returned by Carbon Black for '{}' since '{}'".format(len(processes), query, start_time))
                                self.detections.append('! DETECTED {} PROCESSSES WITH URL ON CMDLINE {} ! -- TOO LARGE of dataset to display, only including first 100 results in extra detections.'.format(len(processes), url))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                for proc in processes[:100]:
                                    proc_summary = "Hostname:{} User:{} Process_Name:{} Command_Line:{} GUI_Link:{}".format(proc.hostname,
                                                                                                                            proc.username,
                                                                                                                            proc.process_name,
                                                                                                                            proc.cmdline,
                                                                                                                            proc.webui_link)
                                    self.extra.append(proc_summary)
                            else:
                                for proc in processes:
                                    user_id = proc.username.lower()
                                    if '\\' in user_id:
                                        # such as corp\user_id
                                        user_id = user_id[user_id.rfind('\\')+1:]
                                    clicker_ids.append(user_id)
                                    self.detections.append('! DETECTED CLICK by {} on URL {} FROM {} ! {}'.format(user_id, url, proc.hostname, proc.webui_link))
                                    if proc.hostname not in computer_user_map:
                                        computer_user_map[proc.hostname] = []
                                    if user_id not in computer_user_map[proc.hostname]: 
                                        computer_user_map[proc.hostname].append(user_id)
                                    if proc.hostname not in computer_proc_map:
                                        computer_proc_map[proc.hostname] = {}
                                    if proc.id not in computer_proc_map[proc.hostname].keys():
                                        computer_proc_map[proc.hostname][proc.id] = proc
                                    self.tags.append('incidents')
                                    self.tags.append('exploitation')
                                    # just using the convienient display of ProcessWrapper
                                    self.extra.append(str(ProcessWrapper(proc)))
                    except:
                        self.logger.exception('Error searching CarbonBlack data: {}'.format(query))

                for ip in ips:

                    query = '(ipaddr:{} OR cmdline:{}) {}'.format(ip, ip, cb_whitelisted_things_string)
                    try:
                        processes = cb.select(Process).where(query).group_by('id').min_last_server_update(start_time.replace(' ','T')+'Z')
                        self.logger.info("Searching Carbon Black data for network connections with: {}".format(query))
                        if processes:
                            if len(processes) > 500:
                                self.logger.warning("{} processes returned by Carbon Black for '{}' since '{}'".format(len(processes), query, start_time))
                                self.detections.append('! DETECTED {} PROCESSSES THAT MADE NETCONNS TO IP {} ! -- TOO LARGE of dataset to display, only including first 100 results in extra detections.'.format(len(processes), ip))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                for proc in processes[:100]:
                                    proc_summary = "Hostname:{} User:{} Process_Name:{} Command_Line:{} GUI_Link:{}".format(proc.hostname,
                                                                                                                            proc.username,
                                                                                                                            proc.process_name,
                                                                                                                            proc.cmdline,
                                                                                                                            proc.webui_link)
                                    self.extra.append(proc_summary)
                            else:
                                for proc in processes:
                                    self.detections.append('! DETECTED NETCONN {} TO IP {} FROM {} ! {}'.format(proc.username, ip, proc.hostname, proc.webui_link))
                                    self.tags.append('incidents')
                                    self.tags.append('exploitation')
                                    user_id = proc.username.lower()
                                    if '\\' in user_id:
                                        # such as corp\user_id
                                        user_id = user_id[user_id.rfind('\\')+1:]
                                    clicker_ids.append(user_id)
                                    if proc.hostname not in computer_user_map:
                                        computer_user_map[proc.hostname] = []
                                    if user_id not in computer_user_map[proc.hostname]:      
                                        computer_user_map[proc.hostname].append(user_id)
                                    if proc.hostname not in computer_proc_map:
                                        computer_proc_map[proc.hostname] = {}
                                    if proc.id not in computer_proc_map[proc.hostname].keys():
                                        computer_proc_map[proc.hostname][proc.id] = proc
                                    # just using the convienient display of ProcessWrapper
                                    self.extra.append(str(ProcessWrapper(proc)))
                    except:
                        self.logger.exception('Error searching CarbonBlack data: {}'.format(query))

                """
                BUILD AND RUN THE SPLUNK SEARCH
                """

                # Store the Splunk output lines.
                output_lines = []

                # This is the actual command line version of the Splunk query.
                command = '{} --enviro {} -s "{}" \'index=bluecoat OR index=bro_http OR index=carbonblack NOT authentication_failed NOT favicon.ico {} {}\''.format(SPLUNKLIB, company, start_time, domains_ips_paths_string, splunk_whitelisted_things_string)
                self.logger.debug("About to run: {}".format(command)) 
                try:
                    self.logger.info("Searching Splunk for clickers with: {}".format(command))
                    output = subprocess.check_output(command, shell=True).decode('utf-8')
                    # If there was output, it means the Splunk search returned something.
                    if output:

                        # Clean up the output lines.
                        for line in output.splitlines():

                            # Replace the "s with spaces and remove the first and last elements of the line.
                            cleaned_line = ' '.join(line.split('"')[1:-1])
                            output_lines.append(cleaned_line)

                            # Try to extract the user ID from the cleaned line, assuming it is a proxy log entry.
                            try:
                                user_id = cleaned_line.split()[8]
                                if employee_id_pattern.match(user_id):
                                    clicker_ids.append(user_id)
                                    self.tags.append('exploitation')
                                    self.tags.append('incidents')
                            except:
                                pass

                            # Try to extract the user ID from the cleaned line, assuming it is a Carbon Black log entry.
                            try:
                                user_id = cleaned_line.split()[88][-7:]
                                if employee_id_pattern.match(user_id):
                                    clicker_ids.append(user_id)
                                    self.tags.append('exploitation')
                                    self.tags.append('incidents')
                            except:
                                pass

                        # Add the (cleaned) raw Splunk results to the extra text.                            
                        self.extra.append('\n'.join(output_lines))
                except:
                    self.logger.exception('Error when running Splunk search: {}'.format(command))

                """
                ANALYZE SEARCH RESULTS TO DETERMINE TYPES OF CLICKERS
                """

                # Dedup and standardize the format of the clicker IDs.
                clicker_ids = list(set([i.lower() for i in clicker_ids]))

                # Standardize the format of the output lines.
                output_lines = [line.lower() for line in output_lines]

                # Logs change and user ID extraction can fail - notify a human
                if output_lines and not clicker_ids:
                    self.logger.warning("got splunk output but didn't find any clicker IDs...")
                    self.detections.append("! {} UN-IDENTIFIED DETECTION RESULTS: Expand details below to view logs...".format(len(output_lines)))
                    self.tags.append('incidents')

                # Build a computer to user map from carbonblack results
                computer_name_re = re.compile(r'computer_name  :  (?P<computer_name>[\w]+)  ,')
                # for grabbing process guids
                proc_guid_re = re.compile(r'process_guid  :  (?P<process_guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})  ,', re.I)

                # Loop over all of the domains and IPs we searched for to identify the clickers.
                for domain_ip_path in domains_ips_paths_urls:

                    # Loop over each clicker to check if they clicked on this domain/IP.
                    for user_id in clicker_ids:

                        # Get all of the Bluecoat log lines for this domain/IP + clicker.
                        bluecoat_lines = [line for line in output_lines if 'bluecoat' in line and domain_ip_path in line and user_id in line]

                        if bluecoat_lines:

                            # Determine the status of the click (i.e.: observed/denied).
                            if all(' denied ' in line for line in bluecoat_lines):
                                status = 'denied'
                            else:
                                status = 'observed'

                            # Determine the type of click (i.e.: http/https).
                            if all(' connect ' in line and ' 443 ' in line for line in bluecoat_lines):
                                click_type = 'https'
                            else:
                                click_type = 'http'

                            # Check if there were any POST requests (only works for http).
                            if any(' post ' in line for line in bluecoat_lines):
                                submitted = True
                            else:
                                submitted = False

                            # Check if we need to add a message reminding us to lock the clicker's account.
                            if submitted or (status == 'observed' and click_type == 'https'):
                                reminder_message = '<--- INITIATE RESPONSE ACTIONS!'
                            else:
                                reminder_message = ''

                            # Add the appropriate event detections.
                            if submitted:
                                self.detections.append('! CLICKER {} CREDENTIALS SUBMITTED ! {} {} {}'.format(company.upper(), user_id, domain_ip_path, reminder_message))
                                self.tags.append('actionsonobjectives')
                                self.tags.append('exfil')
                            else:
                                self.detections.append('! CLICKER {} {} {} ! {} {} {}'.format(company.upper(), click_type.upper(), status.upper(), user_id, domain_ip_path, reminder_message))

                        # Get all of the Carbon Black log lines for this | update -> there are no user ids in cb network logs
                        carbonblack_lines = [line for line in output_lines if 'carbonblack' in line and domain_ip_path in line] # and user_id in line]

                        # if we got bluecoat lines for this user we were able to make a determination
                        if not bluecoat_lines:
                            detections_updated = False
                            for line in carbonblack_lines:
                                match = computer_name_re.search(line)
                                computer = None
                                if match:
                                    computer = match.group('computer_name')
                                match = proc_guid_re.search(line)
                                process_guid = None
                                if match:
                                    process_guid = match.group('process_guid')
                                if computer and computer in computer_user_map.keys():
                                    if user_id in computer_user_map[computer]:
                                        other_users = [user for user in computer_user_map[computer] if user_id != user]
                                        for other_user in other_users:
                                            _new_detection = old_detection = ""
                                            for detection in self.detections:
                                                if 'CLICKER' in detection and other_user in detection and domain_ip_path in detection:
                                                    old_detection = detection
                                                    # other users on this system have a detection in bluecoat logs
                                                    _new_detection = (detection + "\n\t"+u'\u21B3'+" It appears the visit to '{}' by '{}'"
                                                                      " may have been from the same computer named {}. See extra detections"
                                                                      " to validate correlation.")
                                                    _new_detection = _new_detection.format(domain_ip_path, user_id, computer)
                                            if _new_detection != "":
                                                self.detections.remove(old_detection)
                                                self.detections.append(_new_detection)
                                                detections_updated = True

                # Make sure we actually added a detection for each user.
                for user_id in clicker_ids:
                    click_descriptions = [d for d in self.detections if 'CLICKER' in d]
                    if not any(user_id in d for d in click_descriptions):
                        self.detections.append('! CLICKER {} STATUS UNKNOWN ! {}'.format(company.upper(), user_id))

                # computer_user_map
                self.extra.append("\nComputer User map: {}\n".format(computer_user_map))

                """
                RUN ANY FOLLOW-UP 2FA SEARCHES
                """
                if clicker_ids and email_addresses:

                    # Store the Splunk output lines.
                    output_lines = []

                    # Build the user ID "OR" string for the search.
                    user_id_string = ' OR '.join(email_addresses)

                    # This is the actual command line version of the Splunk query.
                    # TODO XXX Make ActorIpAddress list in config that should be ignored here - for us it's just 149.55.24.4
                    command = '{} --enviro {} -s "{}" --json "index=microsoft_cloud (ResultStatus=Failed AND Operation=UserLoginFailed) OR (ResultStatus=Succeeded AND Operation=UserLoggedIn) AND ({}) AND NOT ({})"'.format(SPLUNKLIB, company, start_time, user_id_string, ignored_source_ips_string)
                    self.logger.info("Searching splunk for 2FA clickers with this command: {}".format(command))

                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:

                            results = json.loads(output)['result']
                            for result in results:
                                log = json.loads(result['_raw'])
                                detection_string = '! CLICKER {} 2FA ATTEMPT for {} at {} from {} : {} - {}'.format(company.upper(), log['UserId'], log['CreationTime'], log['ClientIP'], log['Operation'], log['ResultStatus'])
                                if 'LogonError' in log:
                                    detection_string+=' - {}'.format(log['LogonError'])
                                self.detections.append(detection_string)
                    except Exception as e:
                        self.logger.exception('Exception "{}" when running Splunk search: {}'.format(e, command)) 

