# References:
#   Sample: b8eaca0905fc46ad6f69320954a0ec35fcd571fc829ed264a908c7aaa2b4eb92
#     Sandbox Report: 890fb809-f4e3-4a72-9c11-027695fec4a5
#   Sample: 05d09a49f85ff2918fdb41b9987970a5d46c0dd339ffe704a36b24df31af1c24
#   Sample: 3443ced18c9c1582972eaeb97e4978298ad1cb3d3b2dabe71fa16da19b581b3c
#  https://github.com/jeFF0Falltrades/Malware-Writeups/blob/07bd0e84015d8c9afe060f9f4a6ba50a436a57df/Qealler/Qealler-Unloaded.pdf
#  https://malpedia.caad.fkie.fraunhofer.de/library?search=qealler

import requests

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        java_user_agent = False
        dropped_sqlite_dll = False
        qealler_uri_path = False
        suricata_signature = False
        # all of the samples also make get requests to 'bot.whatismyipaddress.com', so that could serve as an additional detection point
        # the use of 'chcp.com chcp' in the process tree can also serve as another detection point
        detection_messages = []
        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            # Loop over each HTTP request in the sample.
            key = 'httprequests' if 'httprequests' in sample else 'http_requests'
            for request in sample[key]:

                _key = 'useragent' if 'useragent' in request else 'user_agent'
                if request[_key].startswith('Java/'):# == 'Java/1.8.0_151':
                    java_user_agent = True
                    detection_messages.append('HTTP Request with user-agent "{}"'.format(request['user_agent']))
                if 'qealler' in request['uri']:
                    qealler_uri_path = True
                    detection_messages.append('HTTP Request to "{}"'.format(request['url']))

            for dropped in sample['dropped_files']:
                if 'sqlite' in dropped['filename'] and '(DLL)' in dropped['type']:
                    dropped_sqlite_dll = True
                    detection_messages.append('Dropped sqlite dll: {}'.format(dropped['filename']))

            if 'suricata_alerts' not in sample:
                continue
            for sa in sample['suricata_alerts']:
                if 'action' in sa and sa['action'].get('db'):
                    if 'ETPRO MALWARE JAR/Qealler Stealer - CnC Activity' in sa['action']['db']:
                        _detection_string = 'Command and Control {} connection to {}:{} - {}'.format(sa.get('protocol'), sa.get('destip'), sa.get('destport'), sa['action']['db'])
                        if _detection_string not in detection_messages:
                            detection_messages.append(_detection_string)
                        suricata_signature = True

        # conditional analyst notification and event tagging
        tag_confidence = False         
        if qealler_uri_path and java_user_agent:
            tag_confidence = True
        if java_user_agent and dropped_sqlite_dll:
            tag_confidence = True
        if suricata_signature and any([dropped_sqlite_dll, java_user_agent, qealler_uri_path]):
            tag_confidence = True
 
        if tag_confidence:
            detection_summary = "Detected the Qealler infostealer:"
            for _detection_string in detection_messages:
                detection_summary += "\n\t"+u'\u21B3'+" "+_detection_string
            self.detections.append(detection_summary)
            self.tags.append('qealler')
            self.tags.append('infostealer')
