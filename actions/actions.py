# This files contains your custom actions which can be used to run
# custom Python code.
#
# See this guide on how to implement these action:
# https://rasa.com/docs/rasa/custom-actions


# This is a simple example for a custom action which utters "Hello World!"

# from typing import Any, Text, Dict, List
#
# from rasa_sdk import Action, Tracker
# from rasa_sdk.executor import CollectingDispatcher
#
#
# class ActionHelloWorld(Action):
#
#     def name(self) -> Text:
#         return "action_hello_world"
#
#     def run(self, dispatcher: CollectingDispatcher,
#             tracker: Tracker,
#             domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
#
#         dispatcher.utter_message(text="Hello World!")
#
#         return []
# actions.py

# actions.py

import smtplib
import ssl
import nmap
import re
import ipaddress
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Any, Dict, List, Text

from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher


smtp_server = 'smtp.gmail.com'
smtp_port = 587  # For TLS
sender_email = 'tlichahmed99@gmail.com'  # Use your Gmail email address
sender_password = 'uotrhwwyzvbtjetk'
def parse_txt_file(file_path):
    name_to_email = {}
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            name, email = line.strip().split(',')
            name_to_email[name.strip()] = email.strip()
    return name_to_email
file_path = "actions/mails.txt"
name_to_email = parse_txt_file(file_path)
accept_dict = {"accepted", "approved", "accepting", "approving", "accept", "approve"}
decline_dict = {"refuse", "refused", "refusing", "declining", "decline", "declined"}
class ActionSendEmail(Action):
    def name(self) -> Text:
        return "action_send_email"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        

        # Collect the recipient email, object, and content from user inputs
        recipient_email = name_to_email.get(tracker.get_slot('recipient_email'), "Name not found in the list")
        email_object = tracker.get_slot('email_object')
        email_content = tracker.get_slot('email_content')

        try:
            # Create a secure SSL context
            context = ssl.create_default_context()

            # Set up the email server and login
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            if email_object == "" :
                email_object = "mail from rssi"
            # Compose the email
            msg = MIMEMultipart()
            msg['From'] = formataddr(('Your Bot', sender_email))
            msg['To'] = recipient_email
            msg['Subject'] = email_object
            msg.attach(MIMEText(email_content, 'plain'))

            # Send the email
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

            # Send a response message to the user
            dispatcher.utter_message(text="The email has been sent successfully.")
        except Exception as e:
            # Handle email sending errors
            dispatcher.utter_message(text="Sorry, there was an issue while sending the email. Please try again later.")
            print(str(e))
        recipient_email = ""
        email_object = ""
        email_content = "" 
        return []

class ActionSendWarningEmail(Action):
    def name(self) -> Text:
        return "action_warning_email"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        

        # Collect the recipient email, object, and content from user inputs
        name = tracker.get_slot('recipient_email')
        recipient_email = name_to_email.get(name, "Name not found in the list")
        email_object = "Concerns About Network Misuse"
        email_content = "I wanted to bring to your attention some concerns regarding your recent network activity. It appears there have been instances of misuse on the company's network, which is against our policies. Please ensure you adhere to our network usage guidelines to maintain a secure and efficient environment for all employees. Further misuse may result in penalties.\n\nThank you for your understanding and cooperation."

        try:
            # Create a secure SSL context
            context = ssl.create_default_context()

            # Set up the email server and login
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            # Compose the email
            msg = MIMEMultipart()
            msg['From'] = formataddr(('Your Bot', sender_email))
            msg['To'] = recipient_email
            msg['Subject'] = email_object
            msg.attach(MIMEText(email_content, 'plain'))

            # Send the email
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

            # Send a response message to the user
            dispatcher.utter_message(text="The email has been sent successfully.")
        except Exception as e:
            # Handle email sending errors
            dispatcher.utter_message(text="Sorry, there was an issue while sending the email. Please try again later.")
            print(str(e))
        recipient_email = ""
        email_object = ""
        email_content = "" 
        return []

class ActionSendrequestgEmail(Action):
    def name(self) -> Text:
        return "action_request_email"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        

        # Collect the recipient email, object, and content from user inputs
        name = tracker.get_slot('recipient_email')
        recipient_email = name_to_email.get(name, "Name not found in the list")
        response = tracker.get_slot('request_status')
        request = tracker.get_slot('request')
        if response in accept_dict:
            email_object = "Request Accepted"
            email_content = f"Dear {name},\nI'm pleased to inform you that your {request} request has been accepted."
        elif response in decline_dict:
            email_object = "Request declined"
            email_content = f"Dear {name},\nI'm pleased to inform you that your {request} request has been declined."
        try:
            # Create a secure SSL context
            context = ssl.create_default_context()

            # Set up the email server and login
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            # Compose the email
            msg = MIMEMultipart()
            msg['From'] = formataddr(('Your Bot', sender_email))
            msg['To'] = recipient_email
            msg['Subject'] = email_object
            msg.attach(MIMEText(email_content, 'plain'))

            # Send the email
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

            # Send a response message to the user
            dispatcher.utter_message(text="The email has been sent successfully.")
        except Exception as e:
            # Handle email sending errors
            dispatcher.utter_message(text="Sorry, there was an issue while sending the email. Please try again later.")
            print(str(e))
        recipient_email = ""
        email_object = ""
        email_content = "" 
        response=""
        request=""
        return []



class ActionNmap(Action):
    def name(self) -> Text:
        return "action_nmap"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        port_min = 80
        port_max = 81
        textt=tracker.get_slot('ip_address')
        ip_add_entered = tracker.get_slot('ip_address')
        dispatcher.utter_message(text=f"{textt}")
        # ip_add_entered='192.168.1.1'
        results = ""
        try:
            open_ports = []
            nm = nmap.PortScanner()
            for port in range(port_min, port_max + 1):
                try:
                    result = nm.scan('192.168.1.1', str(port))
                    port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
                    if port_status == "open":
                        results = results + f"Port {port} is {port_status}\n"
                except Exception as e:
                    dispatcher.utter_message(text=f"Cannot scan port {port}.")
                    dispatcher.utter_message(text=f"{str(e)}")
            dispatcher.utter_message(text=f"{results}")
        except Exception as e:
            # Handle any errors during the scan initiation
            dispatcher.utter_message(text="Sorry, there was an issue while initiating the vulnerability scan. Please try again laterrrrr.")
            dispatcher.utter_message(text=f"{textt}")
            print(str(e))
        return []
    
class ActionNmaprange(Action):
    def name(self) -> Text:
        return "action_nmap_range"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        
        port_min = 80
        port_max = 81
        textt=tracker.get_slot('ip_address')
        ip_add_entered = tracker.get_slot('ip_address')
        # dispatcher.utter_message(text=f"{textt}")
        # ip_add_entered='192.168.1.0/30'
        results = ""
        try:
            open_ports = []
            nm = nmap.PortScanner()
            for ip_address in ipaddress.IPv4Network(ip_add_entered, strict=False):
                ip_address = str(ip_address)
                results += f"Scanning {ip_address}...\n"
                for port in range(port_min, port_max + 1):
                    try:
                        result = nm.scan(ip_address, str(port))
                        port_status = (result['scan'][ip_address]['tcp'][port]['state'])
                        if port_status == "open":
                            results = results + f"Port {port} is {port_status}\n"
                    except Exception as e:
                            # dispatcher.utter_message(text=f"Cannot scan port {port}.")
                        print(str(e))
            dispatcher.utter_message(text=f"{results}")
        except Exception as e:
            # Handle any errors during the scan initiation
            dispatcher.utter_message(text="Sorry, there was an issue while initiating the vulnerability scan.")
            dispatcher.utter_message(text=f"{textt}")
            print(str(e))
        return []
    