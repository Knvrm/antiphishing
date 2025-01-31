import os
import pickle
import re
import base64
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError
from .link import LinkCheck
from .domen import DomainCheck
from .textanalysis import TextAnalysis
from .email_model import Email

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class MailService:
    """Класс для работы с Gmail API"""
    def __init__(self):
        self.api_key = "6c37fb8dc32c4665939056efe8ca9b9b7ef52eca9900f19b1fbc8eb4c03a11d7"
        self.service = self.authenticate_gmail()
        self.link_checker = LinkCheck(api_key=self.api_key)
        self.domain_checker = DomainCheck(api_key=self.api_key)
        self.text_analysis = TextAnalysis()

    def authenticate_gmail(self):
        """Аутентификация и подключение к Gmail API"""
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json',
                    scopes=SCOPES,
                )
                creds = flow.run_local_server(port=0)

            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

        try:
            service = build('gmail', 'v1', credentials=creds)
            return service
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def get_emails(self, label_ids=['INBOX']):
        """Получает письма из Gmail"""
        emails = []
        try:
            results = self.service.users().messages().list(userId='me', labelIds=label_ids).execute()
            messages = results.get('messages', [])

            for message in messages:
                msg = self.service.users().messages().get(userId='me', id=message['id']).execute()

                # Получаем отправителя
                headers = msg['payload']['headers']
                from_header = next((header['value'] for header in headers if header['name'] == 'From'), None)

                # Извлекаем полный адрес отправителя
                if from_header:
                    full_sender = from_header.split('<')[0].strip()  # Полный адрес отправителя
                    sender_domain = from_header.split('@')[-1] if '@' in from_header else 'Unknown'

                # Извлекаем текст письма и очищаем от HTML
                text = self.extract_text(msg)

                # Ищем ссылки в тексте письма, но извлекаем только первую
                links = re.findall(r'(https?://[^\s]+)', text)
                first_link = links[0] if links else None  # Возвращаем только первую ссылку

                # Создаем объект Email и добавляем в список
                email = Email(sender=full_sender, sender_domain=sender_domain, text=text, link=first_link)
                emails.append(email)

        except Exception as e:
            print(f"Ошибка при получении писем: {e}")

        return emails

    def extract_text(self, msg):
        """Извлекает текст из тела письма"""
        try:
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = part['body']['data']
                        return base64.urlsafe_b64decode(body).decode('utf-8')
            else:
                body = msg['payload']['body']['data']
                return base64.urlsafe_b64decode(body).decode('utf-8')
        except Exception as e:
            print(f"Error extracting email text: {e}")
            return "Error extracting text"

    def pass_data_for_analysis(self, email: Email):
        self.link_checker.checkLink(email)

        self.domain_checker.checkDomain(email)

        self.text_analysis.analyzeText(email)
