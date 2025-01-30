import os
import pickle
import re
import base64
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class Email:
    """Класс для хранения информации о письме"""

    def __init__(self, sender_domain: str, text: str, links: list):
        self.sender_domain = sender_domain
        self.text = text
        self.links = links

    def __repr__(self):
        return f"Email(from={self.sender_domain}, text={self.text[:50]}..., links={self.links})"


class MailService:
    """Класс для работы с Gmail API"""
    def __init__(self):
        self.service = self.authenticate_gmail()

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

                # Извлекаем домен отправителя
                sender_domain = from_header.split('@')[-1] if from_header and '@' in from_header else 'Unknown'

                # Извлекаем текст письма
                text = self.extract_text(msg)

                # Ищем ссылки в тексте письма
                links = re.findall(r'(https?://[^\s]+)', text)

                # Создаем объект Email и добавляем в список
                email = Email(sender_domain=sender_domain, text=text, links=links)
                emails.append(email)

        except HttpError as error:
            print(f'An error occurred: {error}')

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
        """Обрабатывает письмо для анализа (заглушка)"""
        print(f"Analyzing email from: {email.sender_domain}")
        print(f"Text preview: {email.text[:100]}...")
        print(f"Links found: {email.links}")


if __name__ == '__main__':
    mail_service = MailService()
    emails = mail_service.get_emails()

    for email in emails:
        mail_service.pass_data_for_analysis(email)
