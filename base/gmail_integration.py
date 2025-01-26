import os
import pickle
import re
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

# Если изменится диапазон доступа, удалите файл token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
credentials_path = os.path.join(os.path.dirname(__file__), 'credentials.json')

def authenticate_gmail():
    """Authenticate and return a Gmail service object"""
    creds = None
    # Если токен уже существует, загружаем его
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    # Если нет валидных учетных данных, запрашиваем новые
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json',
                scopes=SCOPES,
            )
            creds = flow.run_local_server(port=0)

        # Сохраняем учетные данные для следующего использования
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    try:
        # Создаем сервис для работы с Gmail API
        service = build('gmail', 'v1', credentials=creds)
        return service
    except HttpError as error:
        print(f'An error occurred: {error}')

def list_messages(service, label_ids=['INBOX']):
    """List messages in the user's Gmail inbox and extract relevant information"""
    try:
        # Получаем список сообщений
        results = service.users().messages().list(userId='me', labelIds=label_ids).execute()
        messages = results.get('messages', [])

        if not messages:
            print('No messages found.')
        else:
            print('Messages:')
            for message in messages[:5]:  # Получаем 5 последних сообщений
                msg = service.users().messages().get(userId='me', id=message['id']).execute()

                # Извлекаем отправителя
                headers = msg['payload']['headers']
                from_header = next(header['value'] for header in headers if header['name'] == 'From')

                # Извлекаем текст письма (body)
                if 'parts' in msg['payload']:
                    parts = msg['payload']['parts']
                    for part in parts:
                        if part['mimeType'] == 'text/plain':
                            body = part['body']['data']
                            text = base64.urlsafe_b64decode(body).decode('utf-8')
                            break
                else:
                    body = msg['payload']['body']['data']
                    text = base64.urlsafe_b64decode(body).decode('utf-8')

                # Ищем ссылки в тексте письма
                links = re.findall(r'(https?://[^\s]+)', text)

                # Выводим результаты
                print(f"From: {from_header}")
                print(f"Message snippet: {msg['snippet']}")
                print(f"Text: {text[:200]}...")  # Печатаем первые 200 символов текста
                print(f"Links: {links}")
                print('-' * 50)

    except HttpError as error:
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    service = authenticate_gmail()
    list_messages(service)
