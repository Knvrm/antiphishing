import re
import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from typing import List, Optional
from pymorphy2 import MorphAnalyzer
import joblib
import whois

# Модуль для анализа текста
class TextAnalysis:
    def __init__(self):
        # Инициализация морфологического анализатора
        self.morph = MorphAnalyzer()

        # Загрузка обученной модели машинного обучения для анализа фишинга
        self.model = joblib.load('phishing_model.pkl')  # Убедитесь, что файл модели существует

        # Список подозрительных фраз
        self.suspicious_phrases = [
            "ваш счет заблокирован", "подтвердите свою личность", "неизвестная активность",
            "кликните здесь", "ваш пароль", "необходимо срочно", "попробуйте сейчас",
            "неверный вход", "срочная проверка", "аккаунт заблокирован"
        ]

    def analyzeText(self, email: 'Email') -> bool:
        """
        Метод для анализа текста письма с использованием модели машинного обучения.
        Возвращает True, если письмо подозрительное, иначе False.
        """
        # Извлекаем текст из email
        text = email.body

        # Применяем модель машинного обучения для анализа
        return self._is_phishing(text)

    def _is_phishing(self, text: str) -> bool:
        """
        Приватный метод для использования модели машинного обучения для оценки текста.
        Возвращает True, если текст подозрительный (фишинг), иначе False.
        """
        # Преобразуем текст в формат, подходящий для модели (например, вектора признаков)
        features = self._extract_features(text)

        # Прогнозируем, является ли текст фишингом
        prediction = self.model.predict([features])
        return prediction == 1  # 1 — это фишинг, 0 — не фишинг

    def _extract_features(self, text: str) -> List[float]:
        """
        Приватный метод для извлечения признаков из текста, которые использует модель.
        """
        features = []
        features.append(len(text))  # Пример признака: длина текста

        suspicious_count = sum(1 for phrase in self.suspicious_phrases if phrase in text.lower())
        features.append(suspicious_count)  # Признак: количество подозрительных фраз

        return features

    def findSuspiciousPhrases(self, text: str) -> List[str]:
        """
        Метод для нахождения подозрительных фраз в тексте.
        Возвращает список найденных фраз.
        """
        found_phrases = []
        for phrase in self.suspicious_phrases:
            if phrase.lower() in text.lower():
                found_phrases.append(phrase)
        return found_phrases


# Модуль для проверки доменов
class DomainCheck:
    def __init__(self, virustotal_api_key: str):
        self.virustotal_api_key = virustotal_api_key
        self.virustotal_url = "https://www.virustotal.com/api/v3/domains/"

    def checkDomain(self, domain: str) -> bool:
        # Проверка через WHOIS
        whois_info = self.check_whois(domain)
        if whois_info:
            print(f"Информация WHOIS для домена {domain}: {whois_info}")
            # Проверка на необычные или подозрительные данные WHOIS
            if 'creation_date' in whois_info and whois_info['creation_date']:
                creation_date = whois_info['creation_date']
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                # Если домен был зарегистрирован недавно, это может быть подозрительно
                if (domain_age := (datetime.now() - creation_date).days) < 30:
                    print(f"Домен был зарегистрирован всего {domain_age} дней назад, это может быть подозрительно.")
                    return True

        # Проверка через VirusTotal API
        if self.check_virustotal(domain):
            print(f"Домен {domain} помечен как фишинговый в базе данных VirusTotal.")
            return True

        return False

    def check_whois(self, domain: str) -> Optional[dict]:
        try:
            # Получаем информацию WHOIS для домена
            whois_info = whois.whois(domain)
            return whois_info
        except Exception as e:
            print(f"Ошибка при получении WHOIS данных: {e}")
            return None

    def check_virustotal(self, domain: str) -> bool:
        headers = {"x-apikey": self.virustotal_api_key}
        try:
            # Отправка запроса к VirusTotal API
            response = requests.get(self.virustotal_url + domain, headers=headers)
            if response.status_code == 200:
                data = response.json()
                # Проверим, есть ли данные о фишинговых ссылках
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    if 'last_analysis_stats' in attributes:
                        stats = attributes['last_analysis_stats']
                        # Проверяем, есть ли отметка о фишинговых репортах
                        if stats.get('phishing', 0) > 0:
                            return True
            else:
                print(f"Ошибка при запросе в VirusTotal: {response.status_code}")
        except Exception as e:
            print(f"Ошибка при подключении к VirusTotal API: {e}")
        return False


# Модуль для проверки ссылок
class LinkCheck:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.url_base = "https://www.virustotal.com/api/v3/"

    def analyze_url(self, website: str) -> Optional[str]:
        url = f"{self.url_base}urls"
        try:
            response = requests.post(url, headers=self.headers, data={"url": website})
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get("data", {}).get("id", "Не найден")
                return analysis_id
            else:
                print(f"Ошибка при отправке URL: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Ошибка: {e}")
        return None

    def check_analysis_status(self, analysis_id: str) -> str:
        url = f"{self.url_base}analyses/{analysis_id}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                result = response.json()
                status_report = []
                # Получаем результаты анализа
                for engine, report in result.get("data", {}).get("attributes", {}).get("results", {}).items():
                    status_report.append(f"{engine} | Статус: {report.get('result', 'Неизвестно')}")
                return "\n".join(status_report)
            else:
                print(f"Ошибка при проверке статуса: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Ошибка: {e}")
        return "Не удалось получить результаты"

    def checkLinks(self, links: List[str]) -> List[str]:
        results = []
        for link in links:
            print(f"Обрабатываем ссылку: {link}")
            analysis_id = self.analyze_url(link)
            if analysis_id:
                status = self.check_analysis_status(analysis_id)
                results.append(f"Результаты для {link}:\n{status}\n")
            else:
                results.append(f"Ошибка при отправке {link} на анализ\n")
        return results


# Модуль для отправки уведомлений
class NotificationSender:
    def __init__(self, smtp_server: str, smtp_port: int, sender_email: str, sender_password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password

    def send_notification(self, recipient_email: str, subject: str, message: str):
        # Создание письма
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = self.sender_email
        msg["To"] = recipient_email

        # Отправка письма
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.sendmail(self.sender_email, recipient_email, msg.as_string())


# Модуль для классификации писем
class EmailClassifier:
    def classify(self, analysis_results: dict) -> str:
        text_analysis = analysis_results["text_analysis"]
        domain_check = analysis_results["domain_check"]
        link_check = analysis_results["link_check"]

        # Логика классификации
        if domain_check or any("phishing" in result.lower() for result in link_check):
            return "Опасное"
        elif text_analysis or any("suspicious" in result.lower() for result in link_check):
            return "Подозрительное"
        else:
            return "Безопасное"


# Модуль для обработки писем
class MailProcessor:
    def __init__(self, text_analyzer: TextAnalysis, domain_checker: DomainCheck, link_checker: LinkCheck):
        self.text_analyzer = text_analyzer
        self.domain_checker = domain_checker
        self.link_checker = link_checker

    def process_email(self, email: 'Email') -> dict:
        # Анализ текста письма
        text_analysis_result = self.text_analyzer.analyzeText(email)

        # Проверка домена отправителя
        domain_check_result = self.domain_checker.checkDomain(email.sender_domain)

        # Проверка ссылок в письме
        link_check_result = self.link_checker.checkLinks(email.links)

        # Возвращаем результаты анализа
        return {
            "text_analysis": text_analysis_result,
            "domain_check": domain_check_result,
            "link_check": link_check_result
        }


# Основной класс системы
class AntiPhishingSystem:
    def __init__(self, mail_processor: MailProcessor, email_classifier: EmailClassifier, notification_sender: NotificationSender):
        self.mail_processor = mail_processor
        self.email_classifier = email_classifier
        self.notification_sender = notification_sender

    def process_and_notify(self, email: 'Email', recipient_email: str):
        # Обработка письма
        analysis_results = self.mail_processor.process_email(email)

        # Классификация письма
        classification_result = self.email_classifier.classify(analysis_results)

        # Отправка уведомления
        self.notification_sender.send_notification(
            recipient_email=recipient_email,
            subject="Результат проверки письма",
            message=f"Ваше письмо было классифицировано как '{classification_result}'."
        )


# Класс для представления письма
class Email:
    def __init__(self, body: str, sender_domain: str, links: List[str]):
        self.body = body
        self.sender_domain = sender_domain
        self.links = links


# Пример использования
if __name__ == "__main__":
    # Инициализация компонентов
    virustotal_api_key = "6c37fb8dc32c4665939056efe8ca9b9b7ef52eca9900f19b1fbc8eb4c03a11d7"  # Замените на ваш ключ
    text_analyzer = TextAnalysis()
    domain_checker = DomainCheck(virustotal_api_key)
    link_checker = LinkCheck(virustotal_api_key)

    mail_processor = MailProcessor(text_analyzer, domain_checker, link_checker)
    email_classifier = EmailClassifier()
    notification_sender = NotificationSender(
        smtp_server="smtp.gmail.com",
        smtp_port=587,
        sender_email="your_email@gmail.com",
        sender_password="your_password"
    )

    # Создание системы
    anti_phishing_system = AntiPhishingSystem(mail_processor, email_classifier, notification_sender)

    # Создаем тестовое письмо
    email = Email(
        body="Уважаемый пользователь, пожалуйста, обновите свои данные по ссылке: http://phishing-site.com",
        sender_domain="phishing-domain.com",
        links=["http://phishing-site.com"]
    )

    # Обработка письма и отправка уведомления
    anti_phishing_system.process_and_notify(email, recipient_email="user@example.com")