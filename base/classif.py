import re
from urllib.parse import urlparse

class Classification:
    def __init__(self):
        pass

    def classify(self, email: str) -> str:
        """
        Классификация письма на основе анализа текста, домена и ссылок.
        :param email: Текст email для анализа.
        :return: Результат классификации письма.
        123
        """
        # Применение проверок
        if self.is_spam(email):
            return "Spam"
        elif self.is_phishing(email):
            return "Phishing"
        elif self.is_ham(email):
            return "Ham"
        else:
            return "Unknown"

    def is_spam(self, email: str) -> bool:
        """
        Проверка на спам. Например, по наличию ключевых слов или подозрительных паттернов.
        :param email: Текст письма.
        :return: True, если письмо является спамом, False в противном случае.
        """
        spam_keywords = ['buy now', 'limited offer', 'free', 'win', 'urgent']
        for keyword in spam_keywords:
            if keyword.lower() in email.lower():
                return True
        return False

    def is_phishing(self, email: str) -> bool:
        """
        Проверка на фишинг. Например, по подозрительным ссылкам или доменам.
        :param email: Текст письма.
        :return: True, если письмо является фишингом, False в противном случае.
        """
        links = self.extract_links(email)
        for link in links:
            domain = self.get_domain_from_url(link)
            if self.is_suspicious_domain(domain):
                return True
        return False

    def is_ham(self, email: str) -> bool:
        """
        Проверка на легитимные письма.
        :param email: Текст письма.
        :return: True, если письмо легитимное (не спам и не фишинг).
        """
        # Например, проверим, что письмо не содержит подозрительных слов.
        return not self.is_spam(email) and not self.is_phishing(email)

    def extract_links(self, email: str) -> list:
        """
        Извлечение всех ссылок из текста письма.
        :param email: Текст письма.
        :return: Список ссылок.
        """
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email)
        return links

    def get_domain_from_url(self, url: str) -> str:
        """
        Извлечение домена из URL.
        :param url: URL.
        :return: Домен из URL.
        """
        parsed_url = urlparse(url)
        return parsed_url.netloc

    def is_suspicious_domain(self, domain: str) -> bool:
        """
        Проверка, является ли домен подозрительным.
        :param domain: Домен для проверки.
        :return: True, если домен подозрительный, False в противном случае.
        """
        suspicious_domains = ['example.com', 'phishingsite.com', 'malicioussite.com']
        if domain in suspicious_domains:
            return True
        return False


# Пример использования
email = """
Hello, we have a limited time offer just for you. Buy now on http://example.com to get a discount!
"""
classification = Classification()
result = classification.classify(email)
print(result)  # Выведет: Spam
