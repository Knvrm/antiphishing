import re
from typing import List
from pymorphy2 import MorphAnalyzer
import joblib  # Импортируем joblib напрямую


class TextAnalysis:
    def __init__(self):
        # Инициализация морфологического анализатора
        self.morph = MorphAnalyzer()

        # Загрузка обученной модели машинного обучения для анализа фишинга
        self.model = joblib.load('phishing_model.pkl')  # Модель машинного обучения для анализа

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
        Это может включать различные методы, такие как TF-IDF или другие векторизации.
        """
        # Пример: извлечение длины текста, количества подозрительных фраз и т.д.
        features = []
        features.append(len(text))  # Пример признака: длина текста

        suspicious_count = sum(1 for phrase in self.suspicious_phrases if phrase in text.lower())
        features.append(suspicious_count)  # Признак: количество подозрительных фраз

        # Вы можете добавить дополнительные признаки, такие как частота использования специфических слов
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
