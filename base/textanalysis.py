import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from .email_model import Email

class TextAnalysis:
    def __init__(self):
        # Загружаем модель и токенизатор для классификации фишинговых писем
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Загрузка токенизатора и модели для детектирования фишинговых писем
        self.tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.1")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            "cybersectony/phishing-email-detection-distilbert_v2.1")

    def analyzeText(self, email: 'Email') -> bool:
        """
        Метод для анализа текста письма с использованием модели машинного обучения.
        Возвращает True, если письмо фишинговое, иначе False.
        """
        # Извлекаем текст из email
        text = email.text

        # Преобразуем текст письма в формат, который принимает модель
        inputs = self.tokenizer(
            text,
            return_tensors="pt",  # Формат для PyTorch
            truncation=True,  # Обрезка текста, если он слишком длинный
            max_length=512  # Максимальная длина текста
        )

        # Получаем предсказание модели
        with torch.no_grad():
            outputs = self.model(**inputs)
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)

        # Получаем вероятности для каждого класса
        probs = predictions[0].tolist()

        # Создаем словарь с результатами
        labels = {
            "legitimate_email": probs[0],
            "phishing_url": probs[1],
            "legitimate_url": probs[2],
            "phishing_url_alt": probs[3]
        }

        max_label = max(labels.items(), key=lambda x: x[1])

        if max_label[0] == "phishing_url":
            # print(text)
            # print('Фишинговый текст')
            email.classification.set_result_text_analyze('Фишинговый')
        else:
            # print(text)
            # print('Безопасный текст')
            email.classification.set_result_text_analyze('Без признаков фишинга')

        return max_label[0] == "phishing_url"
