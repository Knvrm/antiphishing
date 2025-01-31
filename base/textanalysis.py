import os #взаимодействие с ос
import torch #нейросеть
from transformers import AutoTokenizer, AutoModelForSequenceClassification #автотоке
from .email_model import Email # Импортируем класс Email для работы с письмами

class TextAnalysis:#класс
    def __init__(self):
        # Загружаем модель и токенизатор для классификации фишинговых  писем
        current_dir = os.path.dirname(os.path.abspath(__file__))   #d

        # Загрузка токенизатора и модели для детектирования  фишинговых писем
        self.tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.1") #token
        self.model = AutoModelForSequenceClassification.from_pretrained(  #model
            "cybersectony/phishing-email-detection-distilbert_v2.1") #модель

    def analyzeText(self, email: 'Email') -> bool:# Метод для анализа текста письма с использованием модели машинного обучения.
        #Возвращает True, если письмо фишинговое, иначе False.
        # Извлекаем текст из  email
        text = email.text #текст
        # Преобразуем текст письма в формат,  который принимает  модель
        inputs = self.tokenizer( #токен
            text,  #текст
            return_tensors="pt",  # Формат для  PyTorch
            truncation=True,  # Обрезка текста, если он слишком  длинный
            max_length=512  # Максимальная длина  текста
        ) 
        # Получаем предсказание  модели
        with torch.no_grad(): # Отключаем вычисление градиентов, так как это только предсказание
            outputs = self.model(**inputs) # Передаем данные в модель
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1) # Применяем softmax для вероятностей
        # Получаем вероятности  для каждого класса
        probs = predictions[0].tolist() #используется для преобразования тензора (или многомерного массива) в список
        # Создаем  словарь с результатами
        labels = {
            "legitimate_email": probs[0],
            "phishing_url": probs[1],
            "legitimate_url": probs[2],
            "phishing_url_alt": probs[3]
        }
        max_label = max(labels.items(), key=lambda x: x[1])
        if max_label[0] == "phishing_url":
            #  print(text)
            #  print('Фишинговый текст')
            email.classification.set_result_text_analyze('Фишинговый')
        else:
            #  print(text)
            #  print('Безопасный текст')
            email.classification.set_result_text_analyze('Без признаков фишинга')

        return max_label[0] == "phishing_url"
