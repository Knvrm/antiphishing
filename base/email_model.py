from .classif import Classification
class Email:
    def __init__(self, sender: str, sender_domain: str, text: str, link: str):
        self.sender = sender  # Полный адрес отправителя
        self.sender_domain = sender_domain  # Домен отправителя
        self.text = text  # Текст письма
        self.link = link  # Первая ссылка из письма
        self.classification = Classification()  # Классификация письма