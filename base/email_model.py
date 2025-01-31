from .classif import Classification
class Email:
    def __init__(self, sender: str, sender_domain: str, text: str, link: str): #конструктор
        self.sender = sender  # адрес отправителя
        self.sender_domain = sender_domain  # домен отправителя
        self.text = text  # текст письма
        self.link = link  # первая ссылка из письма
        self.classification = Classification()  # классификация письма