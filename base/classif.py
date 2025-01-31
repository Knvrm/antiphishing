class Classification:
    def __init__(self):
        self.resultLinkCheck = None
        self.resultDomainCheck = None
        self.resultTextAnalyze = None
        self.resultClassification = None

    def set_result_link_check(self, result: str):
        self.resultLinkCheck = result

    def set_result_domain_check(self, result: str):
        self.resultDomainCheck = result

    def set_result_text_analyze(self, result: bool):
        self.resultTextAnalyze = result

    def classify(self):
        if self.resultDomainCheck == 'Фишинговый' or self.resultLinkCheck == "Фишинговая":
            self.resultClassification = 'Опасное'
            return "Опасное"
        elif (self.resultDomainCheck == "Недавно зарегистрирован"
              or self.resultTextAnalyze == 'Фишинговый' or self.resultLinkCheck == "Подозрительная"):
            self.resultClassification = 'Подозрительное'
            return "Подозрительное"
        else:
            self.resultClassification = 'Безопасное'
            return "Безопасное"