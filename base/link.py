import requests
from .email_model import Email

class LinkCheck:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.url_base = "https://www.virustotal.com/api/v3/"

    def analyze_url(self, website: str) -> str:
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

    def checkLink(self, email: Email):
        link = email.link
        results = []

        if link:
            analysis_id = self.analyze_url(link)

            if analysis_id:
                status = self.check_analysis_status(analysis_id)
                results.append(f":\n{status}\n")
                # print(status)
            else:
                results.append(f"Ошибка при отправке на анализ\n")
        else:
            results.append("Ссылка не найдена в письме\n")

        if any("статус: phishing" in result.lower() for result in results):
            email.classification.set_result_link_check("Фишинговая")
        elif any("статус: suspicious" in result.lower() for result in results):
            email.classification.set_result_link_check("Подозрительная")
        elif results is not None:
            email.classification.set_result_link_check("Безопасная")
        else:
            email.classification.set_result_link_check(None)