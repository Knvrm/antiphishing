import requests
from typing import List

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

if __name__ == "__main__":
    api_key = "6c37fb8dc32c4665939056efe8ca9b9b7ef52eca9900f19b1fbc8eb4c03a11d7"
    link_check = LinkCheck(api_key)

    # Список ссылок для проверки
    links_to_check = ["https://www.gismeteo.ru/"]

    results = link_check.checkLinks(links_to_check)

    # Вывод результатов
    for result in results:
        print(result)