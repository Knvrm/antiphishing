import whois
import requests
from datetime import datetime


class DomainCheck:
    def __init__(self, virustotal_api_key):
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

    def check_whois(self, domain: str):
        try:
            # Получаем информацию WHOIS для домена
            whois_info = whois.whois(domain)
            return whois_info
        except Exception as e:
            print(f"Ошибка при получении WHOIS данных: {e}")
            return None

    def check_virustotal(self, domain: str) -> bool:
        headers = {
            "x-apikey": self.virustotal_api_key
        }
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

if __name__ == "__main__":
    api_key = "6c37fb8dc32c4665939056efe8ca9b9b7ef52eca9900f19b1fbc8eb4c03a11d7"  # Замените на ваш ключ API
    domain_check = DomainCheck(api_key)
    domain = "msu.ru"

    if domain_check.checkDomain(domain):
        print(f"Домен {domain} может быть фишингом.")
    else:
        print(f"Домен {domain} безопасен.")
