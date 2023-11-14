# CSRF_Scanner
[개발 부문] 대구/경북 사이버보안 UPx3 캠페인 출품작

## 설명
CSRF 스캐너는 웹 어플리케이션의 CSRF 취약점을 식별하고 진단하기 위해 설계된 도구입니다. HTTP 헤더, 쿠키 속성, 폼을 종합적으로 분석하여 견고한 웹 어플리케이션 보안을 보장합니다.

## 기능
- **종합적 분석**
- 헤더, 쿠키, 폼을 분석하여 웹 어플리케이션의 CSRF 취약점을 스캔합니다.
- **자동 보고서 생성**
- 보안 취약점을 신속하게 식별하고 해결할 수 있도록 .log 형식의 상세한 보고서를 생성합니다.
- **기술 스택**
- Python을 사용하여 구축되었으며 `requests`, `BeautifulSoup`, `reportlab`과 같은 라이브러리를 사용합니다.

## 사용법
스캐너를 실행합니다: python csrf_scanner.py
- py 파일이 있는 디렉토리와 동일한 경로에 .log 파일이 생성됩니다.

## 향후 개선사항
- 실제 CSRF 공격 시뮬레이션.
- 에러 및 예외 처리 개선.
- 개선된 로깅 및 사용자 친화적 웹 인터페이스
