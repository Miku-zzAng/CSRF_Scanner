import time
import re
import requests
import random
from bs4 import BeautifulSoup as bsp
from urllib.parse import urljoin, urlparse, urlunparse
import logging

security_headers_info = """
┌────────────────────────────────────────────────────────────
｜ 1. 본 솔루션에서는 웹사이트 내의 각 페이지마다 네 가지 보안 헤더가 각각 설정되어 있는지를 확인하여 로깅합니다.
｜ 참고하시어, 헤더 설정이 미비한 페이지의 경우 사전 설정을 통하여 어느정도 CSRF 공격으로부터 안전한 환경을 구축할 수 있습니다.
｜
｜ ※ 경고 ※ 모든 페이지에 네 가지의 보안 헤더가 모두 적용되는 것이 항상 좋은 상황이 아님을 알립니다!
｜ 각 헤더 별 적용 시 주의사항을 참고하여, 헤더 설정 시 신중하게 고려해주세요.
└────────────────────────────────────────────────────────────

● Content-Security-Policy (CSP):웹 페이지가 로드할 수 있는 리소스의 유형과 출처를 제한합니다.
본 헤더는 스크립트, 스타일시트, 이미지 등이 어디서 로드되어야 하는지를 명시함으로써 외부 스크립트의 실행을 제한할 수 있으므로, 
크로스 사이트 스크립팅(XSS) 공격 및 악성 스크립트에 의한 CSRF 공격을 방어할 수 있습니다.
- 잘 못 설정하면 웹사이트의 기능을 손상시킬 수 있습니다.
- 복잡한 애플리케이션에서는 설정이 어려울 수 있습니다.

●  Strict-Transport-Security (HSTS): 웹 사이트가 항상 HTTPS를 사용하여 통신하도록 강제합니다.
이는 중간자 공격(Man-in-the-Middle, MitM)을 방어할 수 있고, CSRF 토큰 탈취로부터 안전합니다.
- HTTP를 사용하는 서브도메인이 있는 경우 문제가 될 수 있습니다.
- HSTS 프리로딩을 고려할 때 신중해야 합니다.

● X-Content-Type-Options: 주로 nosniff 옵션과 함께 사용되어 브라우저가 리소스를 로드할 때 MIME 타입을 변경하지 못하도록 방지합니다.
헤더가 "nosniff"로 설정되면, 스크립트나 스타일시트 등의 리소스가 잘못된 타입으로 해석되어 실행되는 것을 방지할 수 있습니다. 이를 통해 일부 CSRF 공격을 방어할 수 있습니다.
- 거의 모든 경우에 안전하게 사용할 수 있습니다.

● X-Frame-Options: 웹 페이지가 <iframe> 내에서 어떻게 렌더링될지를 제어합니다.
본 헤더를 통해 클릭 재킹(Clickjacking) 공격을 방어할 수 있습니다. 클릭 재킹은 사용자가 의도하지 않은 액션을 수행하게 만드는 공격 기법으로, CSRF 공격을 유발할 수 있습니다.
- <iframe>을 사용해야 하는 경우, 이 헤더의 설정에 따라 일부 문제가 발생할 수 있습니다.

┌────────────────────────────────────────────────────────────
｜ 2. 본 솔루션에서는 웹사이트 내의 각 페이지마다 설정된 쿠키의 설정 상태를 분석하여 제공합니다.
｜ 상위 로깅된 쿠키를 제외하고 중복되지 않는 쿠키들만 하위 로깅되며, RAW 헤더를 통하여 쿠키의 원시 정보를 함께 제공하고 있습니다.
｜ 또한, 각 쿠키별로 'CSRF' 취약점 방어와 관련된 세 가지 보안 관련 속성에 대한 적용 상태를 제공합니다.
｜ 참고하시어, 쿠키 속성 적용이 미비한 쿠키의 경우 사전 적용을 통하여 어느정도 CSRF 공격으로부터 안전한 환경을 구축할 수 있습니다.
｜ 
｜ ※ 경고 ※ 모든 쿠키에 세 가지의 주요 보안 속성이 모두 적용되는 것이 항상 좋은 상황이 아님을 알립니다!
｜ 각 속성 별 적용 시 주의사항을 참고하여, 쿠키 속성 설정 시 신중하게 고려해주세요.
└────────────────────────────────────────────────────────────

●  Secure가 설정된 쿠키는 HTTPS 프로토콜을 통해서만 전송됩니다.
- HTTP를 통해 전송되는 경우, 쿠키는 브라우저에 의해 무시됩니다.
- 본 속성은 중간자 공격(Man-in-the-Middle Attack)으로부터 쿠키를 보호하는 데 도움이 됩니다.
- 웹 전체가 'HTTPS'를 사용하지 않는경우, 일부 기능이 제대로 작동하지 않을 수 있습니다.

● HttpOnly가 설정된 쿠키는 JavaScript를 통해 접근할 수 없습니다.
- 쿠키는 서버와 클라이언트 간에만 HTTP/HTTPS 헤더를 통해 전송됩니다.
- 본 속성은 크로스 사이트 스크립팅(XSS) 공격으로부터 쿠키를 보호하는 데 도움이 됩니다.
- JavaScript에서 접근할 수 없으므로, 클라이언트 측 스크립트에서 해당 쿠키를 사용해야 하는 기능이 있다면 문제가 발생할 수 있습니다.

● SameSite: 쿠키가 어떤 요청과 함께 전송되어야 하는지를 지정합니다. (Strict, Lax, None 세 가지 옵션이 있습니다.)
본 속성은 크로스 사이트 요청 위조(CSRF) 공격으로부터 보호하는 데 도움이 됩니다.

- Strict: 같은 사이트에서만 쿠키가 전송됩니다.
   >>  사용자가 외부 사이트에서 현재 사이트로 바로 이동할 경우(예: 링크 클릭), 쿠키가 전송되지 않을 수 있습니다. 이로 인해 사용자가 로그아웃되거나 세션이 종료될 수 있습니다.
- Lax: 탑 레벨 탐색이 발생하는 경우에만 다른 사이트로 쿠키가 전송됩니다.
   >> GET 요청에서는 쿠키가 전송되지만, POST 요청에서는 전송되지 않습니다. 따라서 POST를 사용하는 중요한 작업에 영향을 줄 수 있습니다.
- None: 모든 경우에 쿠키가 전송됩니다. 단, Secure 속성도 함께 설정해야 합니다.
   >> 이 설정은 쿠키를 모든 요청과 함께 전송하므로, CSRF 공격에 취약해질 수 있습니다. None을 설정할 경우 반드시 Secure 플래그도 함께 설정해야 합니다.

"""

logging.basicConfig(filename='output.log', level=logging.INFO, format='%(message)s', filemode='w')

logging.info(security_headers_info)

visited_links = set() # 이미 방문한 링크를 set으로 저장

session = requests.Session() # 세션 객체를 생성하여 상태를 유지

analyzed_headers = set() # 이미 분석한 헤더를 저장할 set

# 보안 헤더 분석
# 이미 분석한 헤더를 저장할 set
analyzed_security_headers = set()

# 보안 헤더 분석{full_url}
def analyze_security_headers(response, full_url):
    important_headers = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options'
    ]
    
    # 중요한 헤더만 추출
    important_header_values = {k: response.headers[k] for k in important_headers if k in response.headers}
    
    # 헤더를 문자열로 변환
    headers_str = str(sorted(important_header_values.items()))
    
    # 헤더가 이전에 분석한 것과 동일한지 확인
    if headers_str in analyzed_security_headers:
        #logging.info(f"[!] {full_url}　　▶　　주요 보안 헤더 설정이 이전에 분석한 페이지와 동일하므로 해당 페이지의 분석을 생략")
        return
    
    # 분석한 헤더를 set에 추가
    analyzed_security_headers.add(headers_str)
    logging.info("\n")
    logging.info(f"\n----------------------------------------\n{full_url} 에 적용된 보안 헤더 정보 \n")
    for header, value in response.headers.items():
        logging.info(f"- {header}: {value}")
    logging.info("\n")
    for header in important_headers:
        if header in response.headers:
            logging.info(f"[Good] {header}  [■]")
        else:
            logging.info(f"[Warning] {header} [ ]")
    #logging.info("-------------------------------------------------------------------")

     
     
     
def analyze_cookies(response, unique_cookies):
    cookie_attributes = ['Secure', 'HttpOnly', 'SameSite']
    new_cookies = set()
    cookie_info_list = []
    
    if 'Set-Cookie' in response.headers:
        set_cookie_header = response.headers['Set-Cookie']
        cookies = re.split(r',\s*(?=[^;]*=)', set_cookie_header)
        
        for cookie in cookies:
            cookie_parts = cookie.split(';')
            cookie_name = cookie_parts[0].split('=')[0].strip()
            
            if cookie_name not in unique_cookies:
                new_cookies.add(cookie_name)
                unique_cookies.add(cookie_name)
                
                cookie_info = f"▶  '{cookie_name}' 쿠키 - "
                for attribute in cookie_attributes:
                    if any(attribute in part for part in cookie_parts[1:]):
                        cookie_info += f"{attribute} [■] "
                    else:
                        cookie_info += f"{attribute} [ ] "
                
                cookie_info_list.append(cookie_info)
    
    return new_cookies, cookie_info_list



def analyze_raw_cookie_headers(response, full_url, new_cookies):
    if 'Set-Cookie' in response.headers:
        raw_cookies = response.headers['Set-Cookie']
        cookies = re.split(r',\s*(?=[^;]*=)', raw_cookies)
        logging.info("\n")
        for cookie in cookies:
            cookie_parts = cookie.split(';')
            cookie_name = cookie_parts[0].split('=')[0].strip()
            
            if cookie_name in new_cookies:  # new_cookies에 있는 쿠키만 출력
                logging.info(f"[Raw] {cookie_name} 쿠키 원시 설정 정보: {cookie}")
                new_cookies.remove(cookie_name)  # 이미 출력했으므로 제거

        
        
                
def anal_cookie(response, full_url, unique_cookies):
    new_cookies, cookie_info_list = analyze_cookies(response, unique_cookies)
    #logging.info("-------------------------------------------------------------------")
    if new_cookies:
        logging.info(f"\n----------------------------------------\n{full_url} 의 쿠키 설정 분석 정보 \n")
        
        for cookie_info in cookie_info_list:
            logging.info(cookie_info)
        
        # 원시 쿠키 정보 출력
        analyze_raw_cookie_headers(response, full_url, new_cookies)  # new_cookies를 전달
        #logging.info("-------------------------------------------------------------------")

    
    
    
def normalize_url(url):
    # URL에서 쿼리 파라미터와 프래그먼트 제거
    parsed_url = urlparse(url)
    return urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))


# 이미 분석한 헤더와 쿠키 설정을 저장할 set
analyzed_pages = set()

def crawl_page(base_url, path="/", unique_cookies=set()): # path 탐색할 경로
    full_url = urljoin(base_url, path) # urljoin 절대경로 생성
    normalized_url = normalize_url(full_url)  # 쿼리 파라미터 제거하여 URL 정규화
    
    # (제외 01) 연결된 다른 도메인에 대해서는 크롤링 제외
    parsed_url = urlparse(full_url) # URL을 파싱
    if parsed_url.netloc != urlparse(base_url).netloc: # netloc 도메인 이름
        return
    
    # (제외 02) 이미 방문한 URL은 스킵
    if normalized_url in visited_links:
        return  # 이미 방문한 정규화된 URL은 스킵
    visited_links.add(normalized_url)  # 방문한 URL을 세트에 추가
    #logging.info(visited_links)
    
    # (제외 03) 크롤링이 10분 이상 소요되는 경우, 종료
    start_time = time.time()
    max_time = 5
    if time.time() - start_time > max_time:
        logging.info("타임 아웃")
        return
    
    user_agents = [
    # Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36',
    # Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1',
    # Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15',
    # Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134',
    # Internet Explorer
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
    # Opera
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36 OPR/34.0.2036.25',
    # Others
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 SeaMonkey/2.48',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2)'
]
    
    chosen_user_agent = random.choice(user_agents)
    headers = {'User-Agent': chosen_user_agent}
    response = session.get(full_url, headers=headers) # 세션을 통해 GET 요청을 보냄 # requests.get() HTTP GET 요청을 보냄. 응답을 저장
    
    if response.status_code != 200:
        logging.info(f"\n----------------------------------------\n{full_url}에서 에러- 상태코드 : {response.status_code}")
        return # 응답이 200(성공)이 아니라면 함수 종료
    else:
        # 헤더와 쿠키 설정을 문자열로 변환
        headers_str = str(sorted(response.headers.items()))
        cookies_str = str(sorted(response.cookies.items()))
        
        # 헤더와 쿠키 설정이 이전에 분석한 것과 동일한지 확인
        page_signature = headers_str + "|" + cookies_str
        #if page_signature in analyzed_pages:
            #logging.info(f"\n\n\n{full_url}\n헤더와 쿠키 설정이 이전에 분석한 페이지와 동일하므로 해당 페이지의 분석을 생략")
        analyzed_pages.add(page_signature)
        
        # 보안 헤더 분석
        analyze_security_headers(response, full_url)
        
        # 쿠키 설정 분석
        anal_cookie(response, full_url, unique_cookies)
    
    soup = bsp(response.content, 'html.parser') # 응답 내용 content를 HTML 파서로 파싱하여 저장
    
    # 웹 페이지에서 폼을 찾아서, 각 폼이 어떤 액션을 수행하는지 분석
    forms = find_forms(soup)
    for form in forms: # 각 폼의 action과 method를 가져옴
        action = form.get('action')
        method = form.get('method')
        
        if method == 'POST':
            logging.info(f"\n----------------------------------------\n{full_url} 에서 form 탐색")
            logging.info(f"\n▷  찾은 form: Action = {action} / Method = {method}")
            
            # URL에 'login', 'password', 'change' 등이 포함되어 있는지 확인
            sensitive_keywords = ['login', 'password', 'change']
            if any(keyword in normalized_url for keyword in sensitive_keywords):
                logging.info(f"[Sensitive URL Detected] {normalized_url}")
                
                # 정규식 패턴을 더 엄격하게 설정
                csrf_token = form.find('input', {'name': re.compile('.*(csrf|token|auth).*', re.I)})
                if not csrf_token:
                    csrf_token = form.find('input', {'id': re.compile('.*(csrf|token|auth).*', re.I)})
                if not csrf_token:
                    csrf_token = form.find('input', {'class': re.compile('.*(csrf|token|auth).*', re.I)})
                if not csrf_token:
                    csrf_token = form.find('input', {'data-csrf': re.compile('.*(csrf|token|auth).*', re.I)})
                if not csrf_token:
                    csrf_token = form.find('input', {'data-token': re.compile('.*(csrf|token|auth).*', re.I)})
                
                if csrf_token:
                    logging.info(f"[민감한 URL] CSRF token 탐색 성공: {csrf_token}")
                    
            test_csrf_token_vulnerability(form, full_url, action)
            
    #logging.info("form 찾기 종료")
    # 페이지 내의 다른 링크 탐색
    for link in soup.find_all('a'): # 모든 a태그를 찾아 리스트화하여 for문 돌림
        href = link.get('href') # 모든 a태그의 href 속성을 가져옴
        if href and not href.startswith("#"): # href 값이 존재하고, #로 시작하지 않는 링크만
            next_path = urljoin(full_url, href) # next_path 절대 경로 생성
            #logging.info(f"탐색: {next_path}")
            crawl_page(base_url, next_path, unique_cookies) # 재귀함수 구현
            
            
def find_forms(soup): # form을 더 정교하게 찾는 함수
    found_forms = []

    # ID나 Class를 이용한 정규식
    found_forms.extend(soup.find_all('form', {'id': re.compile('.*(login|sign-in).*', re.I)}))

    # Name 속성을 이용한 정규식
    found_forms.extend(soup.find_all('form', {'name': re.compile('.*(login|auth).*', re.I)}))

    # 여러 속성을 동시에 검사
    found_forms.extend(soup.find_all('form', {'id': re.compile('.*(login|sign-in).*', re.I), 'name': re.compile('.*(login|auth).*', re.I)}))

    # CSS Selector와 정규식을 함께 사용
    found_forms.extend(soup.select('form[id*="login"]'))

    # 폼 내부의 입력 필드를 이용한 검색
    all_forms = soup.find_all('form')
    found_forms.extend([form for form in all_forms if form.find('input', {'name': re.compile('.*(user|pass).*', re.I)})])

    # 중복 제거
    unique_forms = list(set(found_forms))

    return unique_forms   

       
def test_csrf_token_vulnerability(form, base_url, action):
    # POST 요청에 대한 CSRF 토큰 취약점 검사 로직
    if form.get('method').lower() == 'post':
        csrf_token = form.find('input', {'name': re.compile('.*(csrf|token|auth).*', re.I)})# 정규식을 이용하여, form 내부에서 'csrf' 또는 'token'이라는 문자열을 이름(name) 속성에 포함하는 모든 input 태그를 대소문자 구분없이 찾음.
        if not csrf_token:
            csrf_token = form.find('input', {'id': re.compile('.*(csrf|token|auth).*', re.I)})
        if not csrf_token:
            csrf_token = form.find('input', {'class': re.compile('.*(csrf|token|auth).*', re.I)})
        if not csrf_token:
            csrf_token = form.find('input', {'data-csrf': re.compile('.*(csrf|token|auth).*', re.I)})
        if not csrf_token:
            csrf_token = form.find('input', {'data-token': re.compile('.*(csrf|token|auth).*', re.I)}) 
        
        if csrf_token:
            logging.info(f"▷  찾은 CSRF 토큰의 form: {csrf_token}")
            manipulated_token = csrf_token.get('value', '') + 'manipulated'  # 토큰 값 조작하여 요청 보내기
            data = {csrf_token.get('name'): manipulated_token} # {'토큰이름': '토큰값manipulated'}
            # logging.info(data)
            
            for input_tag in form.find_all('input'): # 각 폼의 input 태그를 찾고, type과 name 속성을 가져옴
                if input_tag.get('type') != 'hidden':  # 히든 타입의 경우, 제외
                    data[input_tag.get('name')] = 'test'
                    # logging.info(f"히든타입이 아닌 경우의 데이터: {data}")
                    
            manipulated_response = session.post(urljoin(base_url, action), data=data) # 세션을 통해 POST 요청을 보냄 # 조작된 데이터로 post 요청을 보냄. / url_join acion과 결합하여 완전한 URL 생성
            
            if manipulated_response.status_code == 200:
                logging.info(f"\n[Warning] CSRF 토큰 유효성 검증 우회 가능: {action}")
            else:
                logging.info(f"\n[Good] CSRF 토큰 유효성 검증 성공: {action}, 상태코드: {manipulated_response.status_code}")
                
        else:
            logging.info(f"\n[Warning] CSRF 토큰 미존재: {action}")
            

# 초기 URL 접속: 웹 사이트의 기본 URL로 요청을 보내 페이지 내용을 가져옴
start_url = input("CSRF 취약점을 진단하려는 URL을 입력하세요: ")

# 크롤링 시작
print("크롤링 시작, 해당 py파일과 동일한 디렉토리의 output.log 확인 ")
crawl_page(start_url)
