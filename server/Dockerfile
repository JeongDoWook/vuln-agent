FROM php:8.3-apache

# 수신 API 와 대시보드가 MySQL 에 붙기 위한 확장
#   bz2: Red Hat OVAL 피드는 .bz2 로만 배포된다(평문·gzip 은 404). 스트림 래퍼
#   (compress.bzip2://)로 XMLReader 에 바로 물려 25MB XML 을 메모리에 통째로 올리지 않는다.
RUN apt-get update && apt-get install -y --no-install-recommends libbz2-dev \
 && docker-php-ext-install pdo_mysql mysqli bz2 \
 && a2enmod rewrite \
 && rm -rf /var/lib/apt/lists/*

# 문서 루트를 public/ 로 이동 (src/ 는 웹에서 직접 접근 불가)
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# 업로드/본문 크기 여유 (패키지 목록 JSON 이 수백 KB)
RUN { \
      echo 'post_max_size=32M'; \
      echo 'upload_max_filesize=32M'; \
      echo 'memory_limit=512M'; \
      echo 'date.timezone=Asia/Seoul'; \
    } > /usr/local/etc/php/conf.d/vulnagent.ini

# ETag 조건부 요청이 304 를 돌려주게 한다.
#   기본값(DeflateAlterETag AddSuffix)은 gzip 응답의 ETag 에 "-gzip" 을 **붙여 내보내면서**
#   If-None-Match 비교는 접미사 없는 원본 ETag 로 한다. 그래서 브라우저가 방금 받은 ETag 를
#   그대로 되보내도 **절대 안 맞아 매번 200 + 본문 전체**가 나간다.
#   실측(dev, Caddy 없이 Apache 단독, /assets/app.css):
#     받은 ETag "234b6-659153d45a1d5-gzip" 그대로 재요청 → 200 OK (본문 41KB 재전송)
#     "-gzip" 을 뗀 "234b6-659153d45a1d5" 로 재요청     → 304 Not Modified
#     If-Modified-Since 는 원래부터 304 (즉 ETag 경로만 깨져 있었다)
#   NoChange 로 두면 압축 여부와 무관하게 같은 ETag 를 쓰므로 매칭이 성립한다.
#   표현이 달라도 ETag 가 같아지는 문제는 Apache 가 함께 내보내는 `Vary: Accept-Encoding`
#   (실측 확인)이 중간 캐시에서 처리한다.
RUN a2enmod deflate \
 && { echo 'DeflateAlterETag NoChange'; } > /etc/apache2/conf-available/vulnagent-etag.conf \
 && a2enconf vulnagent-etag

# 실제 소스는 compose 의 볼륨 마운트로 덮어씌워지지만,
# 볼륨 없이 이미지만으로도 동작하도록 복사해 둔다.
COPY . /var/www/html/

WORKDIR /var/www/html
