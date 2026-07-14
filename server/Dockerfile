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

# 실제 소스는 compose 의 볼륨 마운트로 덮어씌워지지만,
# 볼륨 없이 이미지만으로도 동작하도록 복사해 둔다.
COPY . /var/www/html/

WORKDIR /var/www/html
