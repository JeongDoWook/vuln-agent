FROM php:8.3-apache

# 수신 API 와 대시보드가 MySQL 에 붙기 위한 확장
RUN docker-php-ext-install pdo_mysql mysqli \
 && a2enmod rewrite

# 문서 루트를 public/ 로 이동 (src/ 는 웹에서 직접 접근 불가)
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# 업로드/본문 크기 여유 (패키지 목록 JSON 이 수백 KB)
RUN { \
      echo 'post_max_size=32M'; \
      echo 'upload_max_filesize=32M'; \
      echo 'memory_limit=256M'; \
      echo 'date.timezone=Asia/Seoul'; \
    } > /usr/local/etc/php/conf.d/vulnagent.ini

# 실제 소스는 compose 의 볼륨 마운트로 덮어씌워지지만,
# 볼륨 없이 이미지만으로도 동작하도록 복사해 둔다.
COPY . /var/www/html/

WORKDIR /var/www/html
