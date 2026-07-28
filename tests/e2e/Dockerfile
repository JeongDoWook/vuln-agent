# 브라우저 E2E 전용 이미지 — 베이스에 playwright npm 패키지만 얹는다.
#
# mcr.microsoft.com/playwright 이미지에는 **브라우저(/ms-playwright)만** 들어 있고
# playwright npm 패키지는 없다(전역 모듈은 corepack·npm·yarn 뿐이라 require('playwright')
# 가 MODULE_NOT_FOUND 로 죽는다). 저장소에 node_modules/package.json 을 만들지 않기 위해
# 패키지를 전역으로 얹은 얇은 이미지를 굽는다 — docs/specs/diagrams 가 plantuml 에 한글
# 폰트를 얹어 쓰는 것과 같은 패턴이다. 레이어 캐시가 먹으므로 두 번째부터는 사실상 공짜.
#
# 버전은 고정한다(latest 는 재현되지 않는다). 브라우저와 패키지가 어긋나면 실행이 죽으므로
# 베이스 태그와 npm 버전을 **같은 값**으로 맞춘다.
FROM mcr.microsoft.com/playwright:v1.62.0-jammy
RUN npm i -g playwright@1.62.0
