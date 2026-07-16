# plantuml/plantuml 에 한글 폰트를 넣은 렌더 전용 이미지. render.sh 가 이걸 빌드해서 쓴다.
#
# 왜 필요한가: 원본 plantuml/plantuml 에는 한글 폰트가 하나도 없다(fc-list :lang=ko 결과 0개).
# PlantUML 은 Java AWT 폰트 메트릭으로 글자 폭을 재서 SVG 에 textLength="..." 를 박아 넣는데,
# 한글 글리프가 없으면 그 폭이 실제보다 짧게 계산된다. 브라우저는 진짜 한글 폰트로 그리면서
# 그 짧은 textLength 에 맞춰 자간을 줄이므로(lengthAdjust="spacing") 글자가 서로 겹쳐 뭉갠다.
# render.sh 의 -charset UTF-8 은 입력 인코딩만 맞출 뿐, 이 폭 계산은 못 고친다.
FROM plantuml/plantuml
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends fonts-nanum \
 && fc-cache -f \
 && rm -rf /var/lib/apt/lists/*
