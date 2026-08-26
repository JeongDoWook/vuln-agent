from celery import Celery
from app.config import settings


celery_app = Celery(
    'worker',
    broker=settings.celery_broker,
    include=['app.workers.tasks']
)


celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Seoul',
    enable_utc=True,
    worker_enable_remote_control=False,
    # process_job은 LLM 호출로 인해 수 분간 블로킹되는 작업이다. --pool=solo로 실행하면
    # 태스크 실행 중 AMQP 하트비트를 보낼 수 없어 브로커가 유휴 연결로 판단해 끊어버리고,
    # 재연결 시 태스크가 중복 실행되는 문제가 실제로 발생함을 확인했다. prefork(기본) 풀은
    # 태스크를 별도 워커 프로세스에서 실행하므로 메인 프로세스가 하트비트를 계속 보낼 수 있다.
    worker_pool='prefork',
    broker_heartbeat=30,
)