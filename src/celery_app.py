from celery import Celery
import os
from dotenv import load_dotenv

# load .env if needed
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# Create Celery app
celery_app = Celery(
    'remoterun',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    include=['src.tasks']
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

__all__ = ["celery_app"]
