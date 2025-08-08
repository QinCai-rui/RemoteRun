from celery import Celery
import os
import sys

# Add the src directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# load .env if needed
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

celery_app = Celery(
    'remoterun',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# import tasks so they are registered
import main
