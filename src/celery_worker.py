from celery import Celery
import os
import sys

# Add the src directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# load .env if needed
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# Import the celery app from main.py instead of creating a new one
from main import celery_app

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# import tasks so they are registered
import main
