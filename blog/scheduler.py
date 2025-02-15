from apscheduler.schedulers.background import BackgroundScheduler
import requests

def run_scheduled_jobs():
    jobs = ScheduledJob.objects.all()
    url="https://heal-haven.vercel.app/msg_called/"
    requests.get(url)
           

def start():
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_scheduled_jobs, "interval", minutes=2)  # Runs every minute
    scheduler.start()
