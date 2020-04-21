from app import celery, create_app
from app.utils.nessus import Batch
# Make sure to import your celery tasks here!
# Otherwise the worker will not pick them up.
from celery.schedules import crontab

app = create_app()


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Calls test('hello') every 10 seconds.
    #sender.add_periodic_task(10.0, nessus_update.s(), name='add every 10')
    sender.add_periodic_task(
        crontab(hour='*', minute=30, day_of_week='*'),
        nessus_update.s()
    )

@celery.task
def test(arg):
    print(arg)

@celery.task
def nessus_update():
    Batch.run_batch()


with app.app_context():
    celery.start()
