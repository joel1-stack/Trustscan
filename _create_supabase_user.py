import os, sys, django

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
os.environ['DATABASE_URL'] = 'postgresql://postgres:oGftHn0JoqZWAZJp@db.rzqryyarxezmsspudmxv.supabase.co:6543/postgres'
os.environ['DB_ENGINE'] = 'django.db.backends.postgresql'
os.environ['DB_NAME'] = 'postgres'
os.environ['DB_USER'] = 'postgres'
os.environ['DB_PASSWORD'] = 'oGftHn0JoqZWAZJp'
os.environ['DB_HOST'] = 'db.rzqryyarxezmsspudmxv.supabase.co'
os.environ['DB_PORT'] = '6543'

sys.path.insert(0, os.path.dirname(__file__))

django.setup()
from django.core.management import call_command

# Run migrations
print('Running migrations...')
call_command('migrate', '--noinput', verbosity=1)

# Create superuser
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='joelkaunda15@gmail.com').exists():
    User.objects.create_superuser(
        username='joelkaunda',
        email='joelkaunda15@gmail.com',
        password='Incorrect9.',
        first_name='Joel',
        last_name='Kaunda'
    )
    print('Superuser created in Supabase!')
else:
    print('Superuser already exists in Supabase')

# Verify
user = User.objects.get(email='joelkaunda15@gmail.com')
print(f'Verified: {user.email} (staff={user.is_staff}, superuser={user.is_superuser})')
