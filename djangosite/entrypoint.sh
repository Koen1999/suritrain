npm run preparestatic
npm run sass:release

/venv/bin/python3 manage.py collectstatic --clear --no-default-ignore --noinput

chgrp -R www-data /djangosite_dynamic
chgrp -R www-data /djangosite_data
chmod -R ug=rwx,o-rwx /djangosite_dynamic
chmod -R ug=rwx,o-rwx /djangosite_data

/venv/bin/python3 manage.py starttestservice &

/venv/bin/uwsgi --ini djangosite/uwsgi.ini
