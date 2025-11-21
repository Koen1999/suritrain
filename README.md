# SuriCap CTF website

# Installation

1. `docker compose up -d`
2. `docker compose exec postgres su postgres psql -c 'createdb -O postgres umami;'`
3. `sudo chmod -R 777 pgadmin_data`
4. `docker compose exec django /venv/bin/python3 manage.py makemigrations main`
5. `docker compose exec django /venv/bin/python3 manage.py migrate`
6. `docker compose exec django /venv/bin/python3 manage.py createsuperuser --username=ANONYMIZED --email=ANONYMIZED`
7. `./init-letsencrypt.sh`

# Updates

1. `docker compose cp djangosite/static django:/djangosite`
2. `docker compose up -d --force-recreate --build --no-deps django nginx`
3. `docker compose exec django /venv/bin/python3 manage.py makemigrations`
4. `docker compose exec django /venv/bin/python3 manage.py migrate`

# Set up worker

1. `docker compose -f docker-compose_worker.yml up -d --force-recreate --build`

# Rerun tests

1. `docker compose exec django /venv/bin/python3 manage.py retest &`
2. `docker compose up -d --force-recreate --build --no-deps django`

# Ensure all tests ran correctly

1. `docker compose exec django /venv/bin/python3 manage.py verifytestresults`

# Export data

1. `docker compose exec django /venv/bin/python3 manage.py dumpdata > djangosite/dumps/dumpdata.json`

# Load data

1. `docker compose exec django /venv/bin/python3 manage.py loaddata dumps/dumpdata.json`

# Setup experiment

1. Download Microsoft Forms Intake as Excel file and place it under `djangosite/forms`
2. Modify `intake.py`,`credentials.py`, and `outtake.py` to reference the Excel file and contain correct details for date, location, etc.
3. `docker compose exec django /venv/bin/python3 manage.py intake`
4. `docker compose exec django /venv/bin/python3 manage.py credentials`

# Round up the experiment

1. `docker compose exec django /venv/bin/python3 manage.py outtake`

# Export experiment data

1. Download Microsoft Forms Lecture and Outtake as Excel file and place it under `djangosite/forms`
2. `docker compose exec django /venv/bin/python3 manage.py analyze`
