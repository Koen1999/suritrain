# SuriTrain

## Network traces used for research

Benign network traces that were used can be found here:

1. https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-14/ (Visible)
2. https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-33/ (Invisible)
3. https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/ (Invisible)
4. https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/ (Invisible)

Malspam Download Scenario:

1. https://www.malware-traffic-analysis.net/2021/04/12/index.html (Visible)
2. https://www.malware-traffic-analysis.net/2021/07/02/index.html (Invisible)
3. https://www.malware-traffic-analysis.net/2022/09/21/index.html (Invisible)
4. https://www.malware-traffic-analysis.net/2023/12/11/index.html (Invisible)

RAT Scenario:

1. https://www.malware-traffic-analysis.net/2024/01/09/index.html (Invisible)
2. https://www.malware-traffic-analysis.net/2024/03/14/index.html (Invisible)

There is a third trace for the RAT scenario that is currently not in the public domain and too large (>1GB) to share as part of this repository. Therefore, we cannot make this available at this time.
The PCAPs collected for the Baby and PHP Information Disclosure scenario contain identifying information and are therefore not available. Sadly, PCAPs are not an easy data format to anonymize, since identifying information can be contained in many locations. A typical anonymization method like randomizing IP addresses and removing packet payloads is not suitable, since the detection rules engineered during the workshop may rely on deep packet inspection.
Despite this, we believe the included traces are sufficient to allow reviewers to assess the methodology by which the datasets used for our analysis are gathered.
We note that the network traces used as part of our experiments are not part of our core contribution. We intend to make the remaining used PCAPs fully available after acceptance, when preserving anonymity is no longer a concern.

## Using the SuriCap platform

### Configuration

Modify `docker-compose.yml` to configure the following:

1. A password for the Postgres database in `services.postgres.environment.POSTGRES_PASSWORD` and `services.umami.environment.DATABASE_URL`
2. The number of workers (test runners) you want to run on the main instance in `services.django.environment.N_WORKERS`
3. PgAdmin credentials in `services.pgadmin.environment` if you want to use PgAdmin for database monitoring
4. Additionally, you may want to change the ports Nginx is exposed on and subnet ranges to prevent overlap with pre-existing used IP addresses.

Modify `djangosite/djangosite/settings.py` to configure the following:

1. A new secret `SECRET_KEY`
2. The domain name you want to use in `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`
3. The chosen password for the Postgres database in `DATABASES.default.PASSWORD`
4. Configure an SMTP client using `EMAIL_BACKEND` and the settings directly underneath (e.g., you can use Gmail)

Modify `init-letsencrypt.sh` to reflect the domain name(s) that you want to use for hosting the platform.

### Installation

To do the initial deployment of the platform, ensure Docker is installed on your host and the current user is allowed to deploy containers and expose relevant ports.
Then simply, run the following commands.

1. `docker compose up -d`
2. `docker compose exec postgres su postgres psql -c 'createdb -O postgres umami;'`
3. `sudo chmod -R 777 pgadmin_data`
4. `docker compose exec django /venv/bin/python3 manage.py makemigrations main`
5. `docker compose exec django /venv/bin/python3 manage.py migrate`
6. `docker compose exec django /venv/bin/python3 manage.py createsuperuser --username=ANONYMIZED --email=ANONYMIZED`
7. `./init-letsencrypt.sh`

You can test whether the setup is successful by visiting the platform through the chosen domain name and logging in with the newly created superuser.

### Provisioning with sample scenarios

To provision a newly created platform with the available PCAPs, you can either manually configure the scenarios through the admin page `https://ctf.anonymized.net/admin` or you can import the network traces described above using a database dump. To do the latter, execute the following two commands:

1. `docker compose exec django /venv/bin/python3 manage.py loaddata dumps/provisioning/provisioning.json`
2. `cp -r djangosite/dumps/provisioning/pcap djangosite_data/media/`

By provisioning with this data, you will also have created several users, whose usernames and passwords are identical:

1. admin: a superuser with access to the admin webpage
2. tester: a normal user, simulating the experience of a typical participant
3. leaderboard: a dummy user that can be used to project a leaderboard in a classroom
4. leaderboard_hidden: another dummy user, but this one shows the hidden test score on the leaderboard as well

### Set up worker

When dealing with a large number of simultaneous participants, it may be desirable to set up additional workers on other machines.
Note that the worker machine needs to be able to access the web server and the database on the main instance.
A worker will connect to the database and look for untested submissions, after which it will download relevant PCAPS and test submissions against those.

1. Adjust `docker-compose_worker.yml` so that `DATABASE_HOST` points to the server hosting the main instance and `N_WORKERS` specifies the number of additional workers to run.
2. `docker compose -f docker-compose_worker.yml up -d --force-recreate --build`

### Other commands

There are several commands and procedures that you will most likely not need, but that are useful to be aware of.

#### Updates

If you make changes to the platform and wish to (partially) redeploy the platform, you can simply run the following commands.

1. `docker compose cp djangosite/static django:/djangosite`
2. `docker compose up -d --force-recreate --build --no-deps django nginx`
3. `docker compose exec django /venv/bin/python3 manage.py makemigrations`
4. `docker compose exec django /venv/bin/python3 manage.py migrate`

#### Rerun tests

If you change tests or add new tests, you may want to retest past submissions. You can do so by running the following two commands.

1. `docker compose exec django /venv/bin/python3 manage.py retest &`
2. `docker compose up -d --force-recreate --build --no-deps django`

#### Ensure all tests ran correctly

Sometimes test results may appear incomplete if a container is stopped while running tests.
If you want to verify that all submissions have been tested on all available and configured network traces, you can run the following command.

1. `docker compose exec django /venv/bin/python3 manage.py verifytestresults`

#### Importing and exporting back-end database data

If you want to move your instance to a different machine, or just want to backup the data, you can use the following command to dump all database contents to a json file.

1. `docker compose exec django /venv/bin/python3 manage.py dumpdata > djangosite/dumps/dumpdata.json`

Note that the above command will not export any files uploaded via the admin portal that may be referenced in the database. Therefore, you should also make a copy of `djangosite_data/media` to restore later.

If you later want to import that json file, you can simply run the following command. Note that the dump must be available within the container.

1. `docker compose exec django /venv/bin/python3 manage.py loaddata dumps/dumpdata.json`

### Making handouts available through the platform

You can edit in the admin website the scenarios and upload a PDF file there for each scenario.
Additionally, you can make an instruction lecture PDF to participants depending on their experiment group. Users that are a member of "Experiment Group 1" will be able to access a file `djangosite/handouts/group1/handout.pdf` if that file exists. The same goes for any other experiment group number.
