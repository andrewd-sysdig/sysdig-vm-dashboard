FROM python:3.12-slim

WORKDIR /app

COPY app.py download_sysdig_reports.py requirements.txt /app/

RUN python3 -m pip install -r requirements.txt
 
RUN mkdir /app/reports && mkdir /app/reports/coles_critical_and_high && mkdir /app/reports/coles_critical_and_high_archive && chown -R 1000:1000 /app/reports

USER 1000

ENTRYPOINT ["python3", "app.py"]