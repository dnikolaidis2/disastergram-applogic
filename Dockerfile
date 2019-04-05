FROM python:3.6

EXPOSE 5000

WORKDIR /user/src/app

COPY requirements.txt ./
RUN pip install --no-cache -r requirements.txt

COPY src/. .

CMD ["python", "app.py"]