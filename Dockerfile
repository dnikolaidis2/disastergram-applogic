FROM python:3.6

EXPOSE 5000

WORKDIR /user/src/app

COPY requirements.txt ./
RUN pip install --no-cache -r requirements.txt

RUN mkdir app
RUN mkdir instance

COPY ./app ./app
COPY ./instance ./instance

ENV FLASK_APP /user/src/app/app
ENV FLASK_ENV development
ENV FLASK_DEBUG 1
CMD ["flask", "run", "--host", "0.0.0.0"]