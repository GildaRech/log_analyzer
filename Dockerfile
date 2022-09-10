FROM python:3.7-slim
RUN mkdir /code
WORKDIR /code
#ADD requirements.txt /code/
ADD code.py /code/
ADD main.py /code/
#RUN pip install --no-cache-dir -r requirements.txt
#RUN python main.py
CMD [ "python", "main.py" ]