FROM python:3.11.2
COPY wrapper /app/wrapper
WORKDIR /app/wrapper/
RUN pip3 install -r requirements.txt
RUN pip3 install uvicorn
EXPOSE 8000
CMD ["uvicorn","api_wrapper:app","--host","0.0.0.0", "--reload"]
