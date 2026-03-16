FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install -e . 
COPY . .
EXPOSE 5000
CMD ["python", "main.py"]
