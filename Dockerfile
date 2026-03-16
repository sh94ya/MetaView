FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install -e . 
COPY . .
EXPOSE 5000
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "main:app"]
