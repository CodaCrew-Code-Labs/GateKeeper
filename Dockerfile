# Use the official Python image from the Docker Hub
FROM python:3.13-slim

# Set the working directory inside the container
WORKDIR /app

# Install make and any necessary build tools
RUN apt-get update && apt-get install -y make build-essential ffmpeg flac

# Install any Python dependencies (pydub in this case)
RUN pip install pydub

# Install Poetry
RUN pip install --no-cache-dir poetry

# Verify Poetry installation
RUN poetry --version

# Copy the pyproject.toml and poetry.lock files into the container
COPY pyproject.toml poetry.lock* ./

# Install dependencies with Poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-interaction --no-ansi --no-dev

# Copy the rest of your application code into the container
COPY . .
RUN pwd

# Expose the port the app runs on
EXPOSE 3000

# Define the command to run your app
CMD ["make", "run"]