# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Install pipreqs
RUN pip install pipreqs

# Copy the current directory contents into the container at /app
COPY . /app

# Run pipreqs to generate requirements.txt
RUN pipreqs --force . 

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port on which the task manager will run
EXPOSE 5001

# Run app.py when the container launches
CMD ["sh", "-c", "while true; do python app.py; echo 'app.py crashed with exit code $?'; sleep 5; done"]