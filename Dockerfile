#
# Container to build Linux SEAL libraries, python wrapper, and examples
#
FROM ubuntu:18.04

# Install binary dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    git \
    make \
    python3 \
    python3-dev \
    python3-pip \
    sudo \
    libdpkg-perl \
    --no-install-recommends

# Build SEAL libraries
RUN mkdir -p /SEAL/
COPY pySEAL/SEAL/ /SEAL/SEAL/
WORKDIR /SEAL/SEAL/
RUN chmod +x configure
RUN sed -i -e 's/\r$//' configure
RUN ./configure
RUN make
ENV LD_LIBRARY_PATH SEAL/bin:$LD_LIBRARY_PATH

# Build SEAL C++ example
COPY pySEAL/SEALExamples /SEAL/SEALExamples
WORKDIR /SEAL/SEALExamples
RUN make

# Build SEAL Python wrapper
COPY pySEAL/SEALPython /SEAL/SEALPython
COPY pySEAL/SEALPythonExamples /SEAL/SEALPythonExamples
WORKDIR /SEAL/SEALPython
RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install -r requirements.txt
RUN git clone https://github.com/pybind/pybind11.git
WORKDIR /SEAL/SEALPython/pybind11
RUN git checkout a303c6fc479662fd53eaa8990dbc65b7de9b7deb
WORKDIR /SEAL/SEALPython
RUN python3 setup.py build_ext -i
ENV PYTHONPATH $PYTHONPATH:/SEAL/SEALPython:/SEAL/bin

# Add placeholder for notebooks directory to be mounted
VOLUME /notebooks

# Return to SEAL root directory
WORKDIR /SEAL

# Clean-up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy the Program Files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8000
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8

CMD ["uvicorn", "backend_app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
