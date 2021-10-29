FROM ubuntu:18.04
COPY . /app
#add certificate list
ADD ../icaoData /app/data/icaoData

RUN apt-get -y update
RUN apt install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get install python3.9 -y
RUN apt-get install python3-pip -y
RUN apt install python3.9-distutils -y
RUN python3.9 --version

ENTRYPOINT ["tail"]
CMD ["-f","/dev/null"]