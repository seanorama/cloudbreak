FROM java:openjdk-7u79-jre
MAINTAINER SequenceIQ

# Install starter script for the Periscope application
ADD bootstrap/start_periscope_app.sh /
ADD VERSION /

# Install zip
RUN apt-get update
RUN apt-get install -y zip curl

# install the periscope app
RUN VERSION=$(cat VERSION) && curl -o /periscope.jar https://s3-eu-west-1.amazonaws.com/maven.sequenceiq.com/releases/com/sequenceiq/periscope/$VERSION/periscope-$VERSION.jar
# extract schema files
RUN unzip periscope.jar schema/* -d /

WORKDIR /

ENTRYPOINT ["/start_periscope_app.sh"]