FROM java:openjdk-7u79-jre
MAINTAINER SequenceIQ

# Install starter script for the Cloudbreak application
ADD bootstrap/start_cloudbreak_app.sh /
ADD bootstrap/wait_for_cloudbreak_api.sh /
ADD VERSION /

# Install zip
RUN apt-get update
RUN apt-get install -y zip curl

# install the cloudbreak app
RUN VERSION=$(cat VERSION) && curl -o /cloudbreak.jar https://s3-eu-west-1.amazonaws.com/maven.sequenceiq.com/releases/com/sequenceiq/cloudbreak/$VERSION/cloudbreak-$VERSION.jar

# extract schema files
RUN unzip cloudbreak.jar schema/* -d /

WORKDIR /

ENTRYPOINT ["/start_cloudbreak_app.sh"]