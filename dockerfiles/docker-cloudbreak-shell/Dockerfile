FROM java:openjdk-7u79-jre

RUN apt-get update
RUN apt-get install -y zip bash curl

ADD start /start
ADD VERSION /

RUN VERSION=$(cat VERSION) && curl -o /cloudbreak-shell.jar https://s3-eu-west-1.amazonaws.com/maven.sequenceiq.com/releases/com/sequenceiq/cloudbreak-shell/$VERSION/cloudbreak-shell-$VERSION.jar

COPY logback.xml /logback.xml

ENTRYPOINT [ "/start" ]