FROM blueztestbot/bluez-build:latest

COPY *.sh /
COPY *.py /
COPY *.ini /
COPY gitlint /.gitlint

CMD [ "/entrypoint.sh" ]
