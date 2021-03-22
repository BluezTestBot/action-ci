FROM blueztestbot/bluez-build:dev

COPY *.sh /
COPY *.py /
COPY *.ini /
COPY gitlint /.gitlint

ENTRYPOINT [ "/entrypoint.sh" ]
