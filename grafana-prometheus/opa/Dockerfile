FROM ubuntu
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8
ENV LANGUAGE en_US:en
ENV TZ=Europe/Stockholm
ARG UID=286665
ARG GID=286665
RUN mkdir -p /opt/policies
COPY opa_linux_amd64_v0.53 /opt
RUN chmod +x /opt/opa*
ADD entry.sh /opt
WORKDIR /opt
RUN chmod +x /opt/entry.sh
ENTRYPOINT ["/opt/entry.sh"]

