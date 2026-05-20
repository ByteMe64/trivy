FROM docker:latest

RUN apk add --no-cache curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

COPY scan.sh /scan.sh
RUN chmod +x /scan.sh

ENTRYPOINT ["sh", "/scan.sh"]
