FROM ruby:2.7-slim
 
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl nmap build-essential \
    && rm -rf /var/lib/apt/lists/*
 
# pinned versions compatible with Ruby 2.7
RUN gem install nokogiri -v 1.15.7 \
    && gem install multi_json -v 1.15.0 \
    && gem install gauntlt -v 1.0.13
 
RUN mkdir -p /tmp/attacks
WORKDIR /tmp/attacks
