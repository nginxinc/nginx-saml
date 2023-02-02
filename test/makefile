# makefile to prepare SAML test env for nginx
WORKDIR=${CURDIR}

# build directory
SESRC:=~/nginx-se
NGX:=$(WORKDIR)/nginx-se
NJS:=$(WORKDIR)/njs
IDP:=$(WORKDIR)/idp

# nginx installation prefix
PREFIX:=$(WORKDIR)/nginx

# SAML conf files
CFLIST:=saml_sp.js frontend_server.conf saml_sp_configuration.conf saml_sp.server_conf

# this is needed to instrument code properly
PROF_CFLAGS=-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC
PROF_LDFLAGS=-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now

# used nginx modules
MODULES= --with-http_ssl_module           \
         --with-http_addition_module      \
         --with-http_sub_module           \
         --with-http_gzip_static_module   \
         --with-http_auth_request_module  \
         --with-http_gunzip_module        \
         --with-http_stub_status_module   \
         --with-http_session_log_module   \
         --with-stream                    \
         --with-stream_ssl_module         \
         --with-stream_ssl_preread_module \
         --with-file-aio                  \
         --with-mail_ssl_module           \
         --with-http_v2_module            \
         --with-http_slice_module         \
         --with-http_auth_jwt_module      \
         --with-debug                     \
         --with-threads                   \
         --with-compat                    \
         --add-module=$(NJS)/nginx

all: build start
	@echo "Done!"

# not really targets, just shortcuts
.PHONY: build start stop restart clean

# builds NGINX Plus and NJS
build:
	cp -r $(SESRC) $(WORKDIR) || { echo "nginx-se not found!"; exit 1; }
	hg clone http://hg.nginx.org/njs
	cd $(NJS) && \
	./configure && make
	cd $(NGX) && \
	hg up se && \
	./auto/configure 	--with-cc-opt="$(PROF_CFLAGS)"   \
                    	--with-ld-opt="$(PROF_LDFLAGS)"  \
                        --prefix=$(PREFIX) $(MODULES) && \
	make -j$(nproc) install && \
	rm -f $(NGX)/autotest.*
	@rm -rf $(NGX)
	@rm -rf $(NJS)
	@echo "NGINX and NJS BUILD OK"

# start nginx with saml configuration and SimpleSAMLphp docker container
start:
	cd $(IDP) &&\
	docker-compose up -d --build
	cd $(WORKDIR) &&\
	$(foreach f,$(CFLIST),cp ../$(f) $(PREFIX)/conf/;)
	cd $(PREFIX) &&\
	sudo sbin/nginx -p $(PREFIX) -c $(PREFIX)/conf/frontend_server.conf

# start nginx with saml configuration and SimpleSAMLphp docker container
restart:
	cd $(WORKDIR) &&\
	$(foreach f,$(CFLIST),cp ../$(f) $(PREFIX)/conf/;)
	cd $(PREFIX) &&\
	sudo sbin/nginx -s reload

# stop nginx with saml configuration and SimpleSAMLphp docker container
stop:
	cd $(IDP) &&\
	docker-compose down
	cd $(PREFIX) &&\
	sudo sbin/nginx -s quit

# cleanup
clean:
	@rm -rf $(PREFIX)
	@rm -rf $(NGX)
	@rm -rf $(NJS)
	@echo "CLEANUP DONE"