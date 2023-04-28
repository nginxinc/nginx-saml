# makefile to prepare SAML test env for nginx
WORKDIR=${CURDIR}

# build directory
SESRC:=~/nginx-se
NGX:=$(WORKDIR)/nginx-se
NJS:=$(WORKDIR)/njs
IDP:=$(WORKDIR)/idp

# nginx installation prefix
PREFIX:=$(WORKDIR)/nginx

# SAML conf files to copy
CFLIST:=saml_sp.js frontend.conf saml_sp_configuration.conf saml_sp.server_conf
CRT:=saml.crt saml.key saml.spki

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
	cd $(IDP) &&\
	printf "[ req ]\ndefault_bits = 4096\nencrypt_key = no\ndistinguished_name = req_distinguished_name\n[ req_distinguished_name ]" > openssl.conf &&\
	for name in saml; do \
		openssl req -x509 -new \
		-config openssl.conf -subj "/CN=$$name/" \
		-out $$name.crt -keyout $$name.key \
		>> openssl.out 2>&1 || exit 1; \
		openssl x509 \
		-in $$name.crt -outform DER \
		-out $$name.der \
		>> openssl.out 2>&1 || exit 1; \
		openssl x509 -inform DER \
		-in $$name.der -pubkey -noout \
		> $$name.spki 2>&1 || exit 1; \
	done &&\
	chmod -R 664 saml.* &&\
	mkdir $(PREFIX)/conf/conf.d &&\
	$(foreach f,$(CRT),cp $(f) $(PREFIX)/conf/conf.d/;)
	cd $(PREFIX) &&\
	chmod -R 777 conf &&\
	chmod -R 777 logs &&\
	sed -i 's/listen\s*80;/listen       8011;/g' conf/nginx.conf &&\
	sed -i 's/#gzip\s*on;/include conf.d\/*.conf;/g' conf/nginx.conf &&\
	ln -s conf/conf.d conf.d
	@echo "NGINX and NJS BUILD OK"

# start nginx with saml configuration and SimpleSAMLphp docker container
start:
	cd $(IDP) &&\
	docker-compose up -d --build
	cd $(WORKDIR) &&\
	$(foreach f,$(CFLIST),cp ../$(f) $(PREFIX)/conf.d/;)
	cd $(PREFIX) &&\
	sudo sbin/nginx -p $(PREFIX)

# start nginx with saml configuration and SimpleSAMLphp docker container
restart:
	cd $(WORKDIR) &&\
	$(foreach f,$(CFLIST),cp ../$(f) $(PREFIX)/conf.d/;)
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
	@rm -rf $(IDP)/saml.*
	@rm -rf $(IDP)/openssl.*
	@echo "CLEANUP DONE"