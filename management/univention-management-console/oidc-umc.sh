#!/bin/bash

touch /etc/umc-oidc.secret
chmod 0600 /etc/umc-oidc.secret
echo -en 'us8Upr7BQ9i2EjRUxjnkkNh1m3aAdl53' > /etc/umc-oidc.secret


ucr set \
	umc/oidc/default-op=default \
	umc/oidc/default/client-realm=Ucs \
	umc/oidc/default/client-id=umc \
	umc/oidc/default/server=https://keycloak.projekt21.ucs.intranet/ \
	umc/oidc/default/client-secret-file=/etc/umc-oidc.secret \
	umc/oidc/default/extra-parameter='kc_idp_hint'
