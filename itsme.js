const JWT        = require('./jwt');
const { Issuer } = require('openid-client');
const jose       = require('node-jose');
const clientAuth = require('jwt-bearer-client-auth');
const request    = require('request-promise-native');

//http://e2emybank.labo.sixdots.be/
//http://mybank.labo.sixdots.be/

class Itsme {
    
    //options: 
    // -production
    // -client_id
    // -auth_redirect
    // -issuer_tll
    // -server_id

    constructor(options) {
        const defaults = {
            production: false
        }

        if(typeof(options) === 'string') {
            options = {
                client_id: options
            }
        }

        this.serverId = options.server_id || Math.round(Math.random() * 10000);
        this.index    = 1;
        this.options = options = Object.assign(defaults, options || {});

        if(!options.client_id)
            throw('Client id not provided')
    }

    setKeys(keys) {
        keys = JSON.parse(JSON.stringify(keys));

        const keystore = keys.map((key) => Object.assign(key, JWT.jwkBase64Regenerate(key)))
        this.keystore = jose.JWK.asKeyStore(keystore);
        this.keystore.then((keystore) => {
            this.keystore = keystore.toJSON(true);
        })

        this.keys = keys.map((key) => Object.assign(key, { key: JWT.parseJwk(key) }));
    }

    getKey(search) {
        search = search || {};
        const keystore = this.keys || [];
        for(var key of keystore) {
            var found = true;
            for(var x in search) {
                if(search[x] !== key[x]) {
                    found = false;
                    break;
                }
            }

            if(found) {
                return key;
            }
        }

        return null
    }
    
    async loadPublicKeys() {
        const res = await request({
            uri: this.issuer.jwks_uri,
            method: 'GET',
            json: true 
        })

        this.issuerKeys = res.keys || [];
    }
    
    async getClient() {
        if(this.clientLoading)
            await this.clientLoading;
        
        if(!this.client || (this.options.issuer_tll && this.client.setupTime < Date.now() - this.options.issuer_tll)) {
            console.log('Discover itsme issuer..');

            this.clientLoading = (async () => {
                const url = this.options.production ? 'https://merchant.itsme.be/oidc/.well-known/openid-configuration' : 
                                                  'https://e2emerchant.itsme.be/oidc/.well-known/openid-configuration';

                this.issuer    = await Issuer.discover(url);
                const keystore = this.keystore ? (this.keystore.then ? await this.keystore : this.keystore) : null;

                this.client = new this.issuer.Client({
                    client_id: this.options.client_id,
                    token_endpoint_auth_method: 'private_key_jwt',
                }, keystore);

                await this.loadPublicKeys();
                delete this.clientLoading;
            })()

            await this.clientLoading;
        }

        return this.client;
    }

    async authUrl(scope, redirect_uri) {
        const client = await this.getClient();
        
        if(typeof(scope) === 'object') {
            scope.redirect_uri = scope.redirect_uri || redirect_uri || this.options.auth_redirect;
            return client.authorizationUrl(scope);
        }

        return client.authorizationUrl({
            redirect_uri: redirect_uri || this.options.auth_redirect,
            scope: scope,
        });
    }

    async authFor(endpoint) {
        const client    = await this.getClient();
        //return client.authFor(endpoint);
        const client_id = this.options.client_id;

        endpoint  = this.issuer[`${endpoint}_endpoint`]
        const key = this.getKey({
            kty: 'RSA',
            use: 'sig'
        });

        return {
            body: {
                client_assertion: clientAuth.generate(key, client_id, client_id, endpoint, 3600, {
                    payload: {
                        jti: client_id + '-' + this.serverId + '-' + (this.index++) + '-' + Date.now()
                    }
                }),
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            }
        }
    }

    async loadAuthResponse(code, redirect_uri) {
        const client = await this.getClient();

        if(typeof(code) !== 'object') {
            code = { code }
        }
        
        //return await client.authorizationCallback(redirect_uri || this.options.auth_redirect, )

        const authAssert = await this.authFor('token');
        var body = Object.assign(code, {
            grant_type:  'authorization_code',
            redirect_uri: redirect_uri || this.options.auth_redirect,
        });

        body = Object.assign(body, authAssert.body);

        const options = {
            uri: this.issuer.token_endpoint,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            form: body,
            json: true 
        };

        try {
            return await request(options);
        } catch(e) {
            if(!e.response) {
                throw(e)
            }

            throw({
                code:    e.statusCode,
                error:   e.error,
                message: e.message,
                headers: e.response.headers,
                
                request: {
                    headers: e.response.request.headers,
                    body:    e.response.request.body,
                }
            });
        }
    }
    
    __parseJwt(jwt) {
        if(jwt.headers.alg !== 'RSA-OAEP')
            throw('JWT algorithm not supported ('+jwt.headers.alg+')')

        /*const keystore = this.keystore ? (this.keystore.then ? await this.keystore : this.keystore) : null;
        if(!keystore)
            throw('keystore not found');

        const key = keystore.all({
            kty: 'RSA',
            use: 'enc'
        })[0];*/
        
        const key = (this.getKey({
            kty: 'RSA',
            use: 'enc'
        }) || {}).key;

        if(!key)
            throw('Encryption key not found');

        jwt.privateKey = key;

        //----
        this.issuerKeys = this.issuerKeys || [];
        const issuerKey = this.issuerKeys.find((o) => o.use === 'sig');

        if(issuerKey)
            jwt.setIssuerKey(issuerKey);

        return jwt.parse();
    }
    
    async parseAuthResponse(code, redirect_uri) {
        const res = await this.loadAuthResponse(code, redirect_uri);
        const jwt = new JWT(res.id_token);
        res.id = this.__parseJwt(jwt).payload;
        return res;
    }

    async userinfoRaw(accessToken) {
        await this.getClient();

        const options = {
            uri: this.issuer.userinfo_endpoint,
            method: 'GET',
            headers: {
                'Accept': 'application/jwt, application/json, text/plain, text/html',
                'Content-Type': 'application/jwt',
                'Authorization': `Bearer ${accessToken}`,
            },
            json: true
        };

        try {
            return await request(options);
        } catch(e) {
            if(!e.response) {
                throw(e)
            }

            throw({
                code:    e.statusCode,
                error:   e.error,
                message: e.message,
                headers: e.response.headers,
                
                request: {
                    headers: e.response.request.headers,
                    body:    e.response.request.body,
                }
            });
        }
    }

    async userinfo(accessToken) {
        const info = await this.userinfoRaw(accessToken);
        const jwt = new JWT(info);
        const userinfo = this.__parseJwt(jwt).payload;

        if(userinfo.address) {
            try {
                userinfo.address = JSON.parse(userinfo.address);
            } catch(e) {}
        }

        return userinfo;
    }
}

module.exports = Itsme;