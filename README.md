# node-itsme
Unofficial NodeJs itsme library used to authenticate users.

Simple example:

```node
const ItsMe    = require('itsme');

async function main() {

    const itsme = new ItsMe({
        client_id: 'test account',
        auth_redirect: 'https://localhost:8080/itsme'
    });

    itsme.setKeys([
      enc_key,
      sig_key
    );

    //-----

    const authUrl = await itsme.authUrl('openid profile address phone service:BIT4YOU_LOGIN');

    console.log('Please sign in on the following url:')
    console.log(authUrl);
    console.log("");
    
    //-----
    //Once token received:

    const token = "...";
    const authResult = await itsme.parseAuthResponse(token)

    console.log("");
    console.log("Parsed auth response:")
    console.log(JSON.stringify(authResult, null, 4));
    console.log("")

    const userinfo = await itsme.userinfo( authResult.access_token );
    console.log("Received userinfo:")
    console.log(JSON.stringify(userinfo, null, 4));
}

main().catch(console.error)
```
