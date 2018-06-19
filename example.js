const ItsMe    = require('./');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function ask(question) {
    return new Promise(function(resolve) {
        rl.question(question, resolve);      
    })
}

async function main() {
    const client_id     = await ask('Client id: ');
    const auth_redirect = await ask('Redirect url: ');

    const itsme = new ItsMe({
        client_id,
        auth_redirect
    });

    const keysPath = await ask('Keys file: ');
    const keys = require(keysPath);
    itsme.setKeys(keys);

    //-----

    const authUrl = await itsme.authUrl('openid profile address phone service:PROJECT_LOGIN');

    console.log('Please sign in on the following url:')
    console.log(authUrl);
    console.log("");

    const token = await ask('Received token: ');
    const authResult = await itsme.parseAuthResponse(token)

    console.log("");
    console.log("Parsed auth response:")
    console.log(JSON.stringify(authResult, null, 4));
    console.log("")

    const userinfo = await itsme.userinfo( authResult.access_token );
    console.log("Received userinfo:")
    console.log(JSON.stringify(userinfo, null, 4));

    rl.close();
}

main().catch(console.error)