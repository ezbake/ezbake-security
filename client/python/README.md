EzBake Security Service - Python
================================


## Install

```bash
$ python setup.py install
```

__NOTE__: the tests won't run without the security service running in development mode


## Example

```py
from ezconfiguration.EZConfiguration import EZConfiguration
from ezsecurity.client import EzSecurityClient

ezconfig = EZConfiguration()
client = EzSecurityClient(ezconfig)

client.ping()
client.app_info("AppSecurityId", "OptionalTargetSecurityId")

# pseudocode for the headers...
dn = headers['HTTP_EZB_VERIFIED_USER_INFO']
sig = headers['HTTP_EZB_VERIFIED_USER_INFO']

# verify the headers
client.validateSignedDn(dn, sig)

# get the user's info
token = client.user_info(dn, sig, "OptionalTargetSecurityId")  # target security ID might be your application's security ID

# If you pass the token to another service, it must:
client.validateReceivedToken(token)

```
