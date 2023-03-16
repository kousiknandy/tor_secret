# tor_secret
Python code to write tor hidden services from the secret key

## Write tor hidden service directory
Given the ToR Onion V3 secret key, write the three files:
```
hostname  
hs_ed25519_public_key  
hs_ed25519_secret_key
```
I have no idea why would you want to do this, though. I had to.

## Usage
`python3 tor_secret.py <private_key_file> <tor_hidden_service_directory>`

### Acknowledgement
Cannibalized version of https://github.com/cmehay/pytor 
Removed V2, and hence no dependency hell just python (my requirement)
