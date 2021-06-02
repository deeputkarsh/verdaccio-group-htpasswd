# Verdaccio Module For User Auth Via Htpasswd with groups

`verdaccio-htpasswd-groups` extends the default authentication plugin for the [Verdaccio](https://github.com/verdaccio/verdaccio) `verdaccio-htpasswd`.

## Install

As simple as running:
    $ npm install -g verdaccio-htpasswd-groups

## Configure

    auth:
        htpasswd:
            files:
              - file: ./htpasswd
                isDefault: false
                groupName: admin
              - file: ./dev-htpasswd
                isDefault: true
                groupName: developer
            # Maximum amount of users allowed to register, defaults to "+infinity".
            # You can set this to -1 to disable registration.
            #max_users: 1000

## Generate htpasswd username/password combination

If you wish to handle access control using htpasswd file, you can generate 
username/password combination form 
[here](http://www.htaccesstools.com/htpasswd-generator/) and add it to htpasswd
file.
