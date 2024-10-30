\#! /bin/bash
export AUTH_CLIENT_URL=http://192.168.1.76
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519_jenkins
ssh -vT git@github.com