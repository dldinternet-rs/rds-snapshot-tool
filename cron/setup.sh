#!bash

if test ! -d /usr/local/pyenv ; then
  test 'root' == "$(whoami)" || { echo "Must be root for the first part"; exit 1; }
  yum -y update
  yum -y upgrade
  yum install -y postgresql bind-utils nmap git
  yum install -y @development zlib-devel bzip2 bzip2-devel readline-devel sqlite sqlite-devel openssl-devel xz xz-devel libffi-devel findutils
  export PYENV_ROOT=/usr/local/pyenv
  curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
  cd /usr/local/pyenv/
  export PYENV_ROOT=/usr/local/pyenv
  chown -R root $PYENV_ROOT
  chgrp -R wheel $PYENV_ROOT
  chmod -R ug+w $PYENV_ROOT
  ls -al /usr/local/pyenv/
  usermod -G wheel ec2-user
  echo "Exit session / reload the shell and run $0 again as ec2-user"
else
  export PATH=$PATH:/usr/local/pyenv/bin
  eval "$(pyenv init -)"
  eval "$(pyenv virtualenv-init -)"
  pyenv install --list | egrep -e '^[ \t]*3\.'
  pyenv root
  pyenv versions
  pyenv install 3.9.4
  pyenv global 3.9.4
  pyenv versions

  pip install -r "$(dirname $0)/requirements.txt"
fi

test ! -z "$(egrep PYENV_ROOT ~/.bashrc)" || cat - <<EOL >>~/.bashrc

export PYENV_ROOT=/usr/local/pyenv
export PATH="\$PYENV_ROOT/bin:\$PATH"
eval "\$(pyenv init -)"
eval "\$(pyenv virtualenv-init -)"
EOL
