PWD=`pwd`
cd $HOME/workspace/nginx-1.0.1
./configure --prefix=$HOME/test/nginx \
 --without-http \
 --add-module=/$HOME/workspace/oc_mail \
 --with-debug
cd $PWD
