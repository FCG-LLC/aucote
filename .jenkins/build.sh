#!/bin/bash
function retry() {
    count=$1
    slp=$2
    cmd=$3
    ( for i in $(seq 0 $count); do 
        [ $i -gt 0 ] && echo "---- Rerying $i time ----"; $cmd && break || [ $i -lt $count ] && echo "---- FAILURE, waiting $slp secs ----" && sleep $slp || exit;
     done ) || return 1
}


set -ex

cd $WORKSPACE/source

docker build --build-arg destEnv=$destEnv --no-cache -t cs/aucote/release .

if test "${branch#*tags/}" != "$branch"; then
	VERSION="${branch#tags/}"
else
	SHORT_COMMIT=`expr substr $GIT_COMMIT 1 7`
	VERSION="0.0.0-`date -u +"%Y%m%d%H%M%S"`-$SHORT_COMMIT"
fi

APTLY_SERVER=http://10.12.1.225:8080
docker run --rm -P -v `pwd`:`pwd` -w=`pwd` cs/aucote/release ./package.sh $VERSION
retry 5 15 "curl -X POST -F file=@package/aucote_$VERSION.deb $APTLY_SERVER/api/files/aucote_$VERSION"
retry 5 15 "curl -X POST $APTLY_SERVER/api/repos/$destEnv/file/aucote_$VERSION"
ssh -tt -i ~/.ssh/aptly_rsa aptly@10.12.1.225
echo version="$VERSION" > env.properties

cd $WORKSPACE/source
cd dockerization/hardened
docker build --build-arg destEnv=$destEnv --no-cache -t cs/$app-hardened .
docker tag cs/$app-hardened portus.cs.int:5000/$destEnv/cs-$app-hardened
retry 5 15 "docker push portus.cs.int:5000/$destEnv/cs-$app-hardened"
